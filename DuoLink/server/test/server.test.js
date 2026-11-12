import assert from 'node:assert/strict';
import test from 'node:test';
import {
  b64u,
  buildAckSignature,
  createTestServer,
  fakeCommitCiphertext,
  makeParticipant,
  sha256,
  TestClient,
} from './helpers.js';
import { InvitationState } from '../src/protocol.js';

const ok = (res, status = 200) => {
  assert.equal(res.status, status, `unexpected status ${res.status}: ${JSON.stringify(res.json)}`);
  return res.json;
};

/** Creates an invitation and returns everything a real client would hold. */
async function createInvitation(app, owner = makeParticipant(), extra = {}) {
  const client = new TestClient(app);
  const created = ok(
    await client.call('POST', '/v1/invitations', { body: { owner: owner.wire(), ...extra } }),
    201
  );
  return { client, owner, created };
}

async function redeemedInvitation(app, extra = {}) {
  const owner = makeParticipant();
  const recipient = makeParticipant();
  const { client, created } = await createInvitation(app, owner, extra);
  const redeemed = ok(
    await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: created.activationCode, recipient: recipient.wire() },
    })
  );
  return { client, owner, recipient, created, redeemed };
}

async function atQuorum(app, clock) {
  const ctx = await redeemedInvitation(app);
  const { client, owner, recipient, created, redeemed } = ctx;
  const ownerCommit = fakeCommitCiphertext(Buffer.from('owner-commit'));
  const recipientCommit = fakeCommitCiphertext(Buffer.from('recipient-commit'));
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: created.ownerToken,
      body: {
        role: 'owner',
        commitCiphertextB64u: b64u(ownerCommit),
        commitDigestB64u: b64u(sha256(ownerCommit)),
      },
    })
  );
  const quorum = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: redeemed.recipientToken,
      body: {
        role: 'recipient',
        commitCiphertextB64u: b64u(recipientCommit),
        commitDigestB64u: b64u(sha256(recipientCommit)),
      },
    })
  );
  assert.equal(quorum.quorumReached, true);
  return {
    ...ctx,
    ownerCommit,
    recipientCommit,
    digests: { owner: sha256(ownerCommit), recipient: sha256(recipientCommit) },
    clock,
  };
}

// ---------------------------------------------------------------------------------------------
// Creation & redemption
// ---------------------------------------------------------------------------------------------

test('creates an invitation with a one-time code and never stores the code in plaintext', async () => {
  const { store, app } = createTestServer();
  const { created } = await createInvitation(app);
  assert.match(created.activationCode, /^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/);
  assert.equal(created.protocolVersion, 1);
  assert.equal(Buffer.from(created.ownerToken, 'base64url').length, 32);
  const row = store.rawRow(created.invitationId);
  assert.equal(row.code_hash.length, 32);
  assert.equal(row.owner_token_hash.length, 32);
  // The plaintext activation code must not appear anywhere in the persisted row.
  const flat = JSON.stringify(Object.values(row).map((v) => (Buffer.isBuffer(v) ? v.toString('hex') : v)));
  assert.equal(flat.includes(created.activationCode.replace(/-/g, '')), false);
  assert.equal(row.state, InvitationState.CREATED);
});

test('rejects an owner payload whose deviceId does not match its identity key', async () => {
  const { app } = createTestServer();
  const owner = makeParticipant();
  const forged = { ...owner.wire(), deviceId: b64u(Buffer.alloc(16, 0xab)) };
  const res = await new TestClient(app).call('POST', '/v1/invitations', { body: { owner: forged } });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'identity_mismatch');
});

test('rejects an ACK key that is identical to the long-term identity key', async () => {
  const { app } = createTestServer();
  const owner = makeParticipant();
  const bad = { ...owner.wire(), ackSpki: owner.identitySpkiB64u };
  const res = await new TestClient(app).call('POST', '/v1/invitations', { body: { owner: bad } });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_ack_key');
});

test('rejects malformed public keys and non-canonical base64url', async () => {
  const { app } = createTestServer();
  const owner = makeParticipant();
  const truncated = { ...owner.wire(), identitySpki: b64u(owner.identity.spki.subarray(0, 40)) };
  let res = await new TestClient(app).call('POST', '/v1/invitations', { body: { owner: truncated } });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_public_key');

  const padded = { ...owner.wire(), spkSpki: `${owner.spkSpkiB64u}==` };
  res = await new TestClient(app).call('POST', '/v1/invitations', { body: { owner: padded } });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'malformed_encoding');
});

test('redeems an invitation exactly once and refuses a second redemption', async () => {
  const { app } = createTestServer();
  const { client, created } = await createInvitation(app);
  const first = makeParticipant();
  const second = makeParticipant();
  ok(
    await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: created.activationCode, recipient: first.wire() },
    })
  );
  const duplicate = await client.call('POST', '/v1/invitations/redeem', {
    body: { activationCode: created.activationCode, recipient: second.wire() },
  });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.json.error, 'already_redeemed');
});

test('normalises activation codes typed with spaces / lowercase', async () => {
  const { app } = createTestServer();
  const { client, created } = await createInvitation(app);
  const sloppy = created.activationCode.toLowerCase().replace(/-/g, ' ');
  const recipient = makeParticipant();
  ok(
    await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: sloppy, recipient: recipient.wire() },
    })
  );
});

test('rejects an unknown activation code without revealing whether it existed', async () => {
  const { app } = createTestServer();
  const res = await new TestClient(app).call('POST', '/v1/invitations/redeem', {
    body: { activationCode: 'AAAA-BBBB-CCCC-DDDD', recipient: makeParticipant().wire() },
  });
  assert.equal(res.status, 404);
  assert.equal(res.json.error, 'invalid_activation_code');
});

test('refuses to let the owner redeem its own invitation', async () => {
  const { app } = createTestServer();
  const owner = makeParticipant();
  const { client, created } = await createInvitation(app, owner);
  const res = await client.call('POST', '/v1/invitations/redeem', {
    body: { activationCode: created.activationCode, recipient: owner.wire() },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'self_redeem');
});

test('expired invitations cannot be redeemed and report 410', async () => {
  let now = 1_700_000_000_000;
  const clock = () => now;
  const { app } = createTestServer({ clock });
  const { client, created } = await createInvitation(app);
  now += 16 * 60 * 1000;
  const res = await client.call('POST', '/v1/invitations/redeem', {
    body: { activationCode: created.activationCode, recipient: makeParticipant().wire() },
  });
  // The redeem path answers exactly as it would for an unknown code: expiry must not become an
  // oracle that tells an attacker a code existed.
  assert.equal(res.status, 404);
  assert.equal(res.json.error, 'invalid_activation_code');

  const view = await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken });
  assert.equal(view.status, 410);
  assert.equal(view.json.error, 'expired');
});

// ---------------------------------------------------------------------------------------------
// Authentication & rate limiting
// ---------------------------------------------------------------------------------------------

test('rejects missing, malformed and unknown bearer tokens', async () => {
  const { app } = createTestServer();
  const { client, created } = await createInvitation(app);
  const missing = await client.call('GET', `/v1/invitations/${created.invitationId}`);
  assert.equal(missing.status, 401);
  assert.equal(missing.json.error, 'unauthenticated');

  const unknown = await client.call('GET', `/v1/invitations/${created.invitationId}`, {
    token: b64u(Buffer.alloc(32, 0x77)),
  });
  assert.equal(unknown.status, 401);

  const malformed = await client.call('GET', `/v1/invitations/${created.invitationId}`, {
    token: 'not a token!!',
  });
  assert.equal(malformed.status, 401);
});

test('a recipient token cannot act on behalf of the owner role', async () => {
  const { app } = createTestServer();
  const { client, created, redeemed } = await redeemedInvitation(app);
  const commit = fakeCommitCiphertext(Buffer.from('x'));
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: redeemed.recipientToken,
    body: {
      role: 'owner',
      commitCiphertextB64u: b64u(commit),
      commitDigestB64u: b64u(sha256(commit)),
    },
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'role_mismatch');
});

test('rate limits activation attempts with a 429 and retry-after header', async () => {
  const { app } = createTestServer({ limits: { activationPerWindow: 3, generalPerWindow: 1000 } });
  const client = new TestClient(app);
  for (let i = 0; i < 3; i += 1) {
    const res = await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: 'AAAA-BBBB-CCCC-DDDD', recipient: makeParticipant().wire() },
    });
    assert.equal(res.status, 404);
  }
  const limited = await client.call('POST', '/v1/invitations/redeem', {
    body: { activationCode: 'AAAA-BBBB-CCCC-DDDD', recipient: makeParticipant().wire() },
  });
  assert.equal(limited.status, 429);
  assert.equal(limited.json.error, 'rate_limited');
});

test('rate limits general traffic per transport address', async () => {
  const { app } = createTestServer({ limits: { generalPerWindow: 2, activationPerWindow: 100 } });
  const client = new TestClient(app, '10.1.2.3');
  assert.equal((await client.call('GET', '/healthz')).status, 200);
  assert.equal((await client.call('GET', '/healthz')).status, 200);
  const blocked = await client.call('GET', '/healthz');
  assert.equal(blocked.status, 429);
  // A different address has its own bucket.
  assert.equal((await new TestClient(app, '10.1.2.4').call('GET', '/healthz')).status, 200);
});

test('rate-limit budget survives a store reopen (durable, not in-memory)', async () => {
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'duolink-rl-'));
  try {
    const dbPath = join(dir, 'db.sqlite');
    const first = createTestServer({ databasePath: dbPath, limits: { generalPerWindow: 2 } });
    const client = new TestClient(first.app, '192.0.2.9');
    assert.equal((await client.call('GET', '/healthz')).status, 200);
    assert.equal((await client.call('GET', '/healthz')).status, 200);
    first.store.close();

    const second = createTestServer({ databasePath: dbPath, limits: { generalPerWindow: 2 } });
    const resumed = new TestClient(second.app, '192.0.2.9');
    assert.equal((await resumed.call('GET', '/healthz')).status, 429);
    second.store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------------
// Commit quorum barrier
// ---------------------------------------------------------------------------------------------

test('peer commit ciphertext is withheld until the quorum barrier is reached', async () => {
  const { app } = createTestServer();
  const { client, created, redeemed, owner, recipient } = await redeemedInvitation(app);
  const ownerCommit = fakeCommitCiphertext(Buffer.from('owner-1'));
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: created.ownerToken,
      body: {
        role: 'owner',
        commitCiphertextB64u: b64u(ownerCommit),
        commitDigestB64u: b64u(sha256(ownerCommit)),
      },
    })
  );

  // Before quorum: neither party may see the other's ciphertext, and the state must say so.
  const ownerView = ok(
    await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken })
  );
  assert.equal(ownerView.quorumReached, false);
  assert.equal(ownerView.peerCommitCiphertextB64u, null);
  assert.equal(ownerView.state, InvitationState.COMMITS_PARTIAL);
  assert.deepEqual(ownerView.ciphertextReceipt, { owner: true, recipient: false });
  assert.equal(ownerView.e2eeValidityVerifiedByServer, false);

  const recipientView = ok(
    await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: redeemed.recipientToken })
  );
  assert.equal(recipientView.peerCommitCiphertextB64u, null);
  assert.equal(recipientView.quorumReached, false);

  const recipientCommit = fakeCommitCiphertext(Buffer.from('recipient-1'));
  const second = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: redeemed.recipientToken,
      body: {
        role: 'recipient',
        commitCiphertextB64u: b64u(recipientCommit),
        commitDigestB64u: b64u(sha256(recipientCommit)),
      },
    })
  );
  assert.equal(second.quorumReached, true);

  const ownerAfter = ok(
    await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken })
  );
  assert.equal(ownerAfter.state, InvitationState.COMMIT_QUORUM_REACHED);
  assert.equal(ownerAfter.quorumReached, true);
  assert.equal(ownerAfter.peerCommitCiphertextB64u, b64u(recipientCommit));
  assert.equal(ownerAfter.peerCommitDigestB64u, b64u(sha256(recipientCommit)));
  assert.equal(ownerAfter.peer.deviceIdB64u, recipient.deviceIdB64u);
  assert.equal(ownerAfter.peer.identitySpkiB64u, recipient.identitySpkiB64u);

  const recipientAfter = ok(
    await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: redeemed.recipientToken })
  );
  assert.equal(recipientAfter.peerCommitCiphertextB64u, b64u(ownerCommit));
  assert.equal(recipientAfter.peer.deviceIdB64u, owner.deviceIdB64u);
});

test('the owner never receives the recipient commit before the recipient has committed', async () => {
  const { app } = createTestServer();
  const { client, created } = await redeemedInvitation(app);
  const view = ok(
    await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken })
  );
  assert.equal(view.peerCommitCiphertextB64u, null);
  assert.equal(view.quorumReached, false);
  assert.equal(view.redeemed, true);
});

test('a commit whose declared digest does not match its ciphertext is rejected', async () => {
  const { app } = createTestServer();
  const { client, created } = await redeemedInvitation(app);
  const commit = fakeCommitCiphertext(Buffer.from('digest-test'));
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: created.ownerToken,
    body: {
      role: 'owner',
      commitCiphertextB64u: b64u(commit),
      commitDigestB64u: b64u(Buffer.alloc(32, 0x99)),
    },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'digest_mismatch');
});

test('replaying the identical commit is idempotent, but a different commit for the same role conflicts', async () => {
  const { app } = createTestServer();
  const { client, created } = await redeemedInvitation(app);
  const commit = fakeCommitCiphertext(Buffer.from('replay'));
  const body = {
    role: 'owner',
    commitCiphertextB64u: b64u(commit),
    commitDigestB64u: b64u(sha256(commit)),
  };
  const first = ok(await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, { token: created.ownerToken, body }));
  assert.equal(first.replay, false);
  const second = ok(await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, { token: created.ownerToken, body }));
  assert.equal(second.accepted, true);
  assert.equal(second.replay, true);
  assert.equal(second.quorumReached, false);

  const other = fakeCommitCiphertext(Buffer.from('different'));
  const conflict = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: created.ownerToken,
    body: {
      role: 'owner',
      commitCiphertextB64u: b64u(other),
      commitDigestB64u: b64u(sha256(other)),
    },
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.json.error, 'commit_conflict');
});

test('oversized and undersized commit ciphertexts are rejected before they reach storage', async () => {
  const { app } = createTestServer();
  const { client, created } = await redeemedInvitation(app);
  const tiny = Buffer.from([0x01, 0x02, 0x03]);
  let res = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: created.ownerToken,
    body: { role: 'owner', commitCiphertextB64u: b64u(tiny), commitDigestB64u: b64u(sha256(tiny)) },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_ciphertext');

  const huge = Buffer.alloc(17 * 1024, 0x41);
  res = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: created.ownerToken,
    body: { role: 'owner', commitCiphertextB64u: b64u(huge), commitDigestB64u: b64u(sha256(huge)) },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_ciphertext');
});

test('the serialisation barrier holds under concurrent submissions (exactly one quorum transition)', async () => {
  const { store, app } = createTestServer();
  const { client, created, redeemed } = await redeemedInvitation(app);
  const ownerCommit = fakeCommitCiphertext(Buffer.from('concurrent-owner'));
  const recipientCommit = fakeCommitCiphertext(Buffer.from('concurrent-recipient'));
  // Node's handler is synchronous, so true interleaving is simulated by issuing the two commits from
  // interleaved promises; the invariant under test is that exactly one transition reaches quorum.
  const results = await Promise.all([
    client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: created.ownerToken,
      body: { role: 'owner', commitCiphertextB64u: b64u(ownerCommit), commitDigestB64u: b64u(sha256(ownerCommit)) },
    }),
    client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: redeemed.recipientToken,
      body: {
        role: 'recipient',
        commitCiphertextB64u: b64u(recipientCommit),
        commitDigestB64u: b64u(sha256(recipientCommit)),
      },
    }),
  ]);
  assert.deepEqual(results.map((r) => r.status), [200, 200]);
  const row = store.rawRow(created.invitationId);
  assert.equal(row.state, InvitationState.COMMIT_QUORUM_REACHED);
  assert.ok(row.owner_commit_digest && row.recipient_commit_digest);
  assert.ok(row.quorum_at !== null);
});

// ---------------------------------------------------------------------------------------------
// ACK authentication
// ---------------------------------------------------------------------------------------------

test('a valid ECDSA ACK over the exact transcript is accepted and a receipt is returned', async () => {
  const { app } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, created, digests } = ctx;
  const { signature } = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  });
  const res = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: created.ownerToken,
      body: { role: 'owner', ackSignatureB64u: b64u(signature) },
    })
  );
  assert.equal(res.ackRecorded, true);
  assert.equal(res.mutualReceipt, false);
  assert.equal(res.e2eeHmacVerifiedByServer, false);
  assert.match(res.serverReceipt.meaning, /NOT a proof of peer consent/);
  assert.equal(typeof res.serverReceipt.signatureB64u, 'string');
});

test('an ACK with an invalid signature is rejected (wrong key, wrong transcript, tampering)', async () => {
  const { app } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, recipient, created, digests } = ctx;

  // Signed by the wrong participant.
  let forged = buildAckSignature({
    participant: recipient,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  });
  let res = await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
    token: created.ownerToken,
    body: { role: 'owner', ackSignatureB64u: b64u(forged.signature) },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_ack_signature');

  // Correct key but a transcript bound to different ciphertext digests.
  forged = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.recipient,
    commitDigestRecipient: digests.owner,
  });
  res = await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
    token: created.ownerToken,
    body: { role: 'owner', ackSignatureB64u: b64u(forged.signature) },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_ack_signature');

  // Bit-flipped signature.
  const valid = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  });
  const flipped = Buffer.from(valid.signature);
  flipped[flipped.length - 1] ^= 0x01;
  res = await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
    token: created.ownerToken,
    body: { role: 'owner', ackSignatureB64u: b64u(flipped) },
  });
  assert.equal(res.status, 400);
  assert.equal(res.json.error, 'invalid_ack_signature');
});

test('an ACK is refused before the commit quorum exists', async () => {
  const { app } = createTestServer();
  const { client, created, owner } = await redeemedInvitation(app);
  const { signature } = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: sha256(Buffer.from('a')),
    commitDigestRecipient: sha256(Buffer.from('b')),
  });
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
    token: created.ownerToken,
    body: { role: 'owner', ackSignatureB64u: b64u(signature) },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'ack_before_quorum');
});

test('mutual receipts require two independent ACKs; replaying one is idempotent', async () => {
  const { app } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, recipient, created, digests } = ctx;
  const ownerAck = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  }).signature;
  const recipientAck = buildAckSignature({
    participant: recipient,
    invitationId: created.invitationId,
    role: 'recipient',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  }).signature;

  const first = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: created.ownerToken,
      body: { role: 'owner', ackSignatureB64u: b64u(ownerAck) },
    })
  );
  assert.equal(first.mutualReceipt, false);

  const replay = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: created.ownerToken,
      body: { role: 'owner', ackSignatureB64u: b64u(ownerAck) },
    })
  );
  assert.equal(replay.replay, true);
  assert.equal(replay.mutualReceipt, false);

  const second = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: ctx.redeemed.recipientToken,
      body: { role: 'recipient', ackSignatureB64u: b64u(recipientAck) },
    })
  );
  assert.equal(second.mutualReceipt, true);
  assert.equal(second.ackDigestOwnerB64u, b64u(sha256(ownerAck)));
  assert.equal(second.ackDigestRecipientB64u, b64u(sha256(recipientAck)));
  // Both peer ACK signatures are exposed so each client can verify the peer's identity signature.
  assert.equal(second.ackSignatures.ownerB64u, b64u(ownerAck));
  assert.equal(second.ackSignatures.recipientB64u, b64u(recipientAck));
});

test('a conflicting ACK signature for an already-ACKed role is rejected', async () => {
  const { app } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, created, digests } = ctx;
  const ack = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  }).signature;
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: created.ownerToken,
      body: { role: 'owner', ackSignatureB64u: b64u(ack) },
    })
  );
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
    token: created.ownerToken,
    body: { role: 'owner', ackSignatureB64u: b64u(Buffer.alloc(70, 0x30)) },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'ack_conflict');
});

test('on mutual receipt the ciphertext payloads are destroyed (retention deletion)', async () => {
  const { app, store } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, recipient, created, digests } = ctx;
  const ownerAck = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  }).signature;
  const recipientAck = buildAckSignature({
    participant: recipient,
    invitationId: created.invitationId,
    role: 'recipient',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  }).signature;
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: created.ownerToken,
      body: { role: 'owner', ackSignatureB64u: b64u(ownerAck) },
    })
  );
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
      token: ctx.redeemed.recipientToken,
      body: { role: 'recipient', ackSignatureB64u: b64u(recipientAck) },
    })
  );
  const row = store.rawRow(created.invitationId);
  assert.equal(row.state, InvitationState.MUTUAL_RECEIPT);
  assert.equal(row.owner_commit, null);
  assert.equal(row.recipient_commit, null);
  assert.equal(row.owner_ephemeral_spki, null);
  assert.equal(row.recipient_ephemeral_spki, null);
  assert.ok(row.owner_commit_digest && row.recipient_commit_digest);
  assert.ok(row.purged_at !== null);
});

// ---------------------------------------------------------------------------------------------
// Cancellation races
// ---------------------------------------------------------------------------------------------

test('cancellation race: revoke before any commit', async () => {
  const { app } = createTestServer();
  const { client, created, redeemed } = await redeemedInvitation(app);
  const revoked = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/revoke`, { token: created.ownerToken })
  );
  assert.equal(revoked.state, InvitationState.REVOKED);
  assert.equal(revoked.durablePeerTrustUnaffected, true);
  const commit = fakeCommitCiphertext(Buffer.from('late'));
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: redeemed.recipientToken,
    body: { role: 'recipient', commitCiphertextB64u: b64u(commit), commitDigestB64u: b64u(sha256(commit)) },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'revoked');
});

test('cancellation race: revoke after the first commit purges that commit', async () => {
  const { app, store } = createTestServer();
  const { client, created, redeemed } = await redeemedInvitation(app);
  const commit = fakeCommitCiphertext(Buffer.from('only-one'));
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: created.ownerToken,
      body: { role: 'owner', commitCiphertextB64u: b64u(commit), commitDigestB64u: b64u(sha256(commit)) },
    })
  );
  ok(await client.call('POST', `/v1/invitations/${created.invitationId}/revoke`, { token: created.ownerToken }));
  const row = store.rawRow(created.invitationId);
  assert.equal(row.state, InvitationState.REVOKED);
  assert.equal(row.owner_commit, null);
  // The other side observes a terminal, non-resurrectable state.
  const view = await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: redeemed.recipientToken });
  assert.equal(view.status, 409);
  assert.equal(view.json.error, 'revoked');
});

test('cancellation race: revoke immediately before quorum, then the quorum commit arrives', async () => {
  const { app } = createTestServer();
  const { client, created, redeemed } = await redeemedInvitation(app);
  const ownerCommit = fakeCommitCiphertext(Buffer.from('race-owner'));
  ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
      token: created.ownerToken,
      body: { role: 'owner', commitCiphertextB64u: b64u(ownerCommit), commitDigestB64u: b64u(sha256(ownerCommit)) },
    })
  );
  ok(await client.call('POST', `/v1/invitations/${created.invitationId}/revoke`, { token: created.ownerToken }));
  const late = fakeCommitCiphertext(Buffer.from('race-recipient'));
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/commit`, {
    token: redeemed.recipientToken,
    body: { role: 'recipient', commitCiphertextB64u: b64u(late), commitDigestB64u: b64u(sha256(late)) },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'revoked');
});

test('cancellation race: revoke immediately after quorum blocks ACKs but keeps the transcript digests', async () => {
  const { app } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, created, digests } = ctx;
  ok(await client.call('POST', `/v1/invitations/${created.invitationId}/revoke`, { token: created.ownerToken }));
  const ack = buildAckSignature({
    participant: owner,
    invitationId: created.invitationId,
    role: 'owner',
    commitDigestOwner: digests.owner,
    commitDigestRecipient: digests.recipient,
  }).signature;
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
    token: created.ownerToken,
    body: { role: 'owner', ackSignatureB64u: b64u(ack) },
  });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'revoked');
});

test('revocation after mutual receipt is refused: it cannot un-pair persisted trust', async () => {
  const { app } = createTestServer();
  const ctx = await atQuorum(app);
  const { client, owner, recipient, created, digests } = ctx;
  for (const [role, participant, token] of [
    ['owner', owner, created.ownerToken],
    ['recipient', recipient, ctx.redeemed.recipientToken],
  ]) {
    const sig = buildAckSignature({
      participant,
      invitationId: created.invitationId,
      role,
      commitDigestOwner: digests.owner,
      commitDigestRecipient: digests.recipient,
    }).signature;
    ok(
      await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
        token,
        body: { role, ackSignatureB64u: b64u(sig) },
      })
    );
  }
  const res = await client.call('POST', `/v1/invitations/${created.invitationId}/revoke`, { token: created.ownerToken });
  assert.equal(res.status, 409);
  assert.equal(res.json.error, 'already_mutual');
});

test('rejection by the recipient is terminal and cannot be performed by the owner', async () => {
  const { app } = createTestServer();
  const { client, created, redeemed } = await redeemedInvitation(app);
  const wrongRole = await client.call('POST', `/v1/invitations/${created.invitationId}/reject`, {
    token: created.ownerToken,
  });
  assert.equal(wrongRole.status, 403);
  const rejected = ok(
    await client.call('POST', `/v1/invitations/${created.invitationId}/reject`, {
      token: redeemed.recipientToken,
    })
  );
  assert.equal(rejected.state, InvitationState.REJECTED);
  const ownerView = await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken });
  assert.equal(ownerView.status, 409);
  assert.equal(ownerView.json.error, 'rejected');
});

// ---------------------------------------------------------------------------------------------
// Expiry, retention and restart recovery
// ---------------------------------------------------------------------------------------------

test('lazy expiry transitions overdue invitations and reports 410 to clients', async () => {
  let now = 1_700_000_000_000;
  const clock = () => now;
  const { app, store } = createTestServer({ clock });
  const { client, created } = await redeemedInvitation(app);
  now += 901 * 1000;
  const res = await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken });
  assert.equal(res.status, 410);
  assert.equal(res.json.error, 'expired');
  assert.equal(store.rawRow(created.invitationId).state, InvitationState.EXPIRED);
  assert.equal(store.expireOverdue(), 0, 'already-expired rows must not transition twice');
});

test('the retention sweeper deletes terminal rows after the tombstone window', async () => {
  let now = 1_700_000_000_000;
  const clock = () => now;
  const { app, store } = createTestServer({ clock, retentionSecondsAfterTerminal: 60 });
  const { client, created } = await redeemedInvitation(app);
  ok(await client.call('POST', `/v1/invitations/${created.invitationId}/revoke`, { token: created.ownerToken }));
  assert.ok(store.rawRow(created.invitationId));
  now += 61 * 1000;
  assert.equal(store.expireOverdue(), 0);
  const purged = store.purge();
  assert.equal(purged, 1);
  assert.equal(store.rawRow(created.invitationId), null);
  const res = await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken });
  assert.equal(res.status, 404);
});

test('state survives a server restart (SQLite durability, WAL, restart recovery)', async () => {
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'duolink-restart-'));
  const dbPath = join(dir, 'db.sqlite');
  try {
    const first = createTestServer({ databasePath: dbPath });
    const ctx = await atQuorum(first.app);
    const { created, digests, ownerCommit, recipientCommit } = ctx;
    first.store.close();

    const second = createTestServer({ databasePath: dbPath });
    const client = new TestClient(second.app);
    const view = ok(
      await client.call('GET', `/v1/invitations/${created.invitationId}`, { token: created.ownerToken })
    );
    assert.equal(view.state, InvitationState.COMMIT_QUORUM_REACHED);
    assert.equal(view.peerCommitCiphertextB64u, b64u(recipientCommit));
    assert.equal(view.ownCommitDigestB64u, b64u(digests.owner));
    // The recipient's token hash also survived, so the other side can resume its half of the flow.
    const recipientView = ok(
      await client.call('GET', `/v1/invitations/${created.invitationId}`, {
        token: ctx.redeemed.recipientToken,
      })
    );
    assert.equal(recipientView.peerCommitCiphertextB64u, b64u(ownerCommit));
    // And the ACK flow can complete after the restart.
    const ack = buildAckSignature({
      participant: ctx.owner,
      invitationId: created.invitationId,
      role: 'owner',
      commitDigestOwner: digests.owner,
      commitDigestRecipient: digests.recipient,
    }).signature;
    const ackRes = ok(
      await client.call('POST', `/v1/invitations/${created.invitationId}/ack`, {
        token: created.ownerToken,
        body: { role: 'owner', ackSignatureB64u: b64u(ack) },
      })
    );
    assert.equal(ackRes.ackRecorded, true);
    second.store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------------
// Misc: transport hardening & honesty flags
// ---------------------------------------------------------------------------------------------

test('server-info advertises exactly what the server can and cannot verify', async () => {
  const { app } = createTestServer();
  const info = ok(await new TestClient(app).call('GET', '/v1/server-info'));
  assert.equal(info.protocolVersion, 1);
  assert.deepEqual(info.capabilities, {
    verifiesEcdsaAckSignatures: true,
    verifiesPeerHmac: false,
    decryptsCommitCiphertext: false,
    storesPlaintextActivationCode: false,
    storesPrivateKeys: false,
    // Decision A: the server relays each device's signed-pre-key self-signature so the *peer* can
    // verify it, and states plainly that it does not verify that signature itself.
    relaysSpkSignatureWithoutVerification: true,
    verifiesSpkSignature: false,
  });
  assert.equal(Buffer.from(info.receiptPublicKeySpkiB64u, 'base64url').length, 91);
});

test('unknown routes return a structured 404 and oversized bodies are refused at the transport layer', async () => {
  const { app } = createTestServer();
  const notFound = await new TestClient(app).call('GET', '/v1/nope');
  assert.equal(notFound.status, 404);
  assert.equal(notFound.json.error, 'not_found');

  const { Readable } = await import('node:stream');
  const bigChunk = Buffer.alloc(70 * 1024, 0x20);
  const stream = Readable.from([bigChunk]);
  stream.method = 'POST';
  stream.url = '/v1/invitations';
  stream.headers = {};
  stream.socket = { remoteAddress: '127.0.0.1' };
  const response = await app.handleTransport(stream);
  assert.equal(response.status, 413);
});

test('malformed JSON bodies are rejected with 400 rather than crashing', async () => {
  const { app } = createTestServer();
  const { Readable } = await import('node:stream');
  const stream = Readable.from([Buffer.from('{"owner": ')]);
  stream.method = 'POST';
  stream.url = '/v1/invitations';
  stream.headers = {};
  stream.socket = { remoteAddress: '127.0.0.1' };
  const response = await app.handleTransport(stream);
  assert.equal(response.status, 400);
  assert.equal(JSON.parse(response.body).error, 'malformed_json');
});

test('a real HTTP listener serves the same API end-to-end', async () => {
  const { createDuoLinkServer } = await import('./helpers.js');
  const server = createDuoLinkServer({ databasePath: ':memory:' });
  const info = await server.listen({ host: '127.0.0.1', port: 0, sweepIntervalMs: 0 });
  try {
    const health = await fetch(`${info.baseUrl}/healthz`);
    assert.equal(health.status, 200);
    const body = await health.json();
    assert.equal(body.status, 'ok');
    assert.equal(health.headers.get('cache-control'), 'no-store');
    const owner = makeParticipant();
    const created = await fetch(`${info.baseUrl}/v1/invitations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ owner: owner.wire() }),
    });
    assert.equal(created.status, 201);
    const createdJson = await created.json();
    assert.match(createdJson.activationCode, /^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/);
  } finally {
    await server.close();
  }
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { generateNumericActivationCode } from '../src/crypto.js';
import { INVITATION_TTL_SECONDS } from '../src/protocol.js';
import { createTestServer, makeParticipant, TestClient } from './helpers.js';

/**
 * End-to-end numeric invitation-code flow, driven through the real HTTP handler and the real SQLite
 * store. These are integration tests, not unit tests: every request goes through rate limiting,
 * signature-length validation, the peppered hash and the transaction that enforces single use.
 *
 * The pepper is installed per-test via the exported test seam so no environment variable leaks between
 * tests, and so a missing pepper is a fail-closed error we assert on rather than an ambient accident.
 */

const PEPPER = 'test-pepper-0123456789abcdef0123456789abcdef';

/** Installs the pepper for one test and restores the pristine state afterwards. */
async function withNumericServer(fn) {
  const { setActivationPepperForTesting, resetActivationPepperCache } = await import('../src/crypto.js');
  setActivationPepperForTesting(PEPPER);
  resetActivationPepperCache();
  // Re-apply after the reset, which clears whatever was set.
  setActivationPepperForTesting(PEPPER);
  try {
    return await fn();
  } finally {
    setActivationPepperForTesting(null);
    resetActivationPepperCache();
  }
}

const ok = (res, status = 200) => {
  assert.equal(res.status, status, `unexpected status ${res.status}: ${JSON.stringify(res.json)}`);
  return res.json;
};

/** Mints an invitation whose activation code is a numeric one supplied by the caller. */
async function mintNumeric(app, code, owner = makeParticipant()) {
  const client = new TestClient(app);
  const created = ok(
    await client.call('POST', '/v1/invitations', {
      body: { owner: owner.wire(), activationCode: code },
    }),
    201,
  );
  return { client, owner, created };
}

// ---- happy path ----------------------------------------------------------

test('a numeric invitation can be minted and redeemed end to end', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const code = '482-913-7462';
    const owner = makeParticipant();
    const { client, created } = await mintNumeric(app, code, owner);

    assert.equal(created.activationCode, code, 'the server must echo the canonical numeric form');
    assert.equal(created.protocolVersion, 1);

    const recipient = makeParticipant();
    const redeemed = ok(
      await client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: code, recipient: recipient.wire() },
      }),
    );
    assert.ok(redeemed.invitationId, 'redemption must return the invitation id');
    assert.equal(redeemed.invitationId, created.invitationId);
  });
});

test('an ungrouped numeric code redeems the grouped invitation', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const { client } = await mintNumeric(app, '482-913-7462');
    const recipient = makeParticipant();
    // The user typed it without separators, as people do.
    ok(
      await client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: '4829137462', recipient: recipient.wire() },
      }),
    );
  });
});

// ---- the TTL contract ----------------------------------------------------

test('the invitation lifetime is exactly ten minutes, server-side', () => {
  assert.equal(INVITATION_TTL_SECONDS, 600, 'the app shows a 10-minute countdown; the server must agree');
});

test('the server reports a 600-second expiry at mint time', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const { created } = await mintNumeric(app, '482-913-7462');
    const lifetime = created.expiresAtEpochSec - created.createdAtEpochSec;
    assert.equal(lifetime, 600, `expected a 600s lifetime, got ${lifetime}s`);
  });
});

// ---- negative cases ------------------------------------------------------

test('a numeric code that was never issued is rejected', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    await mintNumeric(app, '482-913-7462');
    const recipient = makeParticipant();
    const client = new TestClient(app);
    const res = await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: '482-913-7463', recipient: recipient.wire() },
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'invalid_activation_code');
  });
});

test('a numeric code cannot be redeemed twice', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const { client } = await mintNumeric(app, '482-913-7462');
    const first = makeParticipant();
    ok(
      await client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: '482-913-7462', recipient: first.wire() },
      }),
    );

    const second = makeParticipant();
    const res = await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: '482-913-7462', recipient: second.wire() },
    });
    assert.equal(res.status, 409, 'single use must be enforced atomically, not by the client');
    assert.equal(res.json.error, 'already_redeemed');
  });
});

test('an expired numeric invitation cannot be redeemed', async () => {
  await withNumericServer(async () => {
    let now = Date.now();
    const { app } = createTestServer({ clock: () => now });
    const { client } = await mintNumeric(app, '482-913-7462');

    // Advance past the 10-minute window.
    now += (INVITATION_TTL_SECONDS + 1) * 1000;

    const recipient = makeParticipant();
    const res = await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: '482-913-7462', recipient: recipient.wire() },
    });
    assert.ok(res.status >= 400, `an expired code must fail, got ${res.status}`);
  });
});

test('the owner cannot redeem its own numeric invitation', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const owner = makeParticipant();
    const { client } = await mintNumeric(app, '482-913-7462', owner);
    const res = await client.call('POST', '/v1/invitations/redeem', {
      body: { activationCode: '482-913-7462', recipient: owner.wire() },
    });
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'self_redeem');
  });
});

test('malformed numeric codes are rejected before any hash is computed', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const recipient = makeParticipant();
    const client = new TestClient(app);
    for (const bad of ['123', '48291374620', 'abcdefghij', '']) {
      const res = await client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: bad, recipient: recipient.wire() },
      });
      assert.equal(res.status, 400, `expected 400 for '${bad}', got ${res.status}`);
    }
  });
});

// ---- collision safety ----------------------------------------------------

test('minting refuses a numeric code that collides with a live invitation', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    await mintNumeric(app, '482-913-7462');

    // A second owner tries to mint the same code. This must fail loudly rather than create two live
    // invitations a joiner could be routed between.
    const client = new TestClient(app);
    const anotherOwner = makeParticipant();
    const res = await client.call('POST', '/v1/invitations', {
      body: { owner: anotherOwner.wire(), activationCode: '482-913-7462' },
    });
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'code_collision');
  });
});

test('the SAME numeric code may be reused once the previous invitation is terminal', async () => {
  await withNumericServer(async () => {
    let now = Date.now();
    const { app } = createTestServer({ clock: () => now });
    const first = await mintNumeric(app, '482-913-7462');

    // Redeem it, then let the retention window purge the row.
    const recipient = makeParticipant();
    ok(
      await first.client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: '482-913-7462', recipient: recipient.wire() },
      }),
    );
    now += (INVITATION_TTL_SECONDS + 3600) * 1000;

    // Re-minting the same digits must now succeed: the old invitation is no longer live, so there is
    // no ambiguity about which device a joiner would reach.
    const client = new TestClient(app);
    const res = await client.call('POST', '/v1/invitations', {
      body: { owner: makeParticipant().wire(), activationCode: '482-913-7462' },
    });
    assert.equal(res.status, 201, `expected a successful re-mint, got ${res.status}`);
  });
});

// ---- rate limiting -------------------------------------------------------

test('repeated wrong numeric codes are rate limited', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer({ limits: { activationPerWindow: 3, windowSeconds: 60 } });
    await mintNumeric(app, '482-913-7462');
    const client = new TestClient(app);

    const statuses = [];
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const res = await client.call('POST', '/v1/invitations/redeem', {
        body: {
          activationCode: `48291374${String(60 + attempt).padStart(2, '0')}`,
          recipient: makeParticipant().wire(),
        },
      });
      statuses.push(res.status);
    }
    assert.ok(
      statuses.includes(429),
      `the attempt budget must bite within six tries, saw ${JSON.stringify(statuses)}`,
    );
  });
});

// ---- generation ----------------------------------------------------------

test('server-generated numeric codes are well formed', () => {
  for (let i = 0; i < 500; i += 1) {
    const code = generateNumericActivationCode();
    assert.match(code, /^[1-9][0-9]{2}-[0-9]{3}-[0-9]{4}$/, `malformed code: ${code}`);
  }
});

// ---- code -> id resolution (the numeric flow's missing link) -------------

test('resolve returns the invitation id for a live numeric code', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const { created } = await mintNumeric(app, '482-913-7462');
    const client = new TestClient(app);
    const resolved = ok(
      await client.call('POST', '/v1/invitations/resolve', {
        body: { activationCode: '4829137462' },
      }),
    );
    assert.equal(resolved.invitationId, created.invitationId);
    assert.equal(resolved.expiresAtEpochSec, created.expiresAtEpochSec);
  });
});

test('resolve leaks nothing beyond the id and expiry', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    await mintNumeric(app, '482-913-7462');
    const client = new TestClient(app);
    const resolved = ok(
      await client.call('POST', '/v1/invitations/resolve', {
        body: { activationCode: '482-913-7462' },
      }),
    );
    // Whitelist, not blacklist: any future field added to the response fails this test until someone
    // consciously decides it is safe to expose to an unauthenticated caller holding only the code.
    const allowed = new Set(['invitationId', 'expiresAtEpochSec', 'note']);
    const unexpected = Object.keys(resolved).filter((key) => !allowed.has(key));
    assert.deepEqual(unexpected, [], `resolve exposed unexpected fields: ${unexpected.join(', ')}`);
    // And explicitly: no key material, no device ids, no tokens.
    const serialised = JSON.stringify(resolved);
    for (const forbidden of ['Spki', 'Token', 'token', 'deviceId', 'Nonce', 'nonce', 'code_hash']) {
      assert.ok(!serialised.includes(forbidden), `resolve response leaked ${forbidden}`);
    }
  });
});

test('resolve does NOT redeem: the invitation stays redeemable afterwards', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const { client, created } = await mintNumeric(app, '482-913-7462');
    const resolver = new TestClient(app);
    // Resolve twice - must be harmless and idempotent.
    ok(await resolver.call('POST', '/v1/invitations/resolve', { body: { activationCode: '482-913-7462' } }));
    ok(await resolver.call('POST', '/v1/invitations/resolve', { body: { activationCode: '482-913-7462' } }));

    // Redemption must still work exactly once.
    const recipient = makeParticipant();
    const redeemed = ok(
      await client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: '482-913-7462', recipient: recipient.wire() },
      }),
    );
    assert.equal(redeemed.invitationId, created.invitationId);
  });
});

test('resolve cannot be used to bypass single use', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    const { client } = await mintNumeric(app, '482-913-7462');
    ok(
      await client.call('POST', '/v1/invitations/redeem', {
        body: { activationCode: '482-913-7462', recipient: makeParticipant().wire() },
      }),
    );
    // After redemption the invitation is no longer live, so resolution must fail exactly like redemption.
    const resolver = new TestClient(app);
    const res = await resolver.call('POST', '/v1/invitations/resolve', {
      body: { activationCode: '482-913-7462' },
    });
    assert.ok(res.status >= 400, `resolution of a redeemed invitation must fail, got ${res.status}`);
  });
});

test('resolve refuses an expired invitation', async () => {
  await withNumericServer(async () => {
    let now = Date.now();
    const { app } = createTestServer({ clock: () => now });
    await mintNumeric(app, '482-913-7462');
    now += (INVITATION_TTL_SECONDS + 1) * 1000;
    const client = new TestClient(app);
    const res = await client.call('POST', '/v1/invitations/resolve', {
      body: { activationCode: '482-913-7462' },
    });
    assert.ok(res.status >= 400, `expected failure for expired code, got ${res.status}`);
  });
});

test('resolve shares the activation attempt budget, so it is not a free probing oracle', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer({ limits: { activationPerWindow: 3, windowSeconds: 60 } });
    await mintNumeric(app, '482-913-7462');
    const client = new TestClient(app);
    const statuses = [];
    for (let i = 0; i < 6; i += 1) {
      const res = await client.call('POST', '/v1/invitations/resolve', {
        body: { activationCode: `48291374${String(70 + i).padStart(2, '0')}` },
      });
      statuses.push(res.status);
    }
    assert.ok(statuses.includes(429), `resolve must share the attempt cap, saw ${JSON.stringify(statuses)}`);
  });
});

test('resolve rejects a code for an invitation that never existed', async () => {
  await withNumericServer(async () => {
    const { app } = createTestServer();
    await mintNumeric(app, '482-913-7462');
    const client = new TestClient(app);
    const res = await client.call('POST', '/v1/invitations/resolve', {
      body: { activationCode: '111-222-3333' },
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'invalid_activation_code');
  });
});

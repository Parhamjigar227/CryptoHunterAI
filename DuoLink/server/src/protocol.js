/**
 * DuoLink Method B — canonical wire protocol constants and transcript constructors.
 *
 * THIS FILE IS THE SINGLE SOURCE OF TRUTH for the byte layout of every signed / authenticated
 * transcript exchanged between (a) the Android client and (b) the signaling server.
 *
 * The Android implementation mirrors these constructors exactly in
 *   DuoLink/app/src/main/java/com/duolink/app/remote/RemoteTranscripts.kt
 * and `RemoteTranscriptParityTest.kt` asserts byte-for-byte equality against the vectors emitted by
 *   DuoLink/server/test/transcriptParity.test.js
 * so that the two independent implementations can never silently drift apart.
 *
 * Field encoding: every variable-length field is written as a 4-byte big-endian length prefix
 * followed by the raw bytes. Fixed-width fields (deviceIds, digests) are written raw. Nothing is
 * ever serialised as JSON inside a signed transcript: JSON key ordering / unicode escaping is
 * attacker-controllable and is never acceptable as signature input.
 */

import { createHash } from 'node:crypto';

/** Protocol version. Bumping this invalidates both sides; never reuse a version with new layout. */
export const PROTOCOL_VERSION = 1;

/** Role of a participant inside one invitation. */
export const ROLE_OWNER = 'owner';
export const ROLE_RECIPIENT = 'recipient';

/** Hard protocol limits (also enforced by the server as defence-in-depth). */
export const LIMITS = Object.freeze({
  activationCodeLength: 16, // 5 groups x 4 chars, base32 (no padding)
  deviceIdBytes: 16,
  publicKeySpkiBytes: 91,
  rootKeyBytes: 32,
  transcriptDigestBytes: 32,
  minCiphertextBytes: 64,
  maxCiphertextBytes: 16 * 1024,
  minSignatureBytes: 64,
  maxSignatureBytes: 80,
  tokenBytes: 32,
  nonceBytes: 16,
  maxActivationAttemptsPerWindow: 10,
  maxRequestsPerWindow: 120,
});

/** Invitation lifetime as seen by the server (independent of the client-displayed countdown). */
export const INVITATION_TTL_SECONDS = 15 * 60;

/**
 * Server-side invitation state machine. `commit_quorum_reached` is the serialisation barrier at
 * which both commit ciphertexts exist and neither side may be delivered before it.
 */
export const InvitationState = Object.freeze({
  CREATED: 'created',
  REDEEMED: 'redeemed',
  COMMITS_PARTIAL: 'commits_partial',
  COMMIT_QUORUM_REACHED: 'commit_quorum_reached',
  MUTUAL_RECEIPT: 'mutual_receipt',
  REVOKED: 'revoked',
  REJECTED: 'rejected',
  EXPIRED: 'expired',
});

const utf8 = (s) => Buffer.from(s, 'utf8');
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
};
const i32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeInt32BE(n | 0, 0);
  return b;
};
const i64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(BigInt(n), 0);
  return b;
};

/** `field = uint32_be(len) || bytes` — the only way variable-length data enters a transcript. */
export const lp = (bytes) => Buffer.concat([u32(bytes.length), Buffer.from(bytes)]);

/** Domain-separated, length-prefixed transcript assembled from already-encoded parts. */
export const buildTranscript = (domain, parts) => Buffer.concat([utf8(domain), ...parts]);

/**
 * Invitation transcript, signed by the owner's long-term identity key (`IK_sig`) on the device, before
 * the invitation is ever sent to the server.
 *
 * Binds the one-time activation code to the owner's public material, so a recipient that knows the code
 * can prove the invitation really came from the holder of that identity key. The signature is stored
 * (public data) and relayed to the recipient; the server cannot check it, and never claims to.
 *
 * `activationCodeHash` (not the code) is what the server sees in this position, but the *signed* bytes
 * use the code hash too: the plaintext code never leaves the owner device, and the recipient can
 * recompute the same hash from the code it was given.
 */
export function invitationTranscript({
  invitationId,
  activationCodeHash,
  deviceId,
  identitySpki,
  ackSpki,
  spkSpki,
  ephemeralSpki,
  nonce,
  expiresAtEpochSec,
}) {
  return buildTranscript('DUOLINK-REMOTE-INVITE-QR-V1', [
    i32(PROTOCOL_VERSION),
    lp(utf8(invitationId)),
    lp(activationCodeHash),
    lp(deviceId),
    lp(identitySpki),
    lp(ackSpki),
    lp(spkSpki),
    lp(ephemeralSpki),
    lp(nonce),
    i64(expiresAtEpochSec),
  ]);
}

/**
 * Redemption transcript, signed by the recipient's `IK_sig` on the device.
 *
 * Binds the invitation id and every public key the recipient registers, including both nonces, so the
 * owner can prove that the material it received belongs to the device that redeemed the code and to no
 * other. Verified only by the owner client.
 */
export function redeemTranscript({
  invitationId,
  deviceId,
  identitySpki,
  ackSpki,
  spkSpki,
  ephemeralSpki,
  nonce,
}) {
  return buildTranscript('DUOLINK-REMOTE-REDEEM-V1', [
    i32(PROTOCOL_VERSION),
    lp(utf8(invitationId)),
    lp(deviceId),
    lp(identitySpki),
    lp(ackSpki),
    lp(spkSpki),
    lp(ephemeralSpki),
    lp(nonce),
  ]);
}

/**
 * ACK transcript signed by the peer client with its session ACK key.
 *
 * Binds: protocol version, invitation id, the sender's role, the sender's device identity, and the
 * exact pair of commit ciphertext digests. Binding both digests (not just the sender's own) makes
 * the ACK unusable for a *different* handshake transcript that happens to reuse the same invitation.
 *
 * NOTE: this transcript deliberately contains no secret material — it is exactly the data the server
 * is allowed to see in order to check the signature.
 */
export function ackTranscript({ invitationId, role, deviceId, commitDigestOwner, commitDigestRecipient }) {
  if (role !== ROLE_OWNER && role !== ROLE_RECIPIENT) throw new Error('invalid role');
  if (deviceId.length !== LIMITS.deviceIdBytes) throw new Error('invalid deviceId');
  if (commitDigestOwner.length !== 32 || commitDigestRecipient.length !== 32) {
    throw new Error('invalid commit digest');
  }
  return buildTranscript('DUOLINK-REMOTE-ACK-V1', [
    i32(PROTOCOL_VERSION),
    lp(utf8(invitationId)),
    lp(utf8(role)),
    lp(deviceId),
    lp(commitDigestOwner),
    lp(commitDigestRecipient),
  ]);
}

/**
 * Commit receipt transcript (returned by the server, verified by the client) binding the exact
 * ciphertext digests to the invitation and the ACK that was accepted.
 */
export function receiptTranscript({ invitationId, role, deviceId, commitDigestOwner, commitDigestRecipient, ackDigest }) {
  return buildTranscript('DUOLINK-REMOTE-RECEIPT-V1', [
    i32(PROTOCOL_VERSION),
    lp(utf8(invitationId)),
    lp(utf8(role)),
    lp(deviceId),
    lp(commitDigestOwner),
    lp(commitDigestRecipient),
    lp(ackDigest),
  ]);
}

/**
 * The *client-side only* commit transcript. Never transmitted; the server cannot compute this.
 * Included here so that the JVM parity test can prove both implementations agree on the bytes the
 * Android clients sign/HMAC and the server merely hashes as an opaque identifier.
 *
 * `K_confirm_*` and the root key never leave the device; the server only ever sees
 * `sha256(commitCiphertext)`.
 */
export function commitPlaintextTranscript({
  invitationId,
  role,
  deviceId,
  peerDeviceId,
  rootKey,
  ephPubSpki,
  spkPublicSpki,
  safetyNumber,
  issuedAtEpochSec,
}) {
  return buildTranscript('DUOLINK-REMOTE-COMMIT-V1', [
    i32(PROTOCOL_VERSION),
    lp(utf8(invitationId)),
    lp(utf8(role)),
    lp(deviceId),
    lp(peerDeviceId),
    lp(rootKey),
    lp(ephPubSpki),
    lp(spkPublicSpki),
    lp(utf8(safetyNumber.replace(/\s+/g, ' '))),
    i64(issuedAtEpochSec),
  ]);
}

/** `sha256(bytes)` as a 32-byte Buffer. Used for ciphertext digests and token-at-rest hashing. */
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

/** Digest of a single commit ciphertext, in the canonical form sent to peers. */
export const digestCiphertext = (ciphertextBytes) => sha256(ciphertextBytes);

/**
 * Golden parity vectors consumed by the Android JVM test `RemoteTranscriptParityTest`.
 * Regenerate deliberately (never casually): the Android side hard-codes these hex strings.
 */
export function parityVectors() {
  const invitationId = 'inv_parity_00000001';
  const deviceId = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const commitDigestOwner = Buffer.alloc(32, 0x11);
  const commitDigestRecipient = Buffer.alloc(32, 0x22);
  const ackDigest = Buffer.alloc(32, 0x33);
  const codeHash = Buffer.alloc(32, 0x44);
  const identitySpki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex'), Buffer.alloc(64, 0x55)]);
  const ackSpki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex'), Buffer.alloc(64, 0x66)]);
  const spkSpki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex'), Buffer.alloc(64, 0x77)]);
  const ephemeralSpki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex'), Buffer.alloc(64, 0x88)]);
  const nonce = Buffer.alloc(16, 0x99);
  const invite = {
    input: {
      invitationId,
      activationCodeHash: codeHash,
      deviceId,
      identitySpki,
      ackSpki,
      spkSpki,
      ephemeralSpki,
      nonce,
      expiresAtEpochSec: 1700000000,
    },
  };
  invite.hex = invitationTranscript(invite.input).toString('hex');
  const redeem = {
    input: { invitationId, deviceId, identitySpki, ackSpki, spkSpki, ephemeralSpki, nonce },
  };
  redeem.hex = redeemTranscript(redeem.input).toString('hex');
  return {
    protocolVersion: PROTOCOL_VERSION,
    invite,
    redeem,
    ack: {
      input: { invitationId, role: 'owner', deviceId, commitDigestOwner, commitDigestRecipient },
      hex: ackTranscript({ invitationId, role: 'owner', deviceId, commitDigestOwner, commitDigestRecipient }).toString('hex'),
    },
    receipt: {
      input: { invitationId, role: 'recipient', deviceId, commitDigestOwner, commitDigestRecipient, ackDigest },
      hex: receiptTranscript({
        invitationId,
        role: 'recipient',
        deviceId,
        commitDigestOwner,
        commitDigestRecipient,
        ackDigest,
      }).toString('hex'),
    },
  };
}

export const internals = { u32, lp, buildTranscript, utf8 };

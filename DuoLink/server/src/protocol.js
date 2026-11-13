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
  activationCodeLength: 16, // legacy: 4 groups of 4 base32 chars (80 bits)
  numericCodeDigits: 10,    // numeric invitations: 482-913-7462 (33.2 bits, peppered+stretched)
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
/**
 * Invitation lifetime: 10 minutes, matching the visible countdown the Android app shows.
 *
 * This was 15 minutes. The brief specifies 10, and the number must be identical on both sides: the
 * owner's countdown is driven by the server's `expiresAt`, so a mismatch would either show "expired"
 * while redemption still worked (baffling) or let a code outlive the screen that displays it.
 *
 * Shortening it also tightens the online guessing budget proportionally. At 10 attempts/minute a
 * 10-minute window allows 100 guesses against a 10^10 space.
 */
export const INVITATION_TTL_SECONDS = 10 * 60;

/**
 * Absolute ceiling on an invitation's lifetime, regardless of what a client asks for.
 *
 * The owner signs an absolute `expiresAtEpochSec` because the joining device must rebuild that exact
 * value to verify the signature, and the owner's clock -- not the server's -- is what the signature
 * covers. Honouring a client-supplied expiry is therefore necessary; letting it be unbounded would let
 * a client mint invitations that never expire, which the TTL policy exists to prevent.
 */
export const MAX_INVITATION_TTL_SECONDS = 15 * 60;

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
 *
 * IMPORTANT — two hashes, not one. `activationCodeHash` here is the *transcript* hash: a plain,
 * unkeyed SHA-256 with the `DUOLINK-ACTIVATION-CODE-V1` domain prefix, computable by both clients
 * because both must build these exact bytes. It is NOT the value the database stores. The stored
 * `code_hash` comes from `hashActivationCode()` in `crypto.js`, which for numeric codes is
 * HMAC(server pepper) + PBKDF2 and is deliberately NOT reproducible by any client.
 *
 * Consequence for numeric codes (33.2 bits): this signature is a stored, publicly-checkable function of
 * the code, so it is an offline oracle in a way that the peppered database hash is not. Measured on the
 * reference hardware, ECDSA P-256 verification costs ~91 us versus ~1.9 us for the SHA-256, so an
 * attacker holding the stored signature can test a candidate in ~48x the time of a raw hash, i.e. the
 * full 10^10 space in roughly 10 CPU-days. That is a real cost but not an infeasible one, and it is
 * unavoidable for ANY design that cryptographically binds a low-entropy code into a public-key
 * signature. It is recorded here rather than glossed over, and it is why the numeric option is
 * presented to users as convenient-but-shorter-lived rather than as equivalent to the 80-bit form.
 */
export function invitationTranscript({
  invitationId,
  activationCodeHash,
  deviceId,
  spkId,
  spkCreatedAtEpochSec,
  spkSignature,
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
    i32(spkId),
    i64(spkCreatedAtEpochSec),
    lp(spkSignature),
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
  spkId,
  spkCreatedAtEpochSec,
  spkSignature,
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
    i32(spkId),
    i64(spkCreatedAtEpochSec),
    lp(spkSignature),
    lp(identitySpki),
    lp(ackSpki),
    lp(spkSpki),
    lp(ephemeralSpki),
    lp(nonce),
  ]);
}

/**
 * Canonical Signed Pre-Key self-signature transcript.
 *
 * MUST stay byte-identical to `EcP256Crypto.buildSpkTranscript()` in
 * `DuoLink/app/src/main/java/com/duolink/app/crypto/DeviceKeyVault.kt`, because the Android client
 * already signs/verifies this exact layout in production (Method A). Reusing it unchanged is what lets
 * the *existing, unmodified* `PeerTrustStore` strict decoder accept a remote peer's `SPK_dh`.
 *
 * Layout: domain(17) || deviceId(16) || spkId(int32_be) || createdAt(int64_be) || len(spki) || spki
 * NOTE: unlike the other transcripts here, the two numeric fields are NOT length-prefixed. That is
 * deliberate: this is the pre-existing Method A format and may not be altered.
 */
export function spkTranscript({ deviceId, spkId, spkCreatedAtEpochSec, spkPublicKeySpki }) {
  if (deviceId.length !== LIMITS.deviceIdBytes) throw new Error('invalid deviceId');
  if (spkPublicKeySpki.length !== LIMITS.publicKeySpkiBytes) throw new Error('invalid spkPublicKeySpki');
  return Buffer.concat([
    Buffer.from('DuoLink-SPK-v1', 'utf8'),
    Buffer.from(deviceId),
    i32(spkId),
    i64(spkCreatedAtEpochSec),
    lp(spkPublicKeySpki),
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
  const spkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex');
  const identitySpki = Buffer.concat([spkiPrefix, Buffer.alloc(64, 0x55)]);
  const ackSpki = Buffer.concat([spkiPrefix, Buffer.alloc(64, 0x66)]);
  const spkSpki = Buffer.concat([spkiPrefix, Buffer.alloc(64, 0x77)]);
  const ephemeralSpki = Buffer.concat([spkiPrefix, Buffer.alloc(64, 0x88)]);
  const nonce = Buffer.alloc(16, 0x99);
  const spkSignature = Buffer.concat([Buffer.from('3045', 'hex'), Buffer.alloc(69, 0xAA)]);
  const spkId = 7;
  const spkCreatedAtEpochSec = 1700000000;

  const spk = { input: { deviceId, spkId, spkCreatedAtEpochSec, spkPublicKeySpki: spkSpki } };
  spk.hex = spkTranscript(spk.input).toString('hex');

  const invite = {
    input: {
      invitationId,
      activationCodeHash: codeHash,
      deviceId,
      spkId,
      spkCreatedAtEpochSec,
      spkSignature,
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
    input: { invitationId, deviceId, spkId, spkCreatedAtEpochSec, spkSignature, identitySpki, ackSpki, spkSpki, ephemeralSpki, nonce },
  };
  redeem.hex = redeemTranscript(redeem.input).toString('hex');

  return {
    protocolVersion: PROTOCOL_VERSION,
    constants: {
      spkId,
      spkCreatedAtEpochSec,
      invitationId,
      deviceIdHex: deviceId.toString('hex'),
      codeHashHex: codeHash.toString('hex'),
      nonceHex: nonce.toString('hex'),
      identitySpkiHex: identitySpki.toString('hex'),
      ackSpkiHex: ackSpki.toString('hex'),
      spkSpkiHex: spkSpki.toString('hex'),
      ephemeralSpkiHex: ephemeralSpki.toString('hex'),
      spkSignatureHex: spkSignature.toString('hex'),
      commitDigestOwnerHex: commitDigestOwner.toString('hex'),
      commitDigestRecipientHex: commitDigestRecipient.toString('hex'),
      ackDigestHex: ackDigest.toString('hex'),
    },
    spk,
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

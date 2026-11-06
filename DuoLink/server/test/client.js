/**
 * DuoLink Method B — full protocol client, implemented independently of the Android code.
 *
 * This module exists for two reasons:
 *
 *  1. **Two-device end-to-end testing.** It runs a real handshake against a real server with real
 *     P-256 / HKDF-SHA256 / AES-256-GCM / HMAC-SHA256 / ECDSA, with two independent identities. Nothing
 *     is simulated: if the protocol is broken, this fails.
 *  2. **Cross-implementation agreement.** `RemotePairingEndToEndTest` (Android JVM) drives *this*
 *     JavaScript device against a Kotlin device over a real socket and asserts that both derive the
 *     same Safety Number and root key and both persist matching peer records. Two independent
 *     implementations agreeing is the strongest evidence available without two physical phones.
 *
 * Key schedule (must match `RemoteKeySchedule.kt` exactly):
 *   DH1 = ECDH(EK_owner, SPK_recipient)
 *   DH2 = ECDH(EK_recipient, SPK_owner)
 *   DH3 = ECDH(EK_owner, EK_recipient)
 *   salt = transcript("DuoLink-RemoteHandshakeSalt-v1", version, invitationId, ownerDeviceId,
 *                     recipientDeviceId, ownerIdentity, recipientIdentity, ownerSpk, recipientSpk,
 *                     ownerEphemeral, recipientEphemeral, ownerNonce, recipientNonce,
 *                     recipientIdentitySignature)
 *   prk  = HKDF-Extract(salt, DH1 || DH2 || DH3)
 *   keys = HKDF-Expand(prk, info=domain, L)
 *   SafetyNumber = 60 digits from SHA-512 iterated 5200x over the canonical binding + DH material
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createCipheriv,
  createDecipheriv,
  createHmac,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import { PROTOCOL_VERSION, MAX_CIPHERTEXT_BYTES } from './constants.js';

const HASH_LEN = 32;
const GCM_NONCE_LEN = 12;
const TAG_LEN = 16;

// ---------------------------------------------------------------------------------------------
// Encoding primitives shared with protocol.js (length-prefixed transcripts)
// ---------------------------------------------------------------------------------------------

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
const lp = (bytes) => Buffer.concat([u32(Buffer.from(bytes).length), Buffer.from(bytes)]);
const utf8 = (s) => Buffer.from(s, 'utf8');
const transcript = (domain, parts) => Buffer.concat([utf8(domain), ...parts]);

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64u = (s) => Buffer.from(s, 'base64url');
export const sha256 = (buf) => createHash('sha256').update(buf).digest();

// ---------------------------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869)
// ---------------------------------------------------------------------------------------------

export function hkdfExtract(salt, ikm) {
  return createHmac('sha256', salt && salt.length ? salt : Buffer.alloc(HASH_LEN)).update(ikm).digest();
}

export function hkdfExpand(prk, info, length) {
  const blocks = [];
  let previous = Buffer.alloc(0);
  let counter = 1;
  let produced = 0;
  while (produced < length) {
    const mac = createHmac('sha256', prk);
    mac.update(previous);
    mac.update(info);
    mac.update(Buffer.from([counter]));
    previous = mac.digest();
    blocks.push(previous);
    produced += previous.length;
    counter += 1;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

const hkdf = (ikm, salt, info, length) => hkdfExpand(hkdfExtract(salt, ikm), info, length);

// ---------------------------------------------------------------------------------------------
// Identity: P-256 signing key + deviceId derivation identical to the Android implementation
// ---------------------------------------------------------------------------------------------

export function createIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const deviceId = sha256(Buffer.concat([utf8('DuoLink-DeviceId-v1'), spki])).subarray(0, 16);
  return {
    privateKey,
    publicKey,
    spki,
    deviceId,
    sign: (message) => sign('sha256', message, { key: privateKey, dsaEncoding: 'der' }),
    verify: (message, signature) => verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, signature),
  };
}

/** P-256 key used for ECDH (SPK / ephemeral). */
export function createEcdhKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey,
    publicKey,
    spki: publicKey.export({ format: 'der', type: 'spki' }),
    agree: (peerSpki) => {
      const peer = createPublicKey({ key: peerSpki, format: 'der', type: 'spki' });
      return diffieHellman({ privateKey, publicKey: peer });
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Transcripts (must match RemoteTranscripts.kt byte for byte)
// ---------------------------------------------------------------------------------------------

export function inviteTranscript({ invitationId, activationCodeHash, deviceId, identitySpki, ackSpki, spkSpki, ephemeralSpki, nonce, expiresAtEpochSec }) {
  return transcript('DUOLINK-REMOTE-INVITE-QR-V1', [
    i32(PROTOCOL_VERSION), lp(utf8(invitationId)), lp(activationCodeHash), lp(deviceId),
    lp(identitySpki), lp(ackSpki), lp(spkSpki), lp(ephemeralSpki), lp(nonce), i64(expiresAtEpochSec),
  ]);
}

export function redeemTranscript({ invitationId, deviceId, identitySpki, ackSpki, spkSpki, ephemeralSpki, nonce }) {
  return transcript('DUOLINK-REMOTE-REDEEM-V1', [
    i32(PROTOCOL_VERSION), lp(utf8(invitationId)), lp(deviceId), lp(identitySpki), lp(ackSpki),
    lp(spkSpki), lp(ephemeralSpki), lp(nonce),
  ]);
}

export function ackTranscript({ invitationId, role, deviceId, commitDigestOwner, commitDigestRecipient }) {
  return transcript('DUOLINK-REMOTE-ACK-V1', [
    i32(PROTOCOL_VERSION), lp(utf8(invitationId)), lp(utf8(role)), lp(deviceId),
    lp(commitDigestOwner), lp(commitDigestRecipient),
  ]);
}

export function commitPlaintextTranscript({ invitationId, role, deviceId, peerDeviceId, rootKey, ephemeralPublicSpki, spkPublicSpki, safetyNumber, issuedAtEpochSec }) {
  return transcript('DUOLINK-REMOTE-COMMIT-V1', [
    i32(PROTOCOL_VERSION), lp(utf8(invitationId)), lp(utf8(role)), lp(deviceId), lp(peerDeviceId),
    lp(rootKey), lp(ephemeralPublicSpki), lp(spkPublicSpki), lp(utf8(normaliseSafetyNumber(safetyNumber))),
    i64(issuedAtEpochSec),
  ]);
}

function normaliseSafetyNumber(value) {
  return value.trim().split(/\s+/).filter(Boolean).join(' ');
}

// ---------------------------------------------------------------------------------------------
// Key schedule (mirrors RemoteKeySchedule.kt)
// ---------------------------------------------------------------------------------------------

export function handshakeSalt(binding) {
  return transcript('DuoLink-RemoteHandshakeSalt-v1', [
    i32(binding.protocolVersion),
    lp(utf8(binding.invitationId)),
    lp(binding.ownerDeviceId),
    lp(binding.recipientDeviceId),
    lp(binding.ownerIdentitySpki),
    lp(binding.recipientIdentitySpki),
    lp(binding.ownerSpkSpki),
    lp(binding.recipientSpkSpki),
    lp(binding.ownerEphemeralSpki),
    lp(binding.recipientEphemeralSpki),
    lp(binding.ownerNonce),
    lp(binding.recipientNonce),
    lp(binding.recipientIdentitySignature),
  ]);
}

export function deriveKeySet(role, binding, dhSecrets) {
  const ikm = Buffer.concat(dhSecrets);
  const salt = handshakeSalt(binding);
  const prk = hkdfExtract(salt, ikm);
  const root = hkdfExpand(prk, utf8('DuoLink-RemotePairRoot-v1'), 32);
  const envC2R = hkdfExpand(prk, utf8('DuoLink-RemoteEnvC2R-v1'), 32);
  const envR2C = hkdfExpand(prk, utf8('DuoLink-RemoteEnvR2C-v1'), 32);
  const confirmOwner = hkdfExpand(prk, utf8('DuoLink-RemoteConfirmOwner-v1'), 32);
  const confirmRecipient = hkdfExpand(prk, utf8('DuoLink-RemoteConfirmRecipient-v1'), 32);
  const isOwner = role === 'owner';
  return {
    role,
    rootKey: root,
    encryptKey: isOwner ? envC2R : envR2C,
    decryptKey: isOwner ? envR2C : envC2R,
    ownConfirmKey: isOwner ? confirmOwner : confirmRecipient,
    peerConfirmKey: isOwner ? confirmRecipient : confirmOwner,
    safetyNumber: safetyNumber(binding, ikm),
  };
}

/** 60-digit Safety Number: 12 groups of 5, three groups per row (matches RemoteSafetyNumber.kt). */
export function safetyNumber(binding, dhMaterial) {
  const ownerBlock = Buffer.concat([lp(binding.ownerDeviceId), lp(binding.ownerIdentitySpki)]);
  const recipientBlock = Buffer.concat([lp(binding.recipientDeviceId), lp(binding.recipientIdentitySpki)]);
  const cmp = Buffer.compare(ownerBlock, recipientBlock);
  if (cmp === 0) throw new Error('identical device identities');
  const [low, high] = cmp < 0 ? [ownerBlock, recipientBlock] : [recipientBlock, ownerBlock];
  const canonical = transcript('DuoLink-RemoteSafetyNumber-v1', [
    i32(1),
    lp(low),
    lp(high),
    i32(binding.protocolVersion),
    lp(utf8(binding.invitationId)),
    lp(binding.ownerEphemeralSpki),
    lp(binding.recipientEphemeralSpki),
    lp(binding.ownerSpkSpki),
    lp(binding.recipientSpkSpki),
    lp(binding.ownerNonce),
    lp(binding.recipientNonce),
    lp(binding.recipientIdentitySignature),
    lp(dhMaterial),
  ]);
  let current = canonical;
  for (let index = 0; index < 5200; index += 1) {
    current = createHash('sha512').update(current).update(canonical).digest();
  }
  const groups = [];
  for (let g = 0; g < 12; g += 1) {
    const offset = g * 5;
    const chunk =
      (BigInt(current[offset]) << 32n) |
      (BigInt(current[offset + 1]) << 24n) |
      (BigInt(current[offset + 2]) << 16n) |
      (BigInt(current[offset + 3]) << 8n) |
      BigInt(current[offset + 4]);
    groups.push((chunk % 100000n).toString().padStart(5, '0'));
  }
  const rows = [];
  for (let i = 0; i < groups.length; i += 3) rows.push(groups.slice(i, i + 3).join(' '));
  return rows.join('\n');
}

// ---------------------------------------------------------------------------------------------
// AEAD envelope + commit codec (mirrors RemoteKeySchedule.Envelope / RemoteCommitCodec.kt)
// ---------------------------------------------------------------------------------------------

export function envelopeAad(invitationId, senderRole, purpose) {
  return transcript('DuoLink-RemoteEnvelopeAAD-v1', [
    i32(PROTOCOL_VERSION), lp(utf8(invitationId)), lp(utf8(senderRole)), lp(utf8(purpose)),
  ]);
}

export function sealEnvelope(key, plaintext, aad) {
  const nonce = randomBytes(GCM_NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([Buffer.from([0x02, GCM_NONCE_LEN]), nonce, ciphertext]);
}

export function openEnvelope(key, sealed, aad) {
  if (sealed.length < 2 + GCM_NONCE_LEN + TAG_LEN) throw new Error('envelope too short');
  if (sealed[0] !== 0x02) throw new Error('unsupported envelope version');
  if (sealed[1] !== GCM_NONCE_LEN) throw new Error('invalid nonce length');
  const nonce = sealed.subarray(2, 2 + GCM_NONCE_LEN);
  const body = sealed.subarray(2 + GCM_NONCE_LEN);
  const ciphertext = body.subarray(0, body.length - TAG_LEN);
  const tag = body.subarray(body.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encodeCommitPlaintext(transcriptBytes, hmac, certificate) {
  return Buffer.concat([
    Buffer.from([0x01]),
    lp(transcriptBytes),
    lp(hmac),
    lp(certificate),
  ]);
}

function decodeCommitPlaintext(plaintext) {
  let offset = 0;
  if (plaintext[offset] !== 0x01) throw new Error('unsupported commit plaintext version');
  offset += 1;
  const readField = () => {
    const length = plaintext.readUInt32BE(offset);
    offset += 4;
    if (offset + length > plaintext.length) throw new Error('commit field truncated');
    const value = plaintext.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const t = readField();
  const hmac = readField();
  const certificate = readField();
  if (offset !== plaintext.length) throw new Error('trailing bytes in commit plaintext');
  return { transcript: t, hmac, certificate };
}

/**
 * One device participating in a Method B pairing. Holds only its own secrets.
 */
export class Device {
  /**
   * @param {string} label human-readable label used only in test output
   */
  constructor(label) {
    this.label = label;
    this.identity = createIdentity();
    this.spk = createEcdhKey();
    this.ackKey = createEcdhKey();
    this.persistedPeer = null;
    this.derived = null;
    this.safetyNumberVerified = false;
  }

  proposeOwnerMaterial(ackSpki) {
    return {
      deviceId: b64u(this.identity.deviceId),
      identitySpki: b64u(this.identity.spki),
      ackSpki: b64u(ackSpki),
      spkSpki: b64u(this.spk.spki),
      ephemeralSpki: b64u(this.ephemeral.spki),
    };
  }

  /** Owner: registers the invitation payload with the server. */
  prepareAsOwner(activationCodeHash, nonce) {
    this.ephemeral = createEcdhKey();
    this.ownerNonce = nonce;
    this.activationCodeHash = activationCodeHash;
    return {
      wire: {
        deviceId: b64u(this.identity.deviceId),
        identitySpki: b64u(this.identity.spki),
        ackSpki: b64u(this.ackKey.spki),
        spkSpki: b64u(this.spk.spki),
        ephemeralSpki: b64u(this.ephemeral.spki),
      },
      nonce,
    };
  }

  /** Recipient: material registered at redemption, including its own nonce. */
  prepareAsRecipient() {
    this.ephemeral = createEcdhKey();
    this.recipientNonce = randomBytes(16);
    return {
      wire: {
        deviceId: b64u(this.identity.deviceId),
        identitySpki: b64u(this.identity.spki),
        ackSpki: b64u(this.ackKey.spki),
        spkSpki: b64u(this.spk.spki),
        ephemeralSpki: b64u(this.ephemeral.spki),
      },
      redeemSignature: this.identity.sign(
        redeemTranscript({
          invitationId: this.invitationId,
          deviceId: this.identity.deviceId,
          identitySpki: this.identity.spki,
          ackSpki: this.ackKey.spki,
          spkSpki: this.spk.spki,
          ephemeralSpki: this.ephemeral.spki,
          nonce: this.recipientNonce,
        })
      ),
    };
  }

  /** Builds the shared binding from the owner's view. */
  buildBinding({ invitationId, owner, recipient, recipientIdentitySignature }) {
    return {
      protocolVersion: PROTOCOL_VERSION,
      invitationId,
      ownerDeviceId: owner.deviceId,
      recipientDeviceId: recipient.deviceId,
      ownerIdentitySpki: owner.identitySpki,
      recipientIdentitySpki: recipient.identitySpki,
      ownerSpkSpki: owner.spkSpki,
      recipientSpkSpki: recipient.spkSpki,
      ownerEphemeralSpki: owner.ephemeralSpki,
      recipientEphemeralSpki: recipient.ephemeralSpki,
      ownerNonce: owner.nonce,
      recipientNonce: recipient.nonce,
      recipientIdentitySignature,
    };
  }

  /** Derives keys from the two DH contributions this device can compute. */
  derive(role, binding) {
    const isOwner = role === 'owner';
    const dhA = isOwner ? this.ephemeral.agree(binding.recipientSpkSpki) : this.ephemeral.agree(binding.ownerSpkSpki);
    const dhB = this.ephemeral.agree(binding.recipientEphemeralSpki);
    this.derived = deriveKeySet(role, binding, [dhA, dhB]);
    return this.derived;
  }

  buildCommit({ invitationId, role }) {
    const isOwner = role === 'owner';
    const bindingId = invitationId;
    const peerDeviceId = isOwner ? this.peer.deviceId : this.peer.deviceId;
    const t = commitPlaintextTranscript({
      invitationId: bindingId,
      role,
      deviceId: this.identity.deviceId,
      peerDeviceId,
      rootKey: this.derived.rootKey,
      ephemeralPublicSpki: this.ephemeral.spki,
      spkPublicSpki: this.spk.spki,
      safetyNumber: this.derived.safetyNumber,
      issuedAtEpochSec: Math.floor(Date.now() / 1000),
    });
    const hmac = createHmac('sha256', this.derived.ownConfirmKey).update(t).digest();
    const certificate = this.identity.sign(Buffer.concat([t, hmac]));
    const plaintext = encodeCommitPlaintext(t, hmac, certificate);
    const aad = envelopeAad(bindingId, role, 'commit');
    this.commit = sealEnvelope(this.derived.encryptKey, plaintext, aad);
    this.commitIssuedAt = Number(plaintext.length) >= 0 ? t.readBigInt64BE(t.length - 8) : 0n;
    return this.commit;
  }

  /**
   * Verifies the peer commit exactly as the Android code does: digest → AEAD → transcript → HMAC →
   * ECDSA certificate → deviceId binding. Returns a structured record of what was proven.
   */
  verifyPeerCommit({ invitationId, peerRole, sealed, advertisedDigest, peerIdentitySpki, peer }) {
    const digest = sha256(sealed);
    if (!timingSafeEqual(digest, advertisedDigest)) throw new Error('advertised digest mismatch');
    const aad = envelopeAad(invitationId, peerRole, 'commit');
    const plaintext = openEnvelope(this.derived.decryptKey, sealed, aad);
    const { transcript: peerTranscript, hmac, certificate } = decodeCommitPlaintext(plaintext);
    const issuedAt = Number(peerTranscript.readBigInt64BE(peerTranscript.length - 8));
    const expected = commitPlaintextTranscript({
      invitationId,
      role: peerRole,
      deviceId: peer.deviceId,
      peerDeviceId: this.identity.deviceId,
      rootKey: this.derived.rootKey,
      ephemeralPublicSpki: peer.ephemeralSpki,
      spkPublicSpki: peer.spkSpki,
      safetyNumber: this.derived.safetyNumber,
      issuedAtEpochSec: issuedAt,
    });
    if (!timingSafeEqual(expected, peerTranscript)) throw new Error('transcript mismatch');
    const expectedHmac = createHmac('sha256', this.derived.peerConfirmKey).update(peerTranscript).digest();
    if (!timingSafeEqual(expectedHmac, hmac)) throw new Error('confirmation HMAC invalid');
    const peerKey = createPublicKey({ key: peerIdentitySpki, format: 'der', type: 'spki' });
    const signatureOk = verify(
      'sha256',
      Buffer.concat([peerTranscript, hmac]),
      { key: peerKey, dsaEncoding: 'der' },
      certificate
    );
    if (!signatureOk) throw new Error('identity certificate invalid');
    return {
      peerDeviceId: peer.deviceId,
      digest,
      issuedAtEpochSec: issuedAt,
      hmacVerified: true,
      certificateVerified: true,
    };
  }

  /** Persists a peer record (in-memory; the server-side retention test inspects the real DB). */
  persistPeer({ peerDeviceId, peerIdentitySpki, rootKey, safetyNumber }) {
    if (this.persistedPeer && !timingSafeEqual(this.persistedPeer.peerIdentitySpki, peerIdentitySpki)) {
      throw new Error('refusing to overwrite an existing trusted peer with a different identity');
    }
    this.persistedPeer = {
      peerDeviceId,
      peerIdentitySpki,
      rootKey,
      safetyNumber,
      pairedAtEpochSec: Math.floor(Date.now() / 1000),
    };
    return this.persistedPeer;
  }

  buildAck({ invitationId, role, commitDigestOwner, commitDigestRecipient }) {
    const t = ackTranscript({
      invitationId,
      role,
      deviceId: this.identity.deviceId,
      commitDigestOwner,
      commitDigestRecipient,
    });
    return this.ackKey.identitySignature(t)}
}

export { MAX_CIPHERTEXT_BYTES };

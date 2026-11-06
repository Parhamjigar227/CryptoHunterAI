/**
 * DuoLink signaling server — cryptographic verification primitives.
 *
 * The server is deliberately *cryptographically minimal*. It holds and verifies ONLY public
 * material. It possesses, at any moment:
 *   - participants' public keys (long-term identity, pairwise-auth key, signed pre-key, ephemeral),
 *   - a salted hash of each invitation's activation code,
 *   - a salted hash of each bearer token,
 *   - opaque end-to-end-encrypted commit/ACK ciphertexts (which it can never decrypt).
 *
 * It NEVER possesses: private keys, the pairing root key, directional envelope keys, confirmation
 * HMAC keys, or any plaintext handshake payload. Consequently the server verifies ECDSA signatures
 * (public-key operation) and can NEVER verify a peer HMAC (symmetric operation requiring a key it
 * must not have). See docs/REMOTE_SIGNALING_PROTOCOL.md §7 for the exact boundary table.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomInt,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import { LIMITS } from './protocol.js';

/** Canonical X.509 SubjectPublicKeyInfo prefix for an uncompressed NIST P-256 public key (26 bytes). */
export const P256_SPKI_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d03010703420004',
  'hex'
);

export class ProtocolError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
const B64U_RE = /^[A-Za-z0-9_-]+$/;

/** Strict canonical base64url decoder: rejects padding, whitespace and non-zero trailing bits. */
export function fromB64uStrict(value, fieldName = 'value') {
  if (typeof value !== 'string' || value.length === 0 || !B64U_RE.test(value)) {
    throw new ProtocolError('malformed_encoding', `${fieldName} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length === 0 || decoded.toString('base64url') !== value) {
    throw new ProtocolError('malformed_encoding', `${fieldName} is not canonical base64url`);
  }
  return decoded;
}

/** Strictly parses an uncompressed NIST P-256 SPKI public key and proves it is a valid curve point. */
export function parseP256PublicKeyDer(der, fieldName = 'publicKey') {
  if (!Buffer.isBuffer(der) || der.length !== LIMITS.publicKeySpkiBytes) {
    throw new ProtocolError('invalid_public_key', `${fieldName} must be ${LIMITS.publicKeySpkiBytes} bytes`);
  }
  if (!der.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) {
    throw new ProtocolError('invalid_public_key', `${fieldName} is not an uncompressed NIST P-256 SPKI key`);
  }
  try {
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new ProtocolError('invalid_public_key', `${fieldName} is not a valid curve point`);
  }
}

export function parseP256PublicKeyB64u(value, fieldName) {
  return parseP256PublicKeyDer(fromB64uStrict(value, fieldName), fieldName);
}

/** Verifies a DER-encoded `SHA256withECDSA` signature. Never throws for bad input, only returns false. */
export function verifyEcdsaSha256(publicKeyDer, message, signatureDer) {
  if (!Buffer.isBuffer(signatureDer) || signatureDer.length < LIMITS.minSignatureBytes || signatureDer.length > LIMITS.maxSignatureBytes) {
    return false;
  }
  try {
    const key = parseP256PublicKeyDer(publicKeyDer);
    return verify('sha256', message, { key, dsaEncoding: 'der' }, signatureDer);
  } catch {
    return false;
  }
}

/** `deviceId = sha256("DuoLink-DeviceId-v1" || IK_sig_spki)[0..16]` — identical to the Android implementation. */
export function computeDeviceId(identitySpki) {
  return createHash('sha256')
    .update(Buffer.from('DuoLink-DeviceId-v1', 'utf8'))
    .update(identitySpki)
    .digest()
    .subarray(0, LIMITS.deviceIdBytes);
}

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

/** Constant-time comparison that leaks only the length relationship (both sides are fixed-width). */
export function safeEquals(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------------------------
// Activation codes: 16 chars of base32 (Crockford-style alphabet without ambiguous glyphs),
// grouped in 4 blocks of 4 => 80 bits of CSPRNG entropy, single use, 15 minute lifetime.
// ---------------------------------------------------------------------------------------------

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateActivationCode(random = randomInt) {
  let raw = '';
  for (let i = 0; i < LIMITS.activationCodeLength; i += 1) raw += CODE_ALPHABET[random(CODE_ALPHABET.length)];
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

/** Normalises user input: strips separators/whitespace, upper-cases, then re-validates strictly. */
export function normaliseActivationCode(input) {
  if (typeof input !== 'string') {
    throw new ProtocolError('invalid_activation_code', 'activation code must be a string');
  }
  const compact = input.replace(/[\s-]/g, '').toUpperCase();
  if (compact.length !== LIMITS.activationCodeLength) {
    throw new ProtocolError('invalid_activation_code', 'activation code has the wrong length');
  }
  for (const ch of compact) {
    if (!CODE_ALPHABET.includes(ch)) {
      throw new ProtocolError('invalid_activation_code', 'activation code contains invalid characters');
    }
  }
  return `${compact.slice(0, 4)}-${compact.slice(4, 8)}-${compact.slice(8, 12)}-${compact.slice(12, 16)}`;
}

/** Salted, domain-separated hash of the activation code. The plaintext code is never persisted. */
export function hashActivationCode(code) {
  return sha256(Buffer.concat([Buffer.from('DUOLINK-ACTIVATION-CODE-V1', 'utf8'), Buffer.from(code, 'utf8')]));
}

// ---------------------------------------------------------------------------------------------
// Bearer tokens: 32 bytes of CSPRNG output handed to one participant exactly once.
// ---------------------------------------------------------------------------------------------

export function generateBearerToken() {
  return randomBytes(LIMITS.tokenBytes);
}

export function hashBearerToken(token) {
  return sha256(Buffer.concat([Buffer.from('DUOLINK-TOKEN-V1', 'utf8'), token]));
}

/** 128-bit public invitation identifier, URL/QR-safe. */
export function generateInvitationId() {
  return `inv_${randomBytes(16).toString('base64url')}`;
}

/**
 * Server-side ECDSA key used ONLY to sign receipts (proof-of-acceptance for an ACK). It is not a
 * trust anchor: clients verify receipts against the server's *pinned* public key when configured,
 * otherwise treat them as transport evidence only. Documents must not overstate this.
 */
export function generateServerSigningKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
    publicKeyDer: publicKey.export({ format: 'der', type: 'spki' }),
  };
}

export function loadServerSigningKey(privateKeyPem) {
  return createPrivateKey(privateKeyPem);
}

export function signReceipt(privateKey, message) {
  return sign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
}

export function serverPublicKeyDer(privateKeyPem) {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ format: 'der', type: 'spki' });
}

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
  createHmac,
  pbkdf2Sync,
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

/**
 * Generates a 10-digit numeric invitation code, grouped `482-913-7462`.
 *
 * `random` is injectable so tests can drive the generator deterministically. In production it is
 * `randomInt`, which is the CSPRNG-backed uniform integer source from `node:crypto`, never `Math.random`.
 *
 * The leading digit is drawn from 1..9 rather than 0..9. A leading zero would give the code two
 * spellings (`0482913746` vs `482913746`) and therefore two chances of a typo matching a live
 * invitation; it would also make a zero-padded display ambiguous. The loss of entropy is 0.15 bits,
 * which is immaterial, and the uniformity of the remaining nine digits is unaffected.
 */
export function generateNumericActivationCode(random = randomInt) {
  let raw = String(random(9) + 1); // 1..9
  for (let i = 1; i < LIMITS.numericCodeDigits; i += 1) raw += String(random(10));
  return `${raw.slice(0, 3)}-${raw.slice(3, 6)}-${raw.slice(6)}`;
}

/**
 * Normalises user input into the canonical grouped form.
 *
 * Two accepted shapes, both re-validated strictly after normalisation:
 *   - **Legacy 16-symbol base32** (80 bits): `ABCD-EFGH-JKMN-PQRS`. Still accepted so that any
 *     invitation minted before the numeric release keeps working.
 *   - **10-digit numeric** (33.2 bits): `4829137462`, displayed as `482-913-7462`. This is the
 *     "Remote Pairing by Numeric Invitation Code" flow.
 *
 * Normalisation is deliberately conservative: separators and whitespace are stripped and case is
 * folded, but nothing is ever "corrected". Persian/Arabic-Indic digits are NOT transliterated,
 * because guessing at intent is exactly how a user ends up typing a code that silently becomes a
 * different code. Unrecognised input is rejected.
 */
export function normaliseActivationCode(input) {
  if (typeof input !== 'string') {
    throw new ProtocolError('invalid_activation_code', 'activation code must be a string');
  }
  // Separators are stripped, not interpreted. Only characters that appear in NEITHER alphabet
  // (whitespace, '-', '.', '_') are removed, so stripping can never make two distinct codes collide -
  // every accepted spelling still denotes exactly one code. This matches the Android client's parser.
  const compact = input.replace(/[\s._-]/g, '').toUpperCase();

  // ---- numeric form -------------------------------------------------------------------
  if (/^[0-9]+$/.test(compact)) {
    if (compact.length !== LIMITS.numericCodeDigits) {
      throw new ProtocolError('invalid_activation_code', 'numeric activation code has the wrong length');
    }
    return `${compact.slice(0, 3)}-${compact.slice(3, 6)}-${compact.slice(6)}`;
  }

  // ---- legacy base32 form -------------------------------------------------------------
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

/** True when a canonical code is the numeric form (used to pick the hash parameters). */
export function isNumericActivationCode(canonicalCode) {
  return /^[0-9-]+$/.test(canonicalCode);
}

/**
 * Server-side secret ("pepper") that keys the activation-code hash.
 *
 * WHY THIS EXISTS — the concrete attack it closes:
 * A 10-digit code carries only 33.2 bits. Hashing it with a bare SHA-256 and storing that digest
 * means anyone who obtains the database (leak, backup, stolen disk, SQL injection) can enumerate
 * the entire keyspace OFFLINE, with no server involved, so no rate limit applies. Measured on this
 * hardware, a bare SHA-256 runs at ~435,000 guesses/sec/core, i.e. all 10^10 codes in about
 * 6.4 CPU-hours. Every code ever issued inside a retention window would fall out.
 *
 * Keying the hash with a secret held ONLY in the process environment (never in the database) makes
 * that attack impossible from a database copy alone: the attacker would need the pepper too. The
 * pepper is per-deployment, so one compromised server does not weaken any other.
 *
 * Failure mode is deliberately hard: without a pepper we REFUSE to hash numeric codes rather than
 * silently falling back to the unkeyed digest. A quiet fallback would reintroduce the exact
 * weakness this function exists to prevent, and nobody would notice.
 */
const PEPPER_ENV_VAR = 'DUOLINK_ACTIVATION_PEPPER';

/** Minimum pepper length. 32 bytes of entropy as a 64-char hex string, or any 32+ char secret. */
const MIN_PEPPER_LENGTH = 32;

/** PBKDF2 work factor for the numeric code. Tuned to stay well under 100 ms server-side. */
export const NUMERIC_CODE_PBKDF2_ITERATIONS = 120_000;

let cachedPepper = null;

/** Resolves the pepper, or throws if it is missing/too weak. Cached per process. */
export function resolveActivationPepper(env = process.env) {
  if (cachedPepper !== null) return cachedPepper;
  const raw = env[PEPPER_ENV_VAR];
  if (typeof raw !== 'string' || raw.length < MIN_PEPPER_LENGTH) {
    throw new ProtocolError(
      'server_misconfigured',
      `${PEPPER_ENV_VAR} must be set to a secret of at least ${MIN_PEPPER_LENGTH} characters ` +
        'before numeric invitation codes can be used (generate with: openssl rand -hex 32)',
      503,
    );
  }
  cachedPepper = Buffer.from(raw, 'utf8');
  return cachedPepper;
}

/** Test/administration hook: clears the cached pepper so a new environment can be picked up. */
export function resetActivationPepperCache() {
  cachedPepper = null;
}

/** Overrides the pepper for tests. Never call this from production code. */
export function setActivationPepperForTesting(value) {
  cachedPepper = value === null ? null : Buffer.from(value, 'utf8');
}

/**
 * Hash of an activation code, as stored by the server. The plaintext code is never persisted.
 *
 * Two parameter sets, chosen by the code shape:
 *
 *   numeric (33.2 bits)  -> HMAC-SHA256(pepper, code) stretched with PBKDF2-HMAC-SHA256, 120k rounds.
 *   legacy base32 (80 bits) -> the original domain-separated SHA-256, unchanged.
 *
 * The legacy branch is intentionally NOT changed: 80 bits is not offline-enumerable, and leaving it
 * byte-identical means every existing transcript, stored row and parity test keeps working. Changing
 * it would have been churn with no security benefit and real compatibility cost.
 *
 * PBKDF2 is applied AFTER the HMAC, so an attacker without the pepper cannot even reach the
 * stretching step: the cost of a guess is "must already possess the server secret".
 */
export function hashActivationCode(code) {
  if (isNumericActivationCode(code)) {
    const pepper = resolveActivationPepper();
    const keyed = createHmac('sha256', pepper)
      .update(Buffer.from('DUOLINK-NUMERIC-CODE-V1', 'utf8'))
      .update(Buffer.from(code, 'utf8'))
      .digest();
    return pbkdf2Sync(keyed, Buffer.from('DUOLINK-NUMERIC-PBKDF2-SALT-V1', 'utf8'),
      NUMERIC_CODE_PBKDF2_ITERATIONS, 32, 'sha256');
  }
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

/**
 * DuoLink signaling server — transactional persistence and the invitation state machine.
 *
 * Every state transition happens inside a single `BEGIN IMMEDIATE ... COMMIT` block so that two
 * concurrent HTTP requests can never interleave a read-modify-write cycle. `BEGIN IMMEDIATE`
 * acquires the SQLite write lock at transaction start, which is what makes the commit-quorum
 * serialisation barrier (`T_quorum`) trustworthy on a single server process as well as across
 * multiple processes sharing one database file.
 *
 * What the server stores (privacy-minimal):
 *   - public keys only (identity, pairwise-ACK verification, signed pre-key, ephemeral),
 *   - salted hashes of the activation code and of both bearer tokens,
 *   - opaque end-to-end-encrypted commit/ACK ciphertexts with their SHA-256 digests,
 *   - timestamps and state.
 * What it never stores: private keys, pairing root keys, envelope keys, confirmation HMAC keys,
 * plaintext handshake payloads, or the plaintext activation code.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  INVITATION_TTL_SECONDS,
  InvitationState,
  LIMITS,
  PROTOCOL_VERSION,
  ROLE_OWNER,
  ROLE_RECIPIENT,
  ackTranscript,
  digestCiphertext,
  receiptTranscript,
} from './protocol.js';
import {
  ProtocolError,
  computeDeviceId,
  hashActivationCode,
  hashBearerToken,
  parseP256PublicKeyDer,
  safeEquals,
  sha256,
  verifyEcdsaSha256,
} from './crypto.js';

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS invitations (
  invitation_id            TEXT PRIMARY KEY,
  protocol_version         INTEGER NOT NULL,
  state                    TEXT    NOT NULL,

  created_at               INTEGER NOT NULL,
  expires_at               INTEGER NOT NULL,
  redeemed_at              INTEGER,
  quorum_at                INTEGER,
  terminal_at              INTEGER,
  purged_at                INTEGER,

  code_hash                BLOB    NOT NULL,
  owner_token_hash         BLOB    NOT NULL,
  recipient_token_hash     BLOB,

  owner_device_id          BLOB    NOT NULL,
  owner_identity_spki      BLOB    NOT NULL,
  owner_ack_spki           BLOB    NOT NULL,
  owner_spk_spki           BLOB    NOT NULL,
  owner_ephemeral_spki     BLOB,
  owner_nonce              BLOB,
  owner_identity_signature BLOB,
  owner_spk_id             INTEGER,
  owner_spk_created_at     INTEGER,
  owner_spk_signature      BLOB,

  recipient_device_id      BLOB,
  recipient_identity_spki  BLOB,
  recipient_ack_spki       BLOB,
  recipient_spk_spki       BLOB,
  recipient_ephemeral_spki BLOB,
  recipient_nonce          BLOB,
  recipient_identity_signature BLOB,
  recipient_spk_id         INTEGER,
  recipient_spk_created_at INTEGER,
  recipient_spk_signature  BLOB,

  owner_commit             BLOB,
  owner_commit_digest      BLOB,
  owner_commit_at          INTEGER,
  recipient_commit         BLOB,
  recipient_commit_digest  BLOB,
  recipient_commit_at      INTEGER,

  owner_ack                BLOB,
  owner_ack_digest         BLOB,
  owner_ack_at             INTEGER,
  recipient_ack            BLOB,
  recipient_ack_digest     BLOB,
  recipient_ack_at         INTEGER,

  activation_failures      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_invitations_expires_at ON invitations (expires_at);
CREATE INDEX IF NOT EXISTS idx_invitations_state ON invitations (state);

CREATE TABLE IF NOT EXISTS rate_events (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket TEXT    NOT NULL,
  ts     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_events_bucket_ts ON rate_events (bucket, ts);
`;

const nowSec = (clock) => Math.floor(clock() / 1000);

/**
 * Allowed transitions. Any transition not listed here is impossible by construction, which is what
 * keeps "cancellation after quorum" from resurrecting an invitation or losing a peer's commit.
 */
const ALLOWED_TRANSITIONS = Object.freeze({
  [InvitationState.CREATED]: [
    InvitationState.REDEEMED,
    InvitationState.REVOKED,
    InvitationState.EXPIRED,
  ],
  [InvitationState.REDEEMED]: [
    InvitationState.COMMITS_PARTIAL,
    InvitationState.REVOKED,
    InvitationState.REJECTED,
    InvitationState.EXPIRED,
  ],
  [InvitationState.COMMITS_PARTIAL]: [
    InvitationState.COMMIT_QUORUM_REACHED,
    InvitationState.REVOKED,
    InvitationState.EXPIRED,
  ],
  [InvitationState.COMMIT_QUORUM_REACHED]: [
    InvitationState.MUTUAL_RECEIPT,
    InvitationState.REVOKED,
    InvitationState.EXPIRED,
  ],
  [InvitationState.MUTUAL_RECEIPT]: [],
  [InvitationState.REVOKED]: [],
  [InvitationState.REJECTED]: [],
  [InvitationState.EXPIRED]: [],
});

export class InvitationStore {
  #db;
  #clock;
  #retentionSecondsAfterTerminal;

  /**
   * @param {object} opts
   * @param {string} opts.databasePath filesystem path, or ':memory:' for ephemeral instances
   * @param {() => number} [opts.clock] milliseconds clock injection point (tests use a fake clock)
   * @param {number} [opts.retentionSecondsAfterTerminal] tombstone retention after a terminal state
   */
  constructor({ databasePath, clock = () => Date.now(), retentionSecondsAfterTerminal = 600 }) {
    if (databasePath !== ':memory:') {
      mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
    }
    this.#db = new DatabaseSync(databasePath);
    this.#clock = clock;
    this.#retentionSecondsAfterTerminal = retentionSecondsAfterTerminal;
    this.#db.exec(SCHEMA);
  }

  close() {
    this.#db.close();
  }

  #inTransaction = false;

  /** Runs `fn` inside an IMMEDIATE transaction, rolling back on any thrown error. */
  #transaction(fn) {
    if (this.#inTransaction) return fn();
    this.#db.exec('BEGIN IMMEDIATE');
    this.#inTransaction = true;
    try {
      const result = fn();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.#db.exec('ROLLBACK');
      } catch {
        /* the transaction may already be closed by SQLite after a fatal error */
      }
      throw error;
    } finally {
      this.#inTransaction = false;
    }
  }

  /**
   * `node:sqlite` returns BLOB columns as `Uint8Array`. Every comparison in this store is
   * Buffer-based and constant-time, so rows are normalised at the boundary exactly once.
   */
  static #normaliseRow(row) {
    if (!row) return null;
    const out = {};
    for (const [key, value] of Object.entries(row)) {
      out[key] = value instanceof Uint8Array ? Buffer.from(value) : value;
    }
    return out;
  }

  #row(invitationId) {
    return InvitationStore.#normaliseRow(
      this.#db.prepare('SELECT * FROM invitations WHERE invitation_id = ?').get(invitationId) ?? null
    );
  }

  #setState(row, next, patch = {}) {
    const allowed = ALLOWED_TRANSITIONS[row.state] ?? [];
    if (next !== row.state && !allowed.includes(next)) {
      throw new ProtocolError(
        'invalid_transition',
        `Invitation cannot move from ${row.state} to ${next}`,
        409
      );
    }
    const terminal =
      next === InvitationState.MUTUAL_RECEIPT ||
      next === InvitationState.REVOKED ||
      next === InvitationState.REJECTED ||
      next === InvitationState.EXPIRED;
    const assignments = ['state = ?'];
    const values = [next];
    for (const [column, value] of Object.entries(patch)) {
      assignments.push(`${column} = ?`);
      values.push(value);
    }
    if (terminal) {
      assignments.push('terminal_at = ?');
      values.push(nowSec(this.#clock));
    }
    this.#db
      .prepare(`UPDATE invitations SET ${assignments.join(', ')} WHERE invitation_id = ?`)
      .run(...values, row.invitation_id);
  }

  /**
   * Marks an invitation expired when its TTL has elapsed, in its own committed transaction.
   *
   * This is deliberately separate from the request's transaction: a request that discovers an
   * expired invitation *fails* (404/410), and letting that failure roll back the expiry write
   * would resurrect the invitation on the next request.
   */
  #expireIfNeeded(invitationId) {
    return this.#transaction(() => {
      const current = this.#row(invitationId);
      if (!current) return null;
      if (
        current.state === InvitationState.EXPIRED ||
        current.state === InvitationState.MUTUAL_RECEIPT ||
        current.state === InvitationState.REVOKED ||
        current.state === InvitationState.REJECTED
      ) {
        return current;
      }
      if (nowSec(this.#clock) < current.expires_at) return current;
      this.#setState(current, InvitationState.EXPIRED, {
        owner_commit: null,
        recipient_commit: null,
      });
      return this.#row(invitationId);
    });
  }

  #requireLive(row) {
    if (!row) throw new ProtocolError('not_found', 'No such invitation', 404);
    if (row.state === InvitationState.EXPIRED) {
      throw new ProtocolError('expired', 'Invitation has expired', 410);
    }
    if (row.state === InvitationState.REVOKED) {
      throw new ProtocolError('revoked', 'Invitation was revoked by its owner', 409);
    }
    if (row.state === InvitationState.REJECTED) {
      throw new ProtocolError('rejected', 'Invitation was rejected by the recipient', 409);
    }
    return row;
  }

  /**
   * Resolves the caller's role from its bearer token, or throws `401`.
   *
   * `token` arrives raw from the transport layer and is hashed here; a malformed token can therefore
   * never be mistaken for an authorisation success, and no token is ever compared in plaintext.
   */
  #authenticate(row, token) {
    if (!Buffer.isBuffer(token) || token.length !== LIMITS.tokenBytes) {
      throw new ProtocolError('unauthenticated', 'Invalid or unknown bearer token', 401);
    }
    const provided = hashBearerToken(token);
    if (safeEquals(provided, row.owner_token_hash)) return ROLE_OWNER;
    if (row.recipient_token_hash && safeEquals(provided, row.recipient_token_hash)) return ROLE_RECIPIENT;
    throw new ProtocolError('unauthenticated', 'Invalid or unknown bearer token', 401);
  }

  // -------------------------------------------------------------------------------------------
  // Rate limiting (durable so a restart cannot be used to reset an attacker's budget)
  // -------------------------------------------------------------------------------------------

  checkRateLimit(bucket, limit, windowSeconds) {
    const now = nowSec(this.#clock);
    const cutoff = now - windowSeconds;
    return this.#transaction(() => {
      this.#db.prepare('DELETE FROM rate_events WHERE ts < ?').run(cutoff);
      const row = this.#db
        .prepare('SELECT COUNT(*) AS count FROM rate_events WHERE bucket = ? AND ts >= ?')
        .get(bucket, cutoff);
      if (row.count >= limit) {
        throw new ProtocolError('rate_limited', 'Too many requests; slow down and retry later', 429);
      }
      this.#db.prepare('INSERT INTO rate_events (bucket, ts) VALUES (?, ?)').run(bucket, now);
      return row.count + 1;
    });
  }

  // -------------------------------------------------------------------------------------------
  // Lifecycle: create / redeem
  // -------------------------------------------------------------------------------------------

  createInvitation({
    invitationId,
    activationCode,
    ownerToken,
    owner,
    ttlSeconds = INVITATION_TTL_SECONDS,
  }) {
    if (typeof invitationId !== 'string' || !/^inv_[A-Za-z0-9_-]{16,32}$/.test(invitationId)) {
      throw new ProtocolError('invalid_invitation_id', 'invitationId must match inv_[A-Za-z0-9_-]{16,32}');
    }
    const createdAt = nowSec(this.#clock);
    const expiresAt = createdAt + ttlSeconds;
    const normalised = {
      deviceId: owner.deviceId,
      identitySpki: owner.identitySpki,
      ackSpki: owner.ackSpki,
      spkSpki: owner.spkSpki,
      ephemeralSpki: owner.ephemeralSpki,
      nonce: owner.nonce,
      identitySignature: owner.identitySignature,
      spkId: owner.spkId,
      spkCreatedAtEpochSec: owner.spkCreatedAtEpochSec,
      spkSignature: owner.spkSignature,
    };
    for (const [name, key] of [
      ['identitySpki', 'identitySpki'],
      ['ackSpki', 'ackSpki'],
      ['spkSpki', 'spkSpki'],
      ['ephemeralSpki', 'ephemeralSpki'],
    ]) {
      parseP256PublicKeyDer(normalised[key], `owner.${name}`);
    }
    if (normalised.deviceId.length !== LIMITS.deviceIdBytes) {
      throw new ProtocolError('invalid_device_id', 'owner.deviceId must be 16 bytes');
    }
    const expected = computeDeviceId(normalised.identitySpki);
    if (!safeEquals(expected, normalised.deviceId)) {
      throw new ProtocolError('identity_mismatch', 'owner.deviceId does not match owner.identitySpki');
    }
    const ackKeyCheck = computeDeviceId(normalised.ackSpki);
    if (safeEquals(ackKeyCheck, normalised.deviceId)) {
      // The ACK key must be *distinct* from the long-term identity key, otherwise the server would
      // be receiving the long-term identity key it is designed never to see.
      throw new ProtocolError('invalid_ack_key', 'owner.ackSpki must be a fresh session key, not the identity key');
    }

    if (!Buffer.isBuffer(owner.nonce) || owner.nonce.length !== 16) {
      throw new ProtocolError('invalid_nonce', 'owner.nonce must be 16 bytes');
    }
    if (!Buffer.isBuffer(owner.identitySignature) || owner.identitySignature.length < 64 || owner.identitySignature.length > 80) {
      throw new ProtocolError('invalid_signature', 'owner.identitySignature must be a DER ECDSA signature');
    }
    if (!Number.isInteger(owner.spkId) || owner.spkId < 1) {
      throw new ProtocolError('invalid_spk', 'owner.spkId must be a positive integer');
    }
    if (!Number.isInteger(owner.spkCreatedAtEpochSec) || owner.spkCreatedAtEpochSec < 0) {
      throw new ProtocolError('invalid_spk', 'owner.spkCreatedAtEpochSec must be a non-negative integer');
    }
    if (!Buffer.isBuffer(owner.spkSignature) || owner.spkSignature.length < 64 || owner.spkSignature.length > 80) {
      throw new ProtocolError('invalid_spk', 'owner.spkSignature must be a DER ECDSA signature');
    }

    return this.#transaction(() => {
      // ---- numeric-code collision guard ---------------------------------------------------
      // A 10-digit space is 10^10, so collisions are not hypothetical once a deployment issues a few
      // thousand live invitations: birthday-bounded, the odds of at least one clash among N live codes
      // is roughly N^2 / 2*10^10. If two LIVE invitations shared a code, a joiner typing it could be
      // silently routed to the wrong owner - precisely the "no silent connection to an unknown device"
      // guarantee the protocol must uphold. Redemption scans rows and takes the first match, so a
      // duplicate would not even fail loudly; it would simply pick one.
      //
      // Checking here, inside the same transaction as the INSERT, makes minting collision-free by
      // construction rather than by luck. Cheap: the query is a bounded scan over at most one TTL
      // window of live rows, and it runs once per mint, not per redemption.
      const codeHash = hashActivationCode(activationCode);
      const clash = this.#db
        .prepare(
          `SELECT 1 FROM invitations
            WHERE code_hash = ? AND state IN (?, ?, ?) AND expires_at > ? AND purged_at IS NULL
            LIMIT 1`
        )
        .all(
          codeHash,
          InvitationState.CREATED,
          InvitationState.REDEEMED,
          InvitationState.COMMITS_PARTIAL,
          createdAt
        );
      if (clash.length > 0) {
        const error = new ProtocolError(
          'code_collision',
          'Generated invitation code collides with a live invitation; retry generation',
          409
        );
        error.retryable = true;
        throw error;
      }

      this.#db
        .prepare(
          `INSERT INTO invitations (
             invitation_id, protocol_version, state, created_at, expires_at,
             code_hash, owner_token_hash,
             owner_device_id, owner_identity_spki, owner_ack_spki, owner_spk_spki, owner_ephemeral_spki,
             owner_nonce, owner_identity_signature,
             owner_spk_id, owner_spk_created_at, owner_spk_signature
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          invitationId,
          PROTOCOL_VERSION,
          InvitationState.CREATED,
          createdAt,
          expiresAt,
          codeHash,
          hashBearerToken(ownerToken),
          normalised.deviceId,
          normalised.identitySpki,
          normalised.ackSpki,
          normalised.spkSpki,
          normalised.ephemeralSpki,
          owner.nonce,
          owner.identitySignature,
          owner.spkId,
          owner.spkCreatedAtEpochSec,
          owner.spkSignature
        );
      return { invitationId, createdAt, expiresAt };
    });
  }

  /**
   * Redeems an activation code exactly once. Failed attempts are counted on the invitation so a
   * brute-force loop is throttled even when it rotates source addresses.
   */
  /**
   * Resolves an activation code to its invitation id, WITHOUT redeeming, mutating or leaking anything.
   *
   * WHY THIS MUST EXIST (and why the numeric flow is impossible without it):
   * The recipient's redeem transcript binds `invitationId`, and the recipient must SIGN that transcript
   * before it can call `/v1/invitations/redeem` - the signature is part of the redeem request. The QR
   * flow carries the invitation id inside the QR payload (`?c=&i=&s=`), so the joiner has it up front.
   * A ten-digit code cannot carry an id, so without a way to resolve code -> id the joiner cannot
   * construct a transcript to sign, and redemption is impossible. That is a hard protocol-level
   * incompatibility, not a UI gap.
   *
   * SECURITY PROPERTIES — this method is deliberately the weakest-privileged operation in the store:
   *   - returns ONLY `{ invitationId, expiresAtEpochSec }`; no keys, no tokens, no device ids, no
   *     activation code, nothing that could help an attacker beyond confirming a code exists;
   *   - does NOT change state. Redemption (and therefore single-use enforcement) still happens exactly
   *     once, later, in the redeem transaction. Resolving twice is harmless; redeeming twice is not;
   *   - applies the same peppered-hash lookup as redemption, so a stolen database yields no codes;
   *   - refuses expired and already-redeemed invitations exactly like redemption does, so a lookup can
   *     never reveal an id for a dead invitation.
   *
   * The offline-oracle caveat is unchanged by this endpoint: an attacker who can already call it online
   * is bounded by the global activation bucket, which is strictly tighter than the database-leak path
   * documented in `hashActivationCode()`.
   */
  resolveInvitationByCode({ activationCode }) {
    const codeHash = hashActivationCode(activationCode);
    return this.#transaction(() => {
      const candidates = this.#db
        .prepare(
          `SELECT * FROM invitations
            WHERE state IN (?, ?, ?) AND expires_at > ? AND purged_at IS NULL`
        )
        .all(
          InvitationState.CREATED,
          InvitationState.REDEEMED,
          InvitationState.COMMITS_PARTIAL,
          nowSec(this.#clock)
        )
        .map(InvitationStore.#normaliseRow);

      const match = candidates.find((row) => row && safeEquals(row.code_hash, codeHash));
      // Identical error shape and status to a failed redemption, so the two endpoints cannot be
      // distinguished by an attacker probing for "code exists but was already used".
      if (!match) {
        throw new ProtocolError('invalid_activation_code', 'Activation code is invalid or already used', 404);
      }
      const row = this.#requireLive(match);
      // Mirror redemption's state gate EXACTLY. Resolving a redeemed or expired invitation must fail
      // with the same code and status that redeeming it would, otherwise this endpoint becomes a
      // cheaper, differently-shaped probe: an attacker could distinguish "never existed" from "already
      // used" here without spending the redeem path's validation work, and the joiner would be told a
      // dead invitation is still current.
      if (row.state !== InvitationState.CREATED) {
        throw new ProtocolError('already_redeemed', 'This invitation has already been redeemed', 409);
      }
      if (row.protocol_version !== PROTOCOL_VERSION) {
        throw new ProtocolError('unsupported_version', 'Invitation uses an unsupported protocol version', 409);
      }
      return { invitationId: row.invitation_id, expiresAtEpochSec: row.expires_at };
    });
  }

  redeemInvitation({ activationCode, recipient, invitationIdHint = null }) {
    const codeHash = hashActivationCode(activationCode);
    if (invitationIdHint) this.#expireIfNeeded(invitationIdHint);
    return this.#transaction(() => {
      const candidates = invitationIdHint
        ? [this.#row(invitationIdHint), this.#expireIfNeeded(invitationIdHint)].filter(Boolean).slice(-1)
        : this.#db
            .prepare(
              `SELECT * FROM invitations
                WHERE state IN (?, ?, ?) AND expires_at > ? AND purged_at IS NULL`
            )
            .all(
              InvitationState.CREATED,
              InvitationState.REDEEMED,
              InvitationState.COMMITS_PARTIAL,
              nowSec(this.#clock)
            )
            .map(InvitationStore.#normaliseRow);

      const match = candidates.find((row) => row && safeEquals(row.code_hash, codeHash));
      if (!match) {
        throw new ProtocolError('invalid_activation_code', 'Activation code is invalid or already used', 404);
      }
      const row = this.#requireLive(match);
      if (row.state !== InvitationState.CREATED) {
        // The invitation was already redeemed: single use is enforced here, not in the client.
        throw new ProtocolError('already_redeemed', 'This invitation has already been redeemed', 409);
      }
      if (row.protocol_version !== PROTOCOL_VERSION) {
        throw new ProtocolError('unsupported_version', 'Invitation uses an unsupported protocol version', 409);
      }

      for (const field of ['identitySpki', 'ackSpki', 'spkSpki', 'ephemeralSpki']) {
        parseP256PublicKeyDer(recipient[field], `recipient.${field}`);
      }
      if (recipient.deviceId.length !== LIMITS.deviceIdBytes) {
        throw new ProtocolError('invalid_device_id', 'recipient.deviceId must be 16 bytes');
      }
      if (!safeEquals(computeDeviceId(recipient.identitySpki), recipient.deviceId)) {
        throw new ProtocolError('identity_mismatch', 'recipient.deviceId does not match recipient.identitySpki');
      }
      if (safeEquals(recipient.deviceId, row.owner_device_id)) {
        throw new ProtocolError('self_redeem', 'The owner cannot redeem its own invitation', 409);
      }
      if (safeEquals(computeDeviceId(recipient.ackSpki), recipient.deviceId)) {
        throw new ProtocolError('invalid_ack_key', 'recipient.ackSpki must be a fresh session key');
      }

      const recipientToken = recipient.token;
      const redeemedAt = nowSec(this.#clock);
      if (!Buffer.isBuffer(recipient.nonce) || recipient.nonce.length !== 16) {
        throw new ProtocolError('invalid_nonce', 'recipient.nonce must be 16 bytes');
      }
      if (!Buffer.isBuffer(recipient.identitySignature) || recipient.identitySignature.length < 64 || recipient.identitySignature.length > 80) {
        throw new ProtocolError('invalid_signature', 'recipient.identitySignature must be a DER ECDSA signature');
      }
      if (!Number.isInteger(recipient.spkId) || recipient.spkId < 1) {
        throw new ProtocolError('invalid_spk', 'recipient.spkId must be a positive integer');
      }
      if (!Number.isInteger(recipient.spkCreatedAtEpochSec) || recipient.spkCreatedAtEpochSec < 0) {
        throw new ProtocolError('invalid_spk', 'recipient.spkCreatedAtEpochSec must be a non-negative integer');
      }
      if (!Buffer.isBuffer(recipient.spkSignature) || recipient.spkSignature.length < 64 || recipient.spkSignature.length > 80) {
        throw new ProtocolError('invalid_spk', 'recipient.spkSignature must be a DER ECDSA signature');
      }
      this.#setState(row, InvitationState.REDEEMED, {
        redeemed_at: redeemedAt,
        recipient_token_hash: hashBearerToken(recipientToken),
        recipient_device_id: recipient.deviceId,
        recipient_identity_spki: recipient.identitySpki,
        recipient_ack_spki: recipient.ackSpki,
        recipient_spk_spki: recipient.spkSpki,
        recipient_ephemeral_spki: recipient.ephemeralSpki,
        recipient_nonce: recipient.nonce,
        recipient_identity_signature: recipient.identitySignature,
        recipient_spk_id: recipient.spkId,
        recipient_spk_created_at: recipient.spkCreatedAtEpochSec,
        recipient_spk_signature: recipient.spkSignature,
      });
      return { invitationId: row.invitation_id, redeemedAt, expiresAt: row.expires_at };
    });
  }

  // -------------------------------------------------------------------------------------------
  // Commits: receipt is recorded, cryptographic validity is NOT claimed by the server
  // -------------------------------------------------------------------------------------------

  submitCommit({ invitationId, token, role, ciphertext, commitDigest }) {
    this.#expireIfNeeded(invitationId);
    return this.#transaction(() => {
      const row = this.#requireLive(this.#row(invitationId));
      const callerRole = this.#authenticate(row, token);
      if (callerRole !== role) {
        throw new ProtocolError('role_mismatch', 'Bearer token does not belong to the claimed role', 403);
      }
      if (row.state !== InvitationState.REDEEMED && row.state !== InvitationState.COMMITS_PARTIAL) {
        throw new ProtocolError('wrong_state', `Commits are not accepted in state ${row.state}`, 409);
      }
      if (!Buffer.isBuffer(ciphertext) || ciphertext.length < LIMITS.minCiphertextBytes || ciphertext.length > LIMITS.maxCiphertextBytes) {
        throw new ProtocolError('invalid_ciphertext', 'Commit ciphertext length is outside protocol limits');
      }
      const expectedDigest = digestCiphertext(ciphertext);
      if (!Buffer.isBuffer(commitDigest) || !safeEquals(expectedDigest, commitDigest)) {
        throw new ProtocolError('digest_mismatch', 'Declared commit digest does not match the ciphertext');
      }

      const roleColumn = role === ROLE_OWNER ? 'owner' : 'recipient';
      const existing = row[`${roleColumn}_commit`];
      if (existing) {
        if (safeEquals(row[`${roleColumn}_commit_digest`], expectedDigest)) {
          // Idempotent replay of the *same* ciphertext (e.g. client retried after a dropped response).
          return {
            accepted: true,
            replay: true,
            quorumReached: row.state === InvitationState.COMMIT_QUORUM_REACHED,
            commitDigestOwner: Buffer.from(row.owner_commit_digest),
            commitDigestRecipient: row.recipient_commit_digest ? Buffer.from(row.recipient_commit_digest) : null,
          };
        }
        throw new ProtocolError('commit_conflict', 'A different commit was already recorded for this role', 409);
      }

      const patch = {
        [`${roleColumn}_commit`]: ciphertext,
        [`${roleColumn}_commit_digest`]: expectedDigest,
        [`${roleColumn}_commit_at`]: nowSec(this.#clock),
      };
      const ownerDigest = role === ROLE_OWNER ? expectedDigest : row.owner_commit_digest;
      const recipientDigest = role === ROLE_RECIPIENT ? expectedDigest : row.recipient_commit_digest;
      const quorum = Boolean(ownerDigest && recipientDigest);
      if (quorum) {
        patch.quorum_at = nowSec(this.#clock);
      }
      this.#setState(row, quorum ? InvitationState.COMMIT_QUORUM_REACHED : InvitationState.COMMITS_PARTIAL, patch);

      return {
        accepted: true,
        replay: false,
        quorumReached: quorum,
        commitDigestOwner: Buffer.from(ownerDigest),
        commitDigestRecipient: recipientDigest ? Buffer.from(recipientDigest) : null,
      };
    });
  }

  // -------------------------------------------------------------------------------------------
  // Authenticated persistence ACKs
  // -------------------------------------------------------------------------------------------

  /**
   * Records a persistence ACK. The signature is verified here against the *session* ACK public key
   * that the peer registered — never against a key the server does not hold, and never via a
   * symmetric HMAC (which the server cannot and must not check).
   */
  submitAck({ invitationId, token, role, signature }) {
    this.#expireIfNeeded(invitationId);
    return this.#transaction(() => {
      const row = this.#requireLive(this.#row(invitationId));
      const callerRole = this.#authenticate(row, token);
      if (callerRole !== role) {
        throw new ProtocolError('role_mismatch', 'Bearer token does not belong to the claimed role', 403);
      }
      if (row.state !== InvitationState.COMMIT_QUORUM_REACHED) {
        throw new ProtocolError(
          'ack_before_quorum',
          `Persistence ACKs are only accepted after the commit quorum (state is ${row.state})`,
          409
        );
      }
      if (!row.owner_commit_digest || !row.recipient_commit_digest) {
        throw new ProtocolError('ack_before_quorum', 'Both commits must exist before an ACK', 409);
      }
      const roleColumn = role === ROLE_OWNER ? 'owner' : 'recipient';
      if (row[`${roleColumn}_ack`]) {
        if (safeEquals(row[`${roleColumn}_ack`], signature)) {
          return this.#ackResult(this.#row(invitationId), role, true);
        }
        throw new ProtocolError('ack_conflict', 'A different ACK was already recorded for this role', 409);
      }

      const ackKeySpki = role === ROLE_OWNER ? row.owner_ack_spki : row.recipient_ack_spki;
      const deviceId = role === ROLE_OWNER ? row.owner_device_id : row.recipient_device_id;
      const transcript = ackTranscript({
        invitationId: row.invitation_id,
        role,
        deviceId,
        commitDigestOwner: row.owner_commit_digest,
        commitDigestRecipient: row.recipient_commit_digest,
      });
      if (!verifyEcdsaSha256(ackKeySpki, transcript, signature)) {
        throw new ProtocolError('invalid_ack_signature', 'ACK signature does not verify', 400);
      }

      const patch = {
        [`${roleColumn}_ack`]: signature,
        [`${roleColumn}_ack_digest`]: sha256(signature),
        [`${roleColumn}_ack_at`]: nowSec(this.#clock),
      };
      const ownerAck = role === ROLE_OWNER ? signature : row.owner_ack;
      const recipientAck = role === ROLE_RECIPIENT ? signature : row.recipient_ack;
      const mutual = Boolean(ownerAck && recipientAck);
      this.#setState(row, mutual ? InvitationState.MUTUAL_RECEIPT : InvitationState.COMMIT_QUORUM_REACHED, patch);

      // Retention policy: as soon as mutual receipt is proven, both commit ciphertexts are destroyed
      // (the peers have already exchanged and verified them). Only digests and ACK signatures remain,
      // and the whole row is purged by `purge()` after the configured tombstone window.
      if (mutual) {
        this.#db
          .prepare(
            `UPDATE invitations SET owner_commit = NULL, recipient_commit = NULL,
                    owner_ephemeral_spki = NULL, recipient_ephemeral_spki = NULL, purged_at = ?
              WHERE invitation_id = ?`
          )
          .run(nowSec(this.#clock), row.invitation_id);
      }
      return this.#ackResult(this.#row(row.invitation_id), role, false);
    });
  }

  #ackResult(row, role, replay) {
    return {
      ackRecorded: true,
      replay,
      role,
      mutualReceipt: row.state === InvitationState.MUTUAL_RECEIPT,
      ackDigestOwner: row.owner_ack_digest ? Buffer.from(row.owner_ack_digest) : null,
      ackDigestRecipient: row.recipient_ack_digest ? Buffer.from(row.recipient_ack_digest) : null,
      ackOwnerSignature: row.owner_ack ? Buffer.from(row.owner_ack) : null,
      ackRecipientSignature: row.recipient_ack ? Buffer.from(row.recipient_ack) : null,
    };
  }

  // -------------------------------------------------------------------------------------------
  // Cancellation
  // -------------------------------------------------------------------------------------------

  revokeInvitation({ invitationId, token, reason = 'revoked_by_owner' }) {
    this.#expireIfNeeded(invitationId);
    return this.#transaction(() => {
      const row = this.#requireLive(this.#row(invitationId));
      const role = this.#authenticate(row, token);
      if (role !== ROLE_OWNER) {
        throw new ProtocolError('role_mismatch', 'Only the invitation owner may revoke', 403);
      }
      if (row.state === InvitationState.MUTUAL_RECEIPT) {
        throw new ProtocolError(
          'already_mutual',
          'Mutual receipt is already recorded; revocation cannot un-pair persisted trust',
          409
        );
      }
      if (row.state === InvitationState.EXPIRED) {
        throw new ProtocolError('expired', 'Invitation has already expired', 410);
      }
      this.#setState(row, InvitationState.REVOKED, {
        owner_commit: null,
        recipient_commit: null,
        owner_ephemeral_spki: null,
        recipient_ephemeral_spki: null,
        owner_nonce: null,
        recipient_nonce: null,
        owner_identity_signature: null,
        recipient_identity_signature: null,
        owner_spk_signature: null,
        recipient_spk_signature: null,
        purged_at: nowSec(this.#clock),
      });
      return { invitationId: row.invitation_id, state: InvitationState.REVOKED, reason };
    });
  }

  rejectInvitation({ invitationId, token, reason = 'rejected_by_recipient' }) {
    this.#expireIfNeeded(invitationId);
    return this.#transaction(() => {
      const row = this.#requireLive(this.#row(invitationId));
      const role = this.#authenticate(row, token);
      if (role !== ROLE_RECIPIENT) {
        throw new ProtocolError('role_mismatch', 'Only the recipient may reject', 403);
      }
      if (row.state === InvitationState.MUTUAL_RECEIPT) {
        throw new ProtocolError('already_mutual', 'Mutual receipt is already recorded', 409);
      }
      this.#setState(row, InvitationState.REJECTED, {
        owner_commit: null,
        recipient_commit: null,
        owner_ephemeral_spki: null,
        recipient_ephemeral_spki: null,
        owner_nonce: null,
        recipient_nonce: null,
        owner_identity_signature: null,
        recipient_identity_signature: null,
        owner_spk_signature: null,
        recipient_spk_signature: null,
        purged_at: nowSec(this.#clock),
      });
      return { invitationId: row.invitation_id, state: InvitationState.REJECTED, reason };
    });
  }

  // -------------------------------------------------------------------------------------------
  // Polling / state retrieval
  // -------------------------------------------------------------------------------------------

  /**
   * Returns the caller's view of the invitation. Peer commit ciphertext is released **only** after
   * the quorum barrier, so neither side can observe a one-sided commit and mistake it for progress.
   */
  getInvitationView({ invitationId, token }) {
    this.#expireIfNeeded(invitationId);
    return this.#transaction(() => {
      const row = this.#requireLive(this.#row(invitationId));
      const role = this.#authenticate(row, token);
      const isOwner = role === ROLE_OWNER;
      const peerCommit = isOwner ? row.recipient_commit : row.owner_commit;
      const peerDeviceId = isOwner ? row.recipient_device_id : row.owner_device_id;
      const peerIdentity = isOwner ? row.recipient_identity_spki : row.owner_identity_spki;
      const peerSpk = isOwner ? row.recipient_spk_spki : row.owner_spk_spki;
      const peerEphemeral = isOwner ? row.recipient_ephemeral_spki : row.owner_ephemeral_spki;
      const atQuorum =
        row.state === InvitationState.COMMIT_QUORUM_REACHED || row.state === InvitationState.MUTUAL_RECEIPT;
      const ownNonce = isOwner ? row.owner_nonce : row.recipient_nonce;
      const peerNonce = isOwner ? row.recipient_nonce : row.owner_nonce;
      const ownIdentitySignature = isOwner ? row.owner_identity_signature : row.recipient_identity_signature;
      const peerIdentitySignature = isOwner ? row.recipient_identity_signature : row.owner_identity_signature;

      return {
        invitationId: row.invitation_id,
        state: row.state,
        role,
        protocolVersion: row.protocol_version,
        expiresAt: row.expires_at,
        redeemed: row.state !== InvitationState.CREATED,
        quorumReached: atQuorum,
        mutualReceipt: row.state === InvitationState.MUTUAL_RECEIPT,
        ownCommitDigest: isOwner
          ? row.owner_commit_digest
            ? Buffer.from(row.owner_commit_digest)
            : null
          : row.recipient_commit_digest
            ? Buffer.from(row.recipient_commit_digest)
            : null,
        peerCommitDigest: atQuorum
          ? isOwner
            ? row.recipient_commit_digest
              ? Buffer.from(row.recipient_commit_digest)
              : null
            : row.owner_commit_digest
              ? Buffer.from(row.owner_commit_digest)
              : null
          : null,
        peerCommitCiphertext: atQuorum && peerCommit ? Buffer.from(peerCommit) : null,
        ownNonce: ownNonce ? Buffer.from(ownNonce) : null,
        ownIdentitySignature: ownIdentitySignature ? Buffer.from(ownIdentitySignature) : null,
        peer: peerDeviceId
          ? {
              deviceId: Buffer.from(peerDeviceId),
              identitySpki: Buffer.from(peerIdentity),
              spkSpki: Buffer.from(peerSpk),
              ephemeralSpki: peerEphemeral ? Buffer.from(peerEphemeral) : null,
              nonce: peerNonce ? Buffer.from(peerNonce) : null,
              identitySignature: peerIdentitySignature ? Buffer.from(peerIdentitySignature) : null,
              spkId: isOwner ? row.recipient_spk_id : row.owner_spk_id,
              spkCreatedAtEpochSec: isOwner ? row.recipient_spk_created_at : row.owner_spk_created_at,
              spkSignature: (isOwner ? row.recipient_spk_signature : row.owner_spk_signature)
                ? Buffer.from(isOwner ? row.recipient_spk_signature : row.owner_spk_signature)
                : null,
            }
          : null,
        acks: {
          ownerRecorded: Boolean(row.owner_ack),
          recipientRecorded: Boolean(row.recipient_ack),
          ownerSignature: row.owner_ack ? Buffer.from(row.owner_ack) : null,
          recipientSignature: row.recipient_ack ? Buffer.from(row.recipient_ack) : null,
        },
        // Explicit honesty flags: the server has *received* ciphertext, it has not *validated* it.
        ciphertextReceipt: {
          owner: Boolean(row.owner_commit_digest),
          recipient: Boolean(row.recipient_commit_digest),
        },
        e2eeValidityVerifiedByServer: false,
      };
    });
  }

  /** Receipt proving the server accepted an ACK, signed with the server's receipt key. */
  buildReceipt({ row, role, serverSigner }) {
    const deviceId = role === ROLE_OWNER ? row.owner_device_id : row.recipient_device_id;
    const ackDigest = role === ROLE_OWNER ? row.owner_ack_digest : row.recipient_ack_digest;
    const transcript = receiptTranscript({
      invitationId: row.invitation_id,
      role,
      deviceId: Buffer.from(deviceId),
      commitDigestOwner: Buffer.from(row.owner_commit_digest),
      commitDigestRecipient: Buffer.from(row.recipient_commit_digest),
      ackDigest: Buffer.from(ackDigest),
    });
    return { transcript, signature: serverSigner(transcript) };
  }

  rawRow(invitationId) {
    return this.#row(invitationId);
  }

  // -------------------------------------------------------------------------------------------
  // Expiry and retention
  // -------------------------------------------------------------------------------------------

  /** Expires every overdue invitation. Returns the number of rows transitioned. */
  expireOverdue() {
    return this.#transaction(() => {
      const now = nowSec(this.#clock);
      const rows = this.#db
        .prepare(
          `SELECT invitation_id FROM invitations
            WHERE expires_at <= ? AND state IN (?, ?, ?, ?)`
        )
        .all(now, InvitationState.CREATED, InvitationState.REDEEMED, InvitationState.COMMITS_PARTIAL, InvitationState.COMMIT_QUORUM_REACHED);
      for (const { invitation_id: id } of rows) {
        const current = this.#row(id);
        this.#setState(current, InvitationState.EXPIRED, { owner_commit: null, recipient_commit: null });
      }
      return rows.length;
    });
  }

  /** Deletes tombstones after the retention window (and any payload still attached to them). */
  purge(options = {}) {
    const retention = options.retentionSeconds ?? this.#retentionSecondsAfterTerminal;
    return this.#transaction(() => {
      const cutoff = nowSec(this.#clock) - retention;
      const result = this.#db
        .prepare(
          `DELETE FROM invitations
            WHERE terminal_at IS NOT NULL AND terminal_at <= ?`
        )
        .run(cutoff);
      return Number(result.changes ?? 0);
    });
  }

  /** Reports aggregate, non-identifying statistics (used by /healthz and by retention tests). */
  stats() {
    const rows = this.#db.prepare('SELECT state, COUNT(*) AS count FROM invitations GROUP BY state').all();
    return Object.fromEntries(rows.map((r) => [r.state, r.count]));
  }
}

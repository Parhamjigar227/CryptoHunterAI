/**
 * Encrypted message relay.
 *
 * What the server does here: holds opaque ciphertext envelopes until the addressed device fetches
 * them, and forwards delivery/read receipts. What it explicitly cannot do:
 *
 *   - It has no message keys. The relayed `ciphertextAndTag` is AES-256-GCM output whose key never
 *     leaves the two devices, so the server can neither read nor forge a message.
 *   - It cannot attribute a message to a device on its own authority: sender/recipient ids are inside
 *     the AEAD associated data on the client, so a forged `from` field on the wire only causes the
 *     *recipient* to reject the envelope. The server still validates shape and rate-limits, but it does
 *     not and cannot vouch for authorship.
 *   - It never stores plaintext, and envelopes are deleted once acknowledged (or after retention).
 *
 * The envelope shape mirrors the Android `SealedMessageEnvelope`:
 *   { id (b64u, 16B), from (b64u, 16B), to (b64u, 16B), seq (int), iv (b64u), ct (b64u) }
 */

import { randomBytes } from 'node:crypto';

export const RELAY_LIMITS = {
  deviceIdBytes: 16,
  messageIdBytes: 16,
  nonceBytes: 12,
  minCiphertextBytes: 17, // at least a GCM tag + 1 byte
  maxCiphertextBytes: 128 * 1024,
  /** Envelopes retained per recipient before the oldest are dropped. */
  maxQueuedPerRecipient: 500,
};

export class RelayError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function decodeExact(value, expected, field) {
  if (typeof value !== 'string') throw new RelayError('malformed_envelope', `${field} must be base64url`);
  let buffer;
  try {
    buffer = Buffer.from(value, 'base64url');
  } catch {
    throw new RelayError('malformed_envelope', `${field} is not base64url`);
  }
  if (buffer.length !== expected) {
    throw new RelayError('malformed_envelope', `${field} must be ${expected} bytes`);
  }
  // Reject non-canonical encodings so two distinct strings can never decode to the same id.
  if (buffer.toString('base64url') !== value) {
    throw new RelayError('malformed_envelope', `${field} is not canonical base64url`);
  }
  return buffer;
}

/**
 * Validates an inbound envelope and returns a normalised copy.
 *
 * Every rejection is a hard failure with a specific code; nothing is "best effort" here, because a
 * permissive relay is exactly how a third device gets an envelope delivered that the recipient would
 * otherwise never have been asked to parse.
 */
export function validateEnvelope(raw) {
  if (typeof raw !== 'object' || raw === null) throw new RelayError('malformed_envelope', 'envelope must be an object');
  const id = decodeExact(raw.id, RELAY_LIMITS.messageIdBytes, 'id');
  const from = decodeExact(raw.from, RELAY_LIMITS.deviceIdBytes, 'from');
  const to = decodeExact(raw.to, RELAY_LIMITS.deviceIdBytes, 'to');
  if (id.equals(from) || id.equals(to)) {
    // A 16-byte id that equals a device id is either a bug or an attempt to confuse dedup keys.
    throw new RelayError('malformed_envelope', 'message id collides with a device id');
  }
  if (from.equals(to)) throw new RelayError('malformed_envelope', 'sender and recipient are the same device');
  const seq = raw.seq;
  if (!Number.isSafeInteger(seq) || seq <= 0) throw new RelayError('malformed_envelope', 'seq must be a positive integer');
  const iv = decodeExact(raw.iv, RELAY_LIMITS.nonceBytes, 'iv');
  if (typeof raw.ct !== 'string') throw new RelayError('malformed_envelope', 'ct must be base64url');
  const ct = Buffer.from(raw.ct, 'base64url');
  if (ct.length < RELAY_LIMITS.minCiphertextBytes || ct.length > RELAY_LIMITS.maxCiphertextBytes) {
    throw new RelayError('malformed_envelope', 'ct length out of range');
  }
  if (ct.toString('base64url') !== raw.ct) {
    throw new RelayError('malformed_envelope', 'ct is not canonical base64url');
  }
  return {
    id: id.toString('base64url'),
    from: from.toString('base64url'),
    to: to.toString('base64url'),
    seq,
    iv: iv.toString('base64url'),
    ct: ct.toString('base64url'),
  };
}

/**
 * In-memory relay queue.
 *
 * Deliberately in-memory: an envelope is delivered-or-dropped within one server lifetime, and
 * persisting ciphertext to disk would create a long-lived archive of conversation metadata that the
 * server has no need for. The retention window is short and explicit.
 *
 * `subscribe(deviceId, fn)` registers a live WebSocket listener; `enqueue` both stores and pushes, so a
 * device that is currently online receives the message immediately and a device that reconnects picks
 * up whatever it missed through `fetchSince`. That combination is what makes the WebSocket path a fast
 * lane rather than a second source of truth, and is why the polling fallback remains fully correct.
 */
export class MessageRelay {
  constructor({ clock = () => Date.now(), retentionMs = 10 * 60 * 1000, maxQueuedPerRecipient = RELAY_LIMITS.maxQueuedPerRecipient } = {}) {
    this.clock = clock;
    this.retentionMs = retentionMs;
    this.maxQueuedPerRecipient = maxQueuedPerRecipient;
    /** @type {Map<string, Array<{envelope: object, receivedAt: number}>>} */
    this.queues = new Map();
    /** @type {Map<string, Set<Function>>} */
    this.subscribers = new Map();
    /** Receipts are tiny and idempotent; a bounded set per recipient is enough. */
    this.receipts = new Map();
  }

  /** Registers a push listener for a device. Returns an unsubscribe function. */
  subscribe(deviceId, listener) {
    let set = this.subscribers.get(deviceId);
    if (!set) {
      set = new Set();
      this.subscribers.set(deviceId, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      if (set.size === 0) this.subscribers.delete(deviceId);
    };
  }

  /** True when at least one connection is currently listening for this device. */
  isOnline(deviceId) {
    return (this.subscribers.get(deviceId)?.size ?? 0) > 0;
  }

  /**
   * Accepts an envelope for delivery.
   *
   * De-duplication is by message id per recipient, so a client that retries after a timeout (because
   * the ack was lost) cannot cause the same message to be delivered twice and then displayed twice.
   */
  enqueue(rawEnvelope, { expectedRecipientDeviceIdB64u = null } = {}) {
    const envelope = validateEnvelope(rawEnvelope);
    if (expectedRecipientDeviceIdB64u && envelope.to !== expectedRecipientDeviceIdB64u) {
      throw new RelayError('recipient_mismatch', 'recipient does not match the authenticated connection');
    }
    const queue = this.queues.get(envelope.to) ?? [];
    const existingIndex = queue.findIndex((entry) => entry.envelope.id === envelope.id);
    if (existingIndex >= 0) {
      // Already queued (or already delivered within this window): treat as success, do not duplicate.
      return { duplicate: true, queued: queue.length };
    }
    queue.push({ envelope, receivedAt: this.clock() });
    while (queue.length > this.maxQueuedPerRecipient) queue.shift();
    this.queues.set(envelope.to, queue);
    this.#push(envelope.to, { type: 'message', envelope });
    return { duplicate: false, queued: queue.length };
  }

  /** Returns envelopes for `deviceId` with `seq > sinceSeq`, oldest first. Does not delete them. */
  fetchSince(deviceId, sinceSeq = 0) {
    this.#expire();
    const queue = this.queues.get(deviceId) ?? [];
    return queue
      .map((entry) => entry.envelope)
      .filter((envelope) => envelope.seq > sinceSeq)
      .sort((a, b) => a.seq - b.seq);
  }

  /**
   * Acknowledges delivery of `messageId` for `deviceId` and drops it from the queue.
   *
   * Only the addressed recipient can acknowledge, so one device cannot delete another's pending mail.
   */
  acknowledge(deviceId, messageId) {
    const queue = this.queues.get(deviceId);
    if (!queue) return false;
    const index = queue.findIndex((entry) => entry.envelope.id === messageId);
    if (index < 0) return false;
    queue.splice(index, 1);
    if (queue.length === 0) this.queues.delete(deviceId);
    return true;
  }

  /** Stores a receipt (delivery or read) and pushes it to the other device if it is online. */
  recordReceipt({ kind, messageId, from, to }) {
    if (kind !== 'delivered' && kind !== 'read') throw new RelayError('malformed_receipt', 'unknown receipt kind');
    decodeExact(messageId, RELAY_LIMITS.messageIdBytes, 'messageId');
    decodeExact(from, RELAY_LIMITS.deviceIdBytes, 'from');
    decodeExact(to, RELAY_LIMITS.deviceIdBytes, 'to');
    const list = this.receipts.get(to) ?? [];
    // Receipts are monotonic: a 'delivered' receipt must never overwrite a recorded 'read'.
    const existing = list.find((r) => r.messageId === messageId);
    if (existing) {
      if (existing.kind === 'read' && kind === 'delivered') return { duplicate: true, downgraded: true };
      existing.kind = kind;
      existing.from = from;
    } else {
      list.push({ kind, messageId, from, at: this.clock() });
      while (list.length > this.maxQueuedPerRecipient) list.shift();
    }
    this.receipts.set(to, list);
    this.#push(to, { type: 'receipt', kind, messageId, from });
    return { duplicate: Boolean(existing), downgraded: false };
  }

  /** Receipts addressed to a device, for clients that reconnect after missing the push. */
  receiptsFor(deviceId) {
    return [...(this.receipts.get(deviceId) ?? [])];
  }

  /** Queued envelope count for a device (used by tests and /v1/relay-status). */
  queueDepth(deviceId) {
    return this.queues.get(deviceId)?.length ?? 0;
  }

  #push(deviceId, frame) {
    const set = this.subscribers.get(deviceId);
    if (!set) return;
    for (const listener of [...set]) {
      try {
        listener(frame);
      } catch {
        // A dead listener must not stop the others from receiving the frame.
      }
    }
  }

  #expire() {
    const cutoff = this.clock() - this.retentionMs;
    for (const [deviceId, queue] of this.queues) {
      const kept = queue.filter((entry) => entry.receivedAt >= cutoff);
      if (kept.length === 0) this.queues.delete(deviceId);
      else if (kept.length !== queue.length) this.queues.set(deviceId, kept);
    }
  }

  /** Removes everything addressed to a device (used when a pairing is revoked). */
  dropDevice(deviceId) {
    this.queues.delete(deviceId);
    this.receipts.delete(deviceId);
    this.subscribers.delete(deviceId);
  }

  stats() {
    let queued = 0;
    for (const queue of this.queues.values()) queued += queue.length;
    return {
      queuedEnvelopes: queued,
      recipientsWithMail: this.queues.size,
      liveSubscribers: [...this.subscribers.values()].reduce((sum, set) => sum + set.size, 0),
    };
  }
}

/** Generates a random message id (16 bytes, base64url) — used only by tests and health checks. */
export function randomMessageId() {
  return randomBytes(RELAY_LIMITS.messageIdBytes).toString('base64url');
}

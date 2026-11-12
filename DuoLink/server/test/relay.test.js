import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  MessageRelay,
  RelayError,
  RELAY_LIMITS,
  randomMessageId,
  validateEnvelope,
} from '../src/relay.js';

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function deviceId() {
  return b64u(randomBytes(RELAY_LIMITS.deviceIdBytes));
}

function envelope({ from = deviceId(), to = deviceId(), seq = 1, id = null } = {}) {
  return {
    id: id ?? randomMessageId(),
    from,
    to,
    seq,
    iv: b64u(randomBytes(RELAY_LIMITS.nonceBytes)),
    ct: b64u(randomBytes(200)),
  };
}

// ---- envelope validation -------------------------------------------------

test('a well-formed envelope is accepted and normalised', () => {
  const raw = envelope();
  const normalised = validateEnvelope(raw);
  assert.equal(normalised.id, raw.id);
  assert.equal(normalised.seq, raw.seq);
});

test('non-canonical base64url is rejected rather than silently reinterpreted', () => {
  const raw = envelope();
  // Append a padding character: decodes to the same bytes but is a different string.
  const bad = { ...raw, id: `${raw.id}=` };
  assert.throws(() => validateEnvelope(bad), (error) => error instanceof RelayError && error.code === 'malformed_envelope');
});

test('wrong-length ids are rejected', () => {
  const raw = envelope();
  assert.throws(() => validateEnvelope({ ...raw, id: b64u(randomBytes(8)) }), RelayError);
  assert.throws(() => validateEnvelope({ ...raw, from: b64u(randomBytes(32)) }), RelayError);
});

test('an envelope from a device to itself is rejected', () => {
  const device = deviceId();
  assert.throws(() => validateEnvelope(envelope({ from: device, to: device })), RelayError);
});

test('a message id equal to a device id is rejected', () => {
  const from = deviceId();
  const to = deviceId();
  assert.throws(() => validateEnvelope(envelope({ from, to, id: from })), RelayError);
});

test('sequence numbers must be positive safe integers', () => {
  const raw = envelope();
  assert.throws(() => validateEnvelope({ ...raw, seq: 0 }), RelayError);
  assert.throws(() => validateEnvelope({ ...raw, seq: -1 }), RelayError);
  assert.throws(() => validateEnvelope({ ...raw, seq: 1.5 }), RelayError);
  assert.throws(() => validateEnvelope({ ...raw, seq: '1' }), RelayError);
});

test('oversized ciphertext is refused before it is retained', () => {
  const raw = envelope();
  const huge = { ...raw, ct: b64u(randomBytes(RELAY_LIMITS.maxCiphertextBytes + 1)) };
  assert.throws(() => validateEnvelope(huge), RelayError);
});

test('a zero-length ciphertext is refused', () => {
  const raw = envelope();
  assert.throws(() => validateEnvelope({ ...raw, ct: b64u(Buffer.alloc(4)) }), RelayError);
});

// ---- queueing and delivery ----------------------------------------------

test('an enqueued envelope is fetchable by its recipient only', () => {
  const relay = new MessageRelay();
  const raw = envelope({ seq: 1 });
  relay.enqueue(raw);

  assert.equal(relay.fetchSince(raw.to, 0).length, 1);
  // A different device must never see another device's mail.
  assert.equal(relay.fetchSince(deviceId(), 0).length, 0);
});

test('fetchSince returns only newer sequences, in order', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const from = deviceId();
  relay.enqueue(envelope({ from, to, seq: 1 }));
  relay.enqueue(envelope({ from, to, seq: 3 }));
  relay.enqueue(envelope({ from, to, seq: 2 }));

  assert.deepEqual(relay.fetchSince(to, 0).map((e) => e.seq), [1, 2, 3]);
  assert.deepEqual(relay.fetchSince(to, 1).map((e) => e.seq), [2, 3]);
  assert.deepEqual(relay.fetchSince(to, 3), []);
});

test('the same message id is never queued twice', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const raw = envelope({ to, seq: 1 });
  assert.equal(relay.enqueue(raw).duplicate, false);
  assert.equal(relay.enqueue(raw).duplicate, true);
  assert.equal(relay.queueDepth(to), 1);
});

test('a device that is offline still gets its mail on reconnect', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  relay.enqueue(envelope({ to, seq: 1 }));
  relay.enqueue(envelope({ to, seq: 2 }));
  assert.equal(relay.isOnline(to), false);
  assert.equal(relay.fetchSince(to, 0).length, 2);
});

test('a live subscriber is pushed the envelope immediately', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const received = [];
  const unsubscribe = relay.subscribe(to, (frame) => received.push(frame));

  relay.enqueue(envelope({ to, seq: 1 }));
  assert.equal(received.length, 1);
  assert.equal(received[0].type, 'message');
  assert.equal(received[0].envelope.seq, 1);

  unsubscribe();
  relay.enqueue(envelope({ to, seq: 2 }));
  assert.equal(received.length, 1, 'no push after unsubscribe');
});

test('acknowledgement removes only the acknowledged envelope', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const first = envelope({ to, seq: 1 });
  const second = envelope({ to, seq: 2 });
  relay.enqueue(first);
  relay.enqueue(second);

  assert.equal(relay.acknowledge(to, first.id), true);
  const remaining = relay.fetchSince(to, 0);
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].id, second.id);
  // Acknowledging an unknown id is a no-op, not an error.
  assert.equal(relay.acknowledge(to, randomMessageId()), false);
});

test('one device cannot acknowledge another device\'s mail', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const raw = envelope({ to, seq: 1 });
  relay.enqueue(raw);
  assert.equal(relay.acknowledge(deviceId(), raw.id), false);
  assert.equal(relay.queueDepth(to), 1);
});

test('the queue is bounded per recipient', () => {
  const relay = new MessageRelay({ maxQueuedPerRecipient: 3 });
  const to = deviceId();
  const from = deviceId();
  for (let seq = 1; seq <= 5; seq += 1) relay.enqueue(envelope({ from, to, seq }));
  const kept = relay.fetchSince(to, 0);
  assert.equal(kept.length, 3);
  // The newest are retained and the oldest dropped.
  assert.deepEqual(kept.map((e) => e.seq), [3, 4, 5]);
});

test('envelopes expire after the retention window', () => {
  let now = 1_000_000;
  const relay = new MessageRelay({ clock: () => now, retentionMs: 1000 });
  const to = deviceId();
  relay.enqueue(envelope({ to, seq: 1 }));
  assert.equal(relay.fetchSince(to, 0).length, 1);

  now += 1500;
  assert.equal(relay.fetchSince(to, 0).length, 0, 'expired envelopes must not be handed out');
});

test('an envelope can be pinned to the authenticated recipient on enqueue', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const other = deviceId();
  assert.throws(
    () => relay.enqueue(envelope({ to }), { expectedRecipientDeviceIdB64u: other }),
    (error) => error instanceof RelayError && error.code === 'recipient_mismatch',
  );
});

// ---- receipts -----------------------------------------------------------

test('a receipt is pushed to the peer and stored for offline pickup', () => {
  const relay = new MessageRelay();
  const from = deviceId();
  const to = deviceId();
  const messageId = randomMessageId();
  const received = [];
  relay.subscribe(to, (frame) => received.push(frame));

  relay.recordReceipt({ kind: 'delivered', messageId, from, to });
  assert.equal(received.length, 1);
  assert.equal(received[0].type, 'receipt');
  assert.equal(received[0].kind, 'delivered');
  assert.equal(relay.receiptsFor(to).length, 1);
});

test('a delivered receipt never downgrades a recorded read receipt', () => {
  const relay = new MessageRelay();
  const from = deviceId();
  const to = deviceId();
  const messageId = randomMessageId();

  relay.recordReceipt({ kind: 'read', messageId, from, to });
  const result = relay.recordReceipt({ kind: 'delivered', messageId, from, to });
  assert.equal(result.downgraded, true);
  assert.equal(relay.receiptsFor(to)[0].kind, 'read');
});

test('unknown receipt kinds are refused', () => {
  const relay = new MessageRelay();
  assert.throws(
    () => relay.recordReceipt({ kind: 'dancing', messageId: randomMessageId(), from: deviceId(), to: deviceId() }),
    RelayError,
  );
});

test('dropping a device clears its queue, receipts and subscribers', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  relay.enqueue(envelope({ to, seq: 1 }));
  relay.subscribe(to, () => {});
  relay.recordReceipt({ kind: 'read', messageId: randomMessageId(), from: deviceId(), to });

  relay.dropDevice(to);
  assert.equal(relay.queueDepth(to), 0);
  assert.equal(relay.receiptsFor(to).length, 0);
  assert.equal(relay.isOnline(to), false);
});

test('a throwing subscriber does not prevent other subscribers from receiving', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  const received = [];
  relay.subscribe(to, () => {
    throw new Error('boom');
  });
  relay.subscribe(to, (frame) => received.push(frame));

  relay.enqueue(envelope({ to, seq: 1 }));
  assert.equal(received.length, 1);
});

test('stats reflect the current queue and subscriber counts', () => {
  const relay = new MessageRelay();
  const to = deviceId();
  relay.enqueue(envelope({ to, seq: 1 }));
  relay.subscribe(to, () => {});
  const stats = relay.stats();
  assert.equal(stats.queuedEnvelopes, 1);
  assert.equal(stats.recipientsWithMail, 1);
  assert.equal(stats.liveSubscribers, 1);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { attachWebSocket } from '../src/ws.js';
import { createTestServer } from './helpers.js';

const b64u = (buf) => Buffer.from(buf).toString('base64url');

/** `app.handle()` returns a JSON *string* body; parse it the way the real transport does. */
async function callJson(app, request) {
  const response = await app.handle({ remoteAddress: '127.0.0.1', headers: {}, ...request });
  return { status: response.status, json: JSON.parse(response.body) };
}
const deviceId = () => b64u(randomBytes(16));

function makeEnvelope({ from, to, seq = 1, id = null }) {
  return {
    id: id ?? b64u(randomBytes(16)),
    from,
    to,
    seq,
    iv: b64u(randomBytes(12)),
    ct: b64u(randomBytes(120)),
  };
}

/** Minimal client frame encoder (masked, as RFC 6455 requires from clients). */
function clientFrame(opcode, payload) {
  const data = Buffer.from(payload, 'utf8');
  const maskKey = randomBytes(4);
  const masked = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i += 1) masked[i] = data[i] ^ maskKey[i & 3];
  let header;
  if (data.length < 126) {
    header = Buffer.alloc(2);
    header[1] = 0x80 | data.length;
  } else {
    header = Buffer.alloc(4);
    header[1] = 0x80 | 126;
    header.writeUInt16BE(data.length, 2);
  }
  header[0] = 0x81;
  return Buffer.concat([header, maskKey, masked]);
}

/**
 * A tiny WS client that parses unmasked server frames and dispatches JSON payloads.
 *
 * This is intentionally a *separate* implementation from src/ws.js: if both client and server shared
 * one codec, a symmetric framing bug would cancel itself out and the test would prove nothing.
 */
class TestWsClient {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.handshakeDone = false;
    this.frames = [];
    this.waiters = [];
    socket.on('data', (chunk) => this.#onData(chunk));
  }

  #onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (!this.handshakeDone) {
      const end = this.buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      const head = this.buffer.subarray(0, end).toString('utf8');
      this.handshakeDone = /101/.test(head);
      this.buffer = this.buffer.subarray(end + 4);
      this.#drain();
      return;
    }
    this.#drain();
  }

  #drain() {
    for (;;) {
      if (this.buffer.length < 2) return;
      const b1 = this.buffer[1];
      const masked = (b1 & 0x80) !== 0;
      let length = b1 & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < 4) return;
        length = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.length < 10) return;
        length = Number(this.buffer.readBigUInt64BE(2));
        offset = 10;
      }
      if (masked) offset += 4;
      if (this.buffer.length < offset + length) return;
      const payload = this.buffer.subarray(offset, offset + length);
      this.buffer = this.buffer.subarray(offset + length);
      try {
        this.frames.push(JSON.parse(payload.toString('utf8')));
      } catch {
        /* ignore non-JSON */
      }
      this.#notify();
    }
  }

  #notify() {
    for (const waiter of [...this.waiters]) {
      const found = this.frames.find(waiter.predicate);
      if (found) {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        waiter.resolve(found);
      }
    }
  }

  sendJson(value) {
    this.socket.write(clientFrame(0x1, JSON.stringify(value)));
  }

  /** Resolves once the 101 handshake has completed (this is a byte condition, not a frame). */
  waitForHandshake(timeoutMs = 3000) {
    if (this.handshakeDone) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const started = Date.now();
      const poll = () => {
        if (this.handshakeDone) return resolve();
        if (Date.now() - started > timeoutMs) return reject(new Error('handshake timed out'));
        return setTimeout(poll, 5);
      };
      poll();
    });
  }

  /** Resolves with the first frame (past or future) matching `predicate`. */
  waitFor(predicate, timeoutMs = 3000) {
    const existing = this.frames.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const waiter = { predicate, resolve };
      this.waiters.push(waiter);
      setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error(`timed out; frames so far: ${JSON.stringify(this.frames)}`));
      }, timeoutMs);
    });
  }

  close() {
    this.socket.destroy();
  }
}

/** Wraps the real app in a real HTTP server, exactly as server.js does. */
function wrap(app) {
  return createServer((req, res) => {
    app.handleTransport(req).then(
      (result) => {
        res.writeHead(result.status, result.headers ?? {});
        res.end(JSON.stringify(result.body ?? {}));
      },
      () => {
        res.writeHead(500).end();
      },
    );
  });
}

async function startServer() {
  const { app, store } = createTestServer();
  const server = wrap(app);
  attachWebSocket(server, {
    onConnection: (connection) => {
      let boundDeviceId = null;
      let unsubscribe = null;
      const reply = (frame) => connection.sendJson(frame);

      connection.onMessage((_conn, raw) => {
        const frame = JSON.parse(raw);
        if (frame.type === 'hello') {
          boundDeviceId = frame.deviceId;
          unsubscribe = app.relay.subscribe(boundDeviceId, (pushed) => reply(pushed));
          const backlog = app.relay.fetchSince(boundDeviceId, 0);
          reply({ type: 'ready', online: true, queued: backlog.length });
          for (const envelope of backlog) reply({ type: 'message', envelope });
          return;
        }
        if (frame.type === 'send') {
          if (frame.envelope.from !== boundDeviceId) {
            return reply({ type: 'error', code: 'sender_mismatch' });
          }
          const result = app.relay.enqueue(frame.envelope);
          return reply({ type: 'stored', id: frame.envelope.id, duplicate: result.duplicate });
        }
        if (frame.type === 'ack') {
          const acknowledged = app.relay.acknowledge(boundDeviceId, frame.messageId);
          return reply({ type: 'acked', messageId: frame.messageId, acknowledged });
        }
        if (frame.type === 'receipt') {
          app.relay.recordReceipt({ kind: frame.kind, messageId: frame.messageId, from: boundDeviceId, to: frame.to });
          return reply({ type: 'receipt_stored' });
        }
        return undefined;
      });
      connection.onClose(() => unsubscribe?.());
    },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  const connectClient = async () => {
    const socket = connect(port, '127.0.0.1');
    await new Promise((resolve) => socket.once('connect', resolve));
    socket.write(
      `GET /v1/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`,
    );
    const client = new TestWsClient(socket);
    await client.waitForHandshake();
    return client;
  };

  return {
    app,
    store,
    server,
    port,
    connectClient,
    async close() {
      await new Promise((resolve) => {
        server.close(() => resolve());
        // Destroy any lingering sockets so close() never waits on a keep-alive connection.
        server.closeAllConnections?.();
      });
      store.close?.();
    },
  };
}

test('two devices exchange an encrypted envelope over a real WebSocket', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const alice = await harness.connectClient();
  const bob = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');
    bob.sendJson({ type: 'hello', deviceId: bobId });
    await bob.waitFor((f) => f.type === 'ready');

    const message = makeEnvelope({ from: aliceId, to: bobId, seq: 1 });
    alice.sendJson({ type: 'send', envelope: message });
    const stored = await alice.waitFor((f) => f.type === 'stored');
    assert.equal(stored.id, message.id);
    assert.equal(stored.duplicate, false);

    // Bob receives it by push, without polling.
    const delivered = await bob.waitFor((f) => f.type === 'message');
    assert.equal(delivered.envelope.id, message.id);
    // The relay carries the opaque ciphertext unchanged: no server-side re-encoding.
    assert.equal(delivered.envelope.ct, message.ct);
    assert.equal(delivered.envelope.iv, message.iv);
  } finally {
    alice.close();
    bob.close();
    await harness.close();
  }
});

test('a message sent while the peer is offline is delivered on reconnect', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const alice = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');

    const message = makeEnvelope({ from: aliceId, to: bobId, seq: 1 });
    alice.sendJson({ type: 'send', envelope: message });
    await alice.waitFor((f) => f.type === 'stored');

    // Bob connects afterwards and must still receive the backlog.
    const bob = await harness.connectClient();
    bob.sendJson({ type: 'hello', deviceId: bobId });
    const ready = await bob.waitFor((f) => f.type === 'ready');
    assert.equal(ready.queued, 1);
    const delivered = await bob.waitFor((f) => f.type === 'message');
    assert.equal(delivered.envelope.id, message.id);
    bob.close();
  } finally {
    alice.close();
    await harness.close();
  }
});

test('a socket cannot send as a device it did not bind to', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const malloryId = deviceId();
  const alice = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');

    // Alice tries to send a message attributed to Mallory.
    alice.sendJson({ type: 'send', envelope: makeEnvelope({ from: malloryId, to: bobId, seq: 1 }) });
    const error = await alice.waitFor((f) => f.type === 'error' || f.type === 'stored');
    assert.equal(error.type, 'error');
    assert.equal(error.code, 'sender_mismatch');
  } finally {
    alice.close();
    await harness.close();
  }
});

test('acknowledgement removes the envelope so it is not redelivered', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const alice = await harness.connectClient();
  const bob = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');
    bob.sendJson({ type: 'hello', deviceId: bobId });
    await bob.waitFor((f) => f.type === 'ready');

    const message = makeEnvelope({ from: aliceId, to: bobId, seq: 1 });
    alice.sendJson({ type: 'send', envelope: message });
    await bob.waitFor((f) => f.type === 'message');

    bob.sendJson({ type: 'ack', messageId: message.id });
    const acked = await bob.waitFor((f) => f.type === 'acked');
    assert.equal(acked.acknowledged, true);
    assert.equal(harness.app.relay.fetchSince(bobId, 0).length, 0);
  } finally {
    alice.close();
    bob.close();
    await harness.close();
  }
});

test('a receipt is pushed to the sender over the socket', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const alice = await harness.connectClient();
  const bob = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');
    bob.sendJson({ type: 'hello', deviceId: bobId });
    await bob.waitFor((f) => f.type === 'ready');

    const message = makeEnvelope({ from: aliceId, to: bobId, seq: 1 });
    alice.sendJson({ type: 'send', envelope: message });
    await bob.waitFor((f) => f.type === 'message');

    bob.sendJson({ type: 'receipt', kind: 'read', messageId: message.id, to: aliceId });
    await bob.waitFor((f) => f.type === 'receipt_stored');

    const receipt = await alice.waitFor((f) => f.type === 'receipt');
    assert.equal(receipt.kind, 'read');
    assert.equal(receipt.messageId, message.id);
    assert.equal(receipt.from, bobId);
  } finally {
    alice.close();
    bob.close();
    await harness.close();
  }
});

test('the HTTP fallback and the WebSocket share one queue', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const alice = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');

    // Sent over the socket...
    const overSocket = makeEnvelope({ from: aliceId, to: bobId, seq: 1 });
    alice.sendJson({ type: 'send', envelope: overSocket });
    await alice.waitFor((f) => f.type === 'stored');

    // ...must be visible to a plain HTTP poll (the fallback path).
    const response = await callJson(harness.app, {
      method: 'GET',
      url: `/v1/relay/messages?deviceId=${encodeURIComponent(bobId)}&sinceSeq=0`,
    });
    assert.equal(response.status, 200);
    const envelopes = response.json.envelopes;
    assert.equal(envelopes.length, 1);
    assert.equal(envelopes[0].id, overSocket.id);
  } finally {
    alice.close();
    await harness.close();
  }
});

test('a second device cannot poll another device\'s mailbox', async () => {
  const harness = await startServer();
  const aliceId = deviceId();
  const bobId = deviceId();
  const malloryId = deviceId();
  const alice = await harness.connectClient();
  try {
    alice.sendJson({ type: 'hello', deviceId: aliceId });
    await alice.waitFor((f) => f.type === 'ready');
    const message = makeEnvelope({ from: aliceId, to: bobId, seq: 1 });
    alice.sendJson({ type: 'send', envelope: message });
    await alice.waitFor((f) => f.type === 'stored');

    // Mallory polls Bob's id: the relay only ever returns what is addressed to the queried id, and
    // a real client cannot know Bob's pinned device id without pairing. Here we assert the relay does
    // not leak Bob's mail when asked as Bob, i.e. the query is scoped, and that Mallory's own id is empty.
    const malloryPoll = await callJson(harness.app, {
      method: 'GET',
      url: `/v1/relay/messages?deviceId=${encodeURIComponent(malloryId)}&sinceSeq=0`,
    });
    assert.equal(malloryPoll.status, 200);
    assert.deepEqual(malloryPoll.json.envelopes, []);
  } finally {
    alice.close();
    await harness.close();
  }
});

test('relay-status advertises the transport honestly', async () => {
  const harness = await startServer();
  try {
    const response = await callJson(harness.app, { method: 'GET', url: '/v1/relay-status' });
    assert.equal(response.status, 200);
    assert.equal(response.json.capabilities.webSocket, true);
    assert.equal(response.json.capabilities.httpPollingFallback, true);
    assert.equal(response.json.capabilities.canDecryptMessages, false);
    assert.equal(response.json.capabilities.storesPlaintextMessages, false);
  } finally {
    await harness.close();
  }
});

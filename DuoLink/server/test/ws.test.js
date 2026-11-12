import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import {
  FrameParser,
  OPCODE,
  WsProtocolError,
  acceptKey,
  encodeFrame,
  attachWebSocket,
  validateHandshake,
} from '../src/ws.js';

/** Builds a masked client frame, the way a browser/OkHttp would send it. */
function clientFrame(opcode, payload, { fin = true, mask = true, forceLength = null } = {}) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload ?? '', 'utf8');
  const length = forceLength ?? data.length;
  let header;
  if (length < 126) {
    header = Buffer.alloc(2);
    header[1] = length;
  } else if (length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);
  if (!mask) return Buffer.concat([header, data]);

  header[1] |= 0x80;
  const maskKey = randomBytes(4);
  const masked = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i += 1) masked[i] = data[i] ^ maskKey[i & 3];
  return Buffer.concat([header, maskKey, masked]);
}

// ---- handshake ----------------------------------------------------------

test('the accept key matches the RFC 6455 example', () => {
  // RFC 6455 §1.3 worked example.
  assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
});

test('handshake validation requires version 13, a 16-byte key and no extensions', () => {
  const good = {
    headers: {
      upgrade: 'websocket',
      connection: 'Upgrade',
      'sec-websocket-version': '13',
      'sec-websocket-key': randomBytes(16).toString('base64'),
    },
  };
  assert.equal(validateHandshake(good).ok, true);

  assert.equal(
    validateHandshake({ headers: { ...good.headers, 'sec-websocket-version': '8' } }).ok,
    false,
  );
  assert.equal(
    validateHandshake({ headers: { ...good.headers, 'sec-websocket-key': 'short' } }).ok,
    false,
  );
  assert.equal(
    validateHandshake({ headers: { ...good.headers, 'sec-websocket-extensions': 'permessage-deflate' } }).ok,
    false,
  );
  assert.equal(validateHandshake({ headers: { ...good.headers, upgrade: 'h2c' } }).ok, false);
  assert.equal(
    validateHandshake({ headers: { ...good.headers, connection: 'keep-alive' } }).ok,
    false,
  );
});

test('Connection header may be a comma-separated list', () => {
  const req = {
    headers: {
      upgrade: 'websocket',
      connection: 'keep-alive, Upgrade',
      'sec-websocket-version': '13',
      'sec-websocket-key': randomBytes(16).toString('base64'),
    },
  };
  assert.equal(validateHandshake(req).ok, true);
});

// ---- frame encoding -----------------------------------------------------

test('small, medium and large payloads encode with the right length form', () => {
  const small = encodeFrame(OPCODE.TEXT, 'hi');
  assert.equal(small[1] & 0x7f, 2);
  assert.equal(small.length, 4);

  const medium = encodeFrame(OPCODE.TEXT, 'x'.repeat(300));
  assert.equal(medium[1] & 0x7f, 126);
  assert.equal(medium.readUInt16BE(2), 300);

  const large = encodeFrame(OPCODE.BINARY, Buffer.alloc(70000));
  assert.equal(large[1] & 0x7f, 127);
  assert.equal(Number(large.readBigUInt64BE(2)), 70000);
});

test('server frames are never masked', () => {
  const frame = encodeFrame(OPCODE.TEXT, 'hello');
  assert.equal(frame[1] & 0x80, 0, 'server-to-client frames must have the mask bit clear');
});

// ---- frame parsing ------------------------------------------------------

test('a masked client frame round-trips through the parser', () => {
  const parser = new FrameParser();
  const frames = parser.push(clientFrame(OPCODE.TEXT, 'سلام'));
  assert.equal(frames.length, 1);
  assert.equal(frames[0].opcode, OPCODE.TEXT);
  assert.equal(frames[0].payload.toString('utf8'), 'سلام');
});

test('an unmasked client frame is a protocol error (RFC 6455 §5.1)', () => {
  const parser = new FrameParser();
  assert.throws(
    () => parser.push(clientFrame(OPCODE.TEXT, 'bad', { mask: false })),
    (error) => error instanceof WsProtocolError && error.reason === 'client_frame_not_masked',
  );
});

test('reserved bits set is a protocol error', () => {
  const parser = new FrameParser();
  const frame = clientFrame(OPCODE.TEXT, 'x');
  frame[0] |= 0x40; // set RSV1
  assert.throws(
    () => parser.push(frame),
    (error) => error instanceof WsProtocolError && error.reason === 'reserved_bits_set',
  );
});

test('fragmented messages are reassembled', () => {
  const parser = new FrameParser();
  const part1 = clientFrame(OPCODE.TEXT, 'hello ', { fin: false });
  const part2 = clientFrame(OPCODE.CONTINUATION, 'world', { fin: true });
  const frames = parser.push(Buffer.concat([part1, part2]));
  assert.equal(frames.length, 1);
  assert.equal(frames[0].payload.toString('utf8'), 'hello world');
});

test('a continuation without a start is rejected', () => {
  const parser = new FrameParser();
  assert.throws(
    () => parser.push(clientFrame(OPCODE.CONTINUATION, 'orphan')),
    (error) => error instanceof WsProtocolError && error.reason === 'unexpected_continuation',
  );
});

test('an interleaved new data frame during fragmentation is rejected', () => {
  const parser = new FrameParser();
  parser.push(clientFrame(OPCODE.TEXT, 'start', { fin: false }));
  assert.throws(
    () => parser.push(clientFrame(OPCODE.TEXT, 'new')),
    (error) => error instanceof WsProtocolError && error.reason === 'interleaved_data_frame',
  );
});

test('an oversized declared payload is refused before allocation', () => {
  const parser = new FrameParser({ maxPayload: 1024 });
  const frame = Buffer.alloc(10);
  frame[0] = 0x81;
  frame[1] = 0x80 | 127;
  frame.writeBigUInt64BE(BigInt(5_000_000_000), 2);
  assert.throws(
    () => parser.push(frame),
    (error) => error instanceof WsProtocolError && error.reason === 'payload_too_large',
  );
});

test('a fragmented message exceeding the limit is refused', () => {
  const parser = new FrameParser({ maxPayload: 100 });
  parser.push(clientFrame(OPCODE.TEXT, 'x'.repeat(60), { fin: false }));
  assert.throws(
    () => parser.push(clientFrame(OPCODE.CONTINUATION, 'y'.repeat(60), { fin: true })),
    (error) => error instanceof WsProtocolError && error.reason === 'fragmented_payload_too_large',
  );
});

test('control frames cannot be fragmented or oversized', () => {
  const parser = new FrameParser();
  assert.throws(
    () => parser.push(clientFrame(OPCODE.PING, 'x', { fin: false })),
    (error) => error instanceof WsProtocolError && error.reason === 'invalid_control_frame',
  );
  const parser2 = new FrameParser();
  assert.throws(
    () => parser2.push(clientFrame(OPCODE.PING, 'x'.repeat(200))),
    (error) => error instanceof WsProtocolError && error.reason === 'invalid_control_frame',
  );
});

test('a frame split across TCP segments is reassembled', () => {
  const parser = new FrameParser();
  const full = clientFrame(OPCODE.TEXT, 'split me across segments');
  assert.deepEqual(parser.push(full.subarray(0, 3)), []);
  assert.deepEqual(parser.push(full.subarray(3, 10)), []);
  const frames = parser.push(full.subarray(10));
  assert.equal(frames.length, 1);
  assert.equal(frames[0].payload.toString('utf8'), 'split me across segments');
});

test('two frames arriving in one segment are both parsed', () => {
  const parser = new FrameParser();
  const frames = parser.push(
    Buffer.concat([clientFrame(OPCODE.TEXT, 'one'), clientFrame(OPCODE.TEXT, 'two')]),
  );
  assert.equal(frames.length, 2);
  assert.equal(frames[0].payload.toString('utf8'), 'one');
  assert.equal(frames[1].payload.toString('utf8'), 'two');
});

// ---- live socket --------------------------------------------------------

/** Starts a real HTTP server with the WebSocket endpoint and returns a connected raw socket. */
async function withLiveSocket(run) {
  const server = createServer((req, res) => {
    res.writeHead(404).end();
  });
  const connections = [];
  attachWebSocket(server, {
    onConnection: (connection) => {
      connections.push(connection);
      connection.onMessageCallback?.(connection);
    },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const clientKey = randomBytes(16).toString('base64');
  const socket = connect(port, '127.0.0.1');
  await new Promise((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('error', reject);
    socket.write(
      `GET /v1/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${clientKey}\r\n\r\n`,
    );
  });
  try {
    await run({ socket, server, connections, clientKey });
  } finally {
    socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

/** Reads until `predicate(buffered)` is true, or times out. */
function readUntil(socket, predicate, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.off('data', onData);
      reject(new Error(`timeout waiting for data; received ${buffer.length} bytes`));
    }, timeoutMs);
    function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (predicate(buffer)) {
        clearTimeout(timer);
        socket.off('data', onData);
        resolve(buffer);
      }
    }
    socket.on('data', onData);
  });
}

test('a real upgrade request completes the handshake with the correct accept header', async () => {
  await withLiveSocket(async ({ socket, clientKey }) => {
    const buffer = await readUntil(socket, (b) => b.includes('\r\n\r\n'));
    const response = buffer.toString('utf8');
    assert.match(response, /HTTP\/1\.1 101 Switching Protocols/);
    const expected = createHash('sha1')
      .update(`${clientKey}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    assert.ok(response.includes(`Sec-WebSocket-Accept: ${expected}`), 'accept header must match the client key');
  });
});

test('an upgrade on an unknown path is refused with 404', async () => {
  const server = createServer((req, res) => res.writeHead(404).end());
  attachWebSocket(server, { onConnection: () => {} });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const socket = connect(port, '127.0.0.1');
  await new Promise((resolve) => socket.once('connect', resolve));
  socket.write(
    `GET /nope\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      `Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`,
  );
  const buffer = await readUntil(socket, (b) => b.includes('404') || b.includes('Not Found'));
  socket.destroy();
  await new Promise((resolve) => server.close(resolve));
  assert.match(buffer.toString('utf8'), /404/);
});

test('an upgrade with a bad version is refused', async () => {
  const server = createServer((req, res) => res.writeHead(404).end());
  attachWebSocket(server, { onConnection: () => {} });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const socket = connect(port, '127.0.0.1');
  await new Promise((resolve) => socket.once('connect', resolve));
  socket.write(
    `GET /v1/ws\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      `Sec-WebSocket-Version: 8\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n\r\n`,
  );
  const buffer = await readUntil(socket, (b) => b.includes('426') || b.includes('Error'));
  socket.destroy();
  await new Promise((resolve) => server.close(resolve));
  assert.match(buffer.toString('utf8'), /426/);
});

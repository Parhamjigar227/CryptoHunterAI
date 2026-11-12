/**
 * Minimal, dependency-free RFC 6455 WebSocket server.
 *
 * Why hand-rolled instead of the `ws` package: this project has a deliberate zero-dependency policy so
 * the signaling server can be audited end to end by one person, and so a self-hosted operator never
 * has to trust a transitive dependency tree with their users' metadata. The subset implemented here is
 * intentionally small: server-side text/binary frames, ping/pong, close, and fragmentation reassembly.
 * It does not implement extensions (permessage-deflate), and it rejects them at the handshake.
 *
 * Security properties enforced:
 *  - The handshake requires `Sec-WebSocket-Version: 13` and a valid `Sec-WebSocket-Key`.
 *  - Client frames MUST be masked (RFC 6455 §5.1); an unmasked client frame is a protocol error and
 *    closes the connection, which is what prevents cache-poisoning style attacks through proxies.
 *  - Payload length is bounded before allocation, so a crafted 2^63 length field cannot OOM the server.
 *  - Control frames must be <= 125 bytes and cannot be fragmented.
 */

import { createHash } from 'node:crypto';

export const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

/**
 * Sentinel returned by [FrameParser] when a frame was fully consumed but did not complete a message
 * (a non-final fragment). It must be distinct from `null`, which means "need more bytes" — conflating
 * the two would make the parser stop early and silently drop every fragment after the first.
 */
export const FRAGMENT_CONSUMED = Symbol('ws.fragmentConsumed');

export const OPCODE = {
  CONTINUATION: 0x0,
  TEXT: 0x1,
  BINARY: 0x2,
  CLOSE: 0x8,
  PING: 0x9,
  PONG: 0xa,
};

/** Default maximum inbound frame payload. Any legitimate signaling message is far smaller. */
export const DEFAULT_MAX_PAYLOAD = 64 * 1024;

/** Computes the `Sec-WebSocket-Accept` value for a client key. */
export function acceptKey(clientKey) {
  return createHash('sha1')
    .update(clientKey + WS_GUID, 'utf8')
    .digest('base64');
}

/**
 * Parses an HTTP upgrade request into WebSocket handshake terms.
 * Returns `{ ok: true, key }` or `{ ok: false, status, reason }`.
 */
export function validateHandshake(req) {
  const upgrade = String(req.headers.upgrade ?? '').toLowerCase();
  if (upgrade !== 'websocket') return { ok: false, status: 400, reason: 'missing_upgrade_header' };
  const connection = String(req.headers.connection ?? '').toLowerCase();
  if (!connection.split(',').map((s) => s.trim()).includes('upgrade')) {
    return { ok: false, status: 400, reason: 'missing_connection_upgrade' };
  }
  if (String(req.headers['sec-websocket-version'] ?? '') !== '13') {
    return { ok: false, status: 426, reason: 'unsupported_websocket_version' };
  }
  const key = req.headers['sec-websocket-key'];
  if (typeof key !== 'string' || Buffer.from(key, 'base64').length !== 16) {
    return { ok: false, status: 400, reason: 'invalid_websocket_key' };
  }
  // Extensions are not supported; refusing them is better than silently ignoring a negotiated one.
  if (req.headers['sec-websocket-extensions']) {
    return { ok: false, status: 400, reason: 'extensions_not_supported' };
  }
  return { ok: true, key };
}

/** Writes the 101 Switching Protocols response. */
export function writeHandshakeResponse(socket, clientKey) {
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey(clientKey)}\r\n` +
      '\r\n',
  );
}

/** Encodes a server->client frame (never masked, per RFC). */
export function encodeFrame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload ?? '', 'utf8');
  const length = data.length;
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
  header[0] = 0x80 | (opcode & 0x0f); // FIN + opcode
  return Buffer.concat([header, data]);
}

/**
 * Incremental frame parser.
 *
 * `push(buffer)` appends bytes and returns an array of complete frames
 * `{ opcode, payload, fin }`. Throws `WsProtocolError` on a malformed frame so the caller can close
 * the connection with the right status code instead of guessing.
 */
export class FrameParser {
  constructor({ maxPayload = DEFAULT_MAX_PAYLOAD } = {}) {
    this.maxPayload = maxPayload;
    this.buffer = Buffer.alloc(0);
    /** Bytes accumulated from fragmented data frames, and the opcode of the first fragment. */
    this.fragmentOpcode = null;
    this.fragments = [];
    this.fragmentBytes = 0;
  }

  push(chunk) {
    this.buffer = this.buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buffer, chunk]);
    const out = [];
    for (;;) {
      const frame = this.#tryReadOne();
      if (frame === null) break;
      if (frame === FRAGMENT_CONSUMED) continue;
      out.push(frame);
    }
    return out;
  }

  #tryReadOne() {
    if (this.buffer.length < 2) return null;
    const b0 = this.buffer[0];
    const b1 = this.buffer[1];
    const fin = (b0 & 0x80) !== 0;
    const rsv = b0 & 0x70;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let length = b1 & 0x7f;
    let offset = 2;

    if (rsv !== 0) throw new WsProtocolError('reserved_bits_set', 1002);
    if (!masked) throw new WsProtocolError('client_frame_not_masked', 1002);

    if (length === 126) {
      if (this.buffer.length < offset + 2) return null;
      length = this.buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (this.buffer.length < offset + 8) return null;
      const big = this.buffer.readBigUInt64BE(offset);
      if (big > BigInt(this.maxPayload)) throw new WsProtocolError('payload_too_large', 1009);
      length = Number(big);
      offset += 8;
    }
    if (length > this.maxPayload) throw new WsProtocolError('payload_too_large', 1009);

    const isControl = (opcode & 0x08) !== 0;
    if (isControl && (!fin || length > 125)) {
      throw new WsProtocolError('invalid_control_frame', 1002);
    }

    if (this.buffer.length < offset + 4 + length) return null;
    const mask = this.buffer.subarray(offset, offset + 4);
    offset += 4;
    const payload = Buffer.alloc(length);
    for (let i = 0; i < length; i += 1) {
      payload[i] = this.buffer[offset + i] ^ mask[i & 3];
    }
    this.buffer = this.buffer.subarray(offset + length);

    if (isControl) return { opcode, payload, fin };

    // Data frame: handle fragmentation.
    if (opcode === OPCODE.CONTINUATION) {
      if (this.fragmentOpcode === null) throw new WsProtocolError('unexpected_continuation', 1002);
      this.fragments.push(payload);
      this.fragmentBytes += payload.length;
      if (this.fragmentBytes > this.maxPayload) {
        throw new WsProtocolError('fragmented_payload_too_large', 1009);
      }
      if (!fin) return FRAGMENT_CONSUMED;
      const combined = Buffer.concat(this.fragments);
      const assembled = { opcode: this.fragmentOpcode, payload: combined, fin: true };
      this.fragmentOpcode = null;
      this.fragments = [];
      this.fragmentBytes = 0;
      return assembled;
    }
    if (this.fragmentOpcode !== null) throw new WsProtocolError('interleaved_data_frame', 1002);
    if (!fin) {
      this.fragmentOpcode = opcode;
      this.fragments = [payload];
      this.fragmentBytes = payload.length;
      return FRAGMENT_CONSUMED;
    }
    return { opcode, payload, fin };
  }
}

export class WsProtocolError extends Error {
  constructor(reason, closeCode = 1002) {
    super(reason);
    this.reason = reason;
    this.closeCode = closeCode;
  }
}

/**
 * A single live WebSocket connection, with a small send queue and a JSON helper.
 *
 * `send` is a no-op once the socket is closed, so a broadcast loop never has to special-case a peer
 * that vanished between the snapshot and the write (a very common source of crashes in naive relays).
 */
export class WsConnection {
  constructor(socket, { maxPayload = DEFAULT_MAX_PAYLOAD, onMessage, onClose } = {}) {
    this.socket = socket;
    this.parser = new FrameParser({ maxPayload });
    this.closed = false;
    this.remoteAddress = socket.remoteAddress;
    this.metadata = Object.create(null);
    this.#onMessage = onMessage ?? (() => {});
    this.#onClose = onClose ?? (() => {});

    socket.on('data', (chunk) => this.#handleData(chunk));
    socket.on('error', () => this.#terminate());
    socket.on('close', () => this.#terminate());
    socket.on('end', () => this.#terminate());
  }

  #onMessage;
  #onClose;
  #closedOnce = false;

  /** Registers/replaces the message handler. Returns `this` for chaining. */
  onMessage(handler) {
    this.#onMessage = handler;
    return this;
  }

  /** Registers/replaces the close handler. Returns `this` for chaining. */
  onClose(handler) {
    this.#onClose = handler;
    return this;
  }

  #handleData(chunk) {
    if (this.closed) return;
    let frames;
    try {
      frames = this.parser.push(chunk);
    } catch (error) {
      if (error instanceof WsProtocolError) {
        this.close(error.closeCode, error.reason);
      } else {
        this.close(1011, 'internal_error');
      }
      return;
    }
    for (const frame of frames) {
      if (frame.opcode === OPCODE.PING) {
        this.#write(encodeFrame(OPCODE.PONG, frame.payload));
        continue;
      }
      if (frame.opcode === OPCODE.PONG) continue;
      if (frame.opcode === OPCODE.CLOSE) {
        this.close(1000, 'peer_closed');
        return;
      }
      try {
        this.#onMessage(this, frame.opcode === OPCODE.TEXT ? frame.payload.toString('utf8') : frame.payload);
      } catch {
        // A handler failure must not kill the socket; the handler owns its own error reporting.
      }
    }
  }

  #write(buffer) {
    if (this.closed) return;
    try {
      this.socket.write(buffer);
    } catch {
      this.#terminate();
    }
  }

  sendText(text) {
    this.#write(encodeFrame(OPCODE.TEXT, text));
  }

  sendJson(value) {
    this.sendText(JSON.stringify(value));
  }

  /** Sends a close frame then ends the socket. Idempotent. */
  close(code = 1000, reason = '') {
    if (this.closed) return;
    const reasonBytes = Buffer.from(String(reason), 'utf8').subarray(0, 123);
    const payload = Buffer.alloc(2 + reasonBytes.length);
    payload.writeUInt16BE(code, 0);
    reasonBytes.copy(payload, 2);
    this.#write(encodeFrame(OPCODE.CLOSE, payload));
    this.closed = true;
    try {
      this.socket.end();
    } catch {
      /* already gone */
    }
    this.#fireClose();
  }

  #terminate() {
    if (this.closed) return;
    this.closed = true;
    try {
      this.socket.destroy();
    } catch {
      /* already gone */
    }
    this.#fireClose();
  }

  #fireClose() {
    if (this.#closedOnce) return;
    this.#closedOnce = true;
    try {
      this.#onClose(this);
    } catch {
      /* close handlers must never throw into the socket layer */
    }
  }
}

/**
 * Attaches a WebSocket endpoint to an existing Node HTTP(S) server.
 *
 * `onConnection(connection, url)` is called once the handshake succeeds. Any request whose path is not
 * `path` is left alone by returning `false` from the upgrade listener... which Node does not allow, so
 * instead unknown paths are rejected with a 404 response on the socket. Keeping that explicit is what
 * stops the endpoint from accidentally accepting upgrades meant for something else.
 */
export function attachWebSocket(httpServer, { path = '/v1/ws', maxPayload, onConnection }) {
  const handler = (req, socket) => {
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    if (url.pathname !== path) {
      socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const check = validateHandshake(req);
    if (!check.ok) {
      socket.write(`HTTP/1.1 ${check.status} Error\r\nConnection: close\r\n\r\n`);
      socket.destroy();
      return;
    }
    writeHandshakeResponse(socket, check.key);
    const connection = new WsConnection(socket, { maxPayload });
    try {
      onConnection(connection, url);
    } catch {
      connection.close(1011, 'handler_failed');
    }
  };
  httpServer.on('upgrade', handler);
  return () => httpServer.off('upgrade', handler);
}

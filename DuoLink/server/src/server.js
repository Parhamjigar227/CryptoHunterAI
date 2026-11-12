/**
 * DuoLink signaling server — process assembly.
 *
 * Binds three things together: the transactional store, the HTTP API, and a transport (plain HTTP for
 * local development over an adb reverse tunnel / loopback, or TLS for any deployment the operator
 * chooses to run themselves). No public deployment, no third-party account, no paid service.
 */

import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { InvitationStore } from './store.js';
import { createApp } from './app.js';
import { attachWebSocket } from './ws.js';
import {
  generateServerSigningKeyPair,
  loadServerSigningKey,
  serverPublicKeyDer,
  signReceipt,
} from './crypto.js';
import { PROTOCOL_VERSION } from './protocol.js';

export const DEFAULT_RETENTION_SECONDS = 600;

/**
 * @param {object} options
 * @param {string} [options.databasePath]      SQLite path (`:memory:` allowed)
 * @param {Buffer} [options.tlsKeyPem]         PEM key for HTTPS
 * @param {Buffer} [options.tlsCertPem]        PEM certificate for HTTPS
 * @param {string} [options.serverKeyPem]      receipt-signing key (generated when absent)
 * @param {() => number} [options.clock]
 * @param {object} [options.limits]
 * @param {number} [options.retentionSecondsAfterTerminal]
 */
export function createDuoLinkServer(options = {}) {
  const databasePath = options.databasePath ?? join(process.cwd(), 'data', 'duolink.sqlite');
  const serverKeyPem = options.serverKeyPem ?? generateServerSigningKeyPair().privateKeyPem;
  const privateKey = loadServerSigningKey(serverKeyPem);
  const publicKeyDer = serverPublicKeyDer(serverKeyPem);

  const clock = options.clock ?? (() => Date.now());
  const store = new InvitationStore({
    databasePath,
    clock,
    retentionSecondsAfterTerminal: options.retentionSecondsAfterTerminal ?? DEFAULT_RETENTION_SECONDS,
  });

  const app = createApp({
    store,
    clock,
    limits: options.limits ?? {},
    serverKeys: {
      publicKeyDer,
      privateKeyPem: serverKeyPem,
      sign: (message) => signReceipt(privateKey, message),
    },
  });

  const handler = (req, res) => {
    app
      .handleTransport(req)
      .then(({ status, headers, body }) => {
        res.writeHead(status, headers);
        res.end(body);
      })
      .catch(() => {
        res.writeHead(500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ error: 'internal_error', message: 'Unexpected server error' }));
      });
  };

  const tls = options.tlsKeyPem && options.tlsCertPem
    ? { key: options.tlsKeyPem, cert: options.tlsCertPem }
    : null;

  const httpServer = tls ? createHttpsServer(tls, handler) : createHttpServer(handler);

  // Retention sweeper: expiry + tombstone deletion every 30s. The store also expires lazily on every
  // request, so correctness never depends on this timer firing.
  let sweeper = null;

  /**
   * WebSocket endpoint for the encrypted relay.
   *
   * Protocol (JSON text frames, all of it ciphertext or routing metadata — never plaintext):
   *   client -> server  { "type": "hello",   "deviceId": "<b64u>" }
   *   server -> client  { "type": "ready",   "online": bool, "queued": n }
   *   client -> server  { "type": "send",    "envelope": { id, from, to, seq, iv, ct } }
   *   server -> client  { "type": "stored",  "id": "...", "duplicate": bool }
   *   client -> server  { "type": "ack",     "messageId": "..." }
   *   client -> server  { "type": "receipt", "kind": "delivered"|"read", "messageId": "...", "to": "..." }
   *   server -> client  { "type": "message", "envelope": {...} }        (pushed)
   *   server -> client  { "type": "receipt", "kind": ..., "messageId": ... }
   *   server -> client  { "type": "error",   "code": "...", "message": "..." }
   *
   * `hello` binds the connection to one device id. Everything the connection sends is then checked
   * against that id, so an open socket cannot be used to read or acknowledge another device's mail.
   */
  const detachWebSocket = attachWebSocket(httpServer, {
    path: '/v1/ws',
    onConnection: (connection) => {
      /** The device this connection authenticated as, or null before `hello`. */
      let boundDeviceId = null;
      let unsubscribe = null;

      const reply = (frame) => connection.sendJson(frame);
      const fail = (code, message) => reply({ type: 'error', code, message });

      connection.onMessage((_conn, raw) => {
        if (typeof raw !== 'string') {
          return fail('binary_not_supported', 'send JSON text frames only');
        }
        let frame;
        try {
          frame = JSON.parse(raw);
        } catch {
          return fail('malformed_json', 'frame is not valid JSON');
        }
        if (!frame || typeof frame.type !== 'string') {
          return fail('malformed_frame', 'frame needs a type');
        }

        if (frame.type === 'hello') {
          if (boundDeviceId !== null) {
            return fail('already_bound', 'this connection is already bound to a device');
          }
          if (typeof frame.deviceId !== 'string' || Buffer.from(frame.deviceId, 'base64url').length !== 16) {
            return fail('malformed_frame', 'deviceId must be a 16-byte base64url string');
          }
          boundDeviceId = frame.deviceId;
          // Push anything that arrived while the device was offline, then keep streaming.
          unsubscribe = app.relay.subscribe(boundDeviceId, (pushed) => reply(pushed));
          const backlog = app.relay.fetchSince(boundDeviceId, 0);
          reply({ type: 'ready', online: true, queued: backlog.length });
          for (const envelope of backlog) reply({ type: 'message', envelope });
          return undefined;
        }

        // Every other frame requires a bound device.
        if (boundDeviceId === null) return fail('not_ready', 'send hello first');

        try {
          if (frame.type === 'send') {
            const envelope = frame.envelope;
            if (!envelope || typeof envelope.to !== 'string') {
              return fail('malformed_frame', 'envelope.to is required');
            }
            if (envelope.from !== boundDeviceId) {
              // A device may only send as itself. This is not attribution — the recipient still
              // verifies the AEAD — but it stops a socket from spoofing a third device's id.
              return fail('sender_mismatch', 'envelope.from must equal the bound device id');
            }
            const result = app.relay.enqueue(envelope, {
              expectedRecipientDeviceIdB64u: envelope.to,
            });
            return reply({ type: 'stored', id: envelope.id, duplicate: result.duplicate });
          }

          if (frame.type === 'ack') {
            const acknowledged = app.relay.acknowledge(boundDeviceId, String(frame.messageId ?? ''));
            return reply({ type: 'acked', messageId: frame.messageId, acknowledged });
          }

          if (frame.type === 'receipt') {
            app.relay.recordReceipt({
              kind: frame.kind,
              messageId: String(frame.messageId ?? ''),
              from: boundDeviceId,
              to: String(frame.to ?? ''),
            });
            return reply({ type: 'receipt_stored' });
          }

          return fail('unknown_type', `unsupported frame type '${frame.type}'`);
        } catch (error) {
          if (error instanceof Error && typeof error.code === 'string') {
            return fail(error.code, error.message);
          }
          return fail('internal_error', 'relay operation failed');
        }
      });

      connection.onClose(() => {
        if (unsubscribe) unsubscribe();
      });
    },
  });

  return {
    store,
    app,
    httpServer,
    /** The encrypted-message relay, shared by the WebSocket path and the HTTP fallback. */
    relay: app.relay,
    detachWebSocket,
    protocolVersion: PROTOCOL_VERSION,
    receiptPublicKeyB64u: publicKeyDer.toString('base64url'),
    async listen({ host = '127.0.0.1', port = 0, sweepIntervalMs = 30_000 } = {}) {
      await new Promise((resolve, reject) => {
        httpServer.once('error', reject);
        httpServer.listen(port, host, () => {
          httpServer.removeListener('error', reject);
          resolve();
        });
      });
      if (sweepIntervalMs > 0) {
        sweeper = setInterval(() => {
          try {
            store.expireOverdue();
            store.purge();
          } catch {
            /* a sweeper failure must never take the listener down */
          }
        }, sweepIntervalMs);
        sweeper.unref?.();
      }
      const address = httpServer.address();
      const scheme = tls ? 'https' : 'http';
      return {
        port: address.port,
        host: address.address,
        baseUrl: `${scheme}://${host === '0.0.0.0' ? '127.0.0.1' : host}:${address.port}`,
        tls: Boolean(tls),
      };
    },
    async close() {
      detachWebSocket?.();
      if (sweeper) {
        clearInterval(sweeper);
        sweeper = null;
      }
      await new Promise((resolve) => httpServer.close(() => resolve()));
      store.close();
    },
  };
}

export function loadPemFile(path) {
  return readFileSync(path);
}

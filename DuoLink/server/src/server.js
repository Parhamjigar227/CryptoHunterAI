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

  return {
    store,
    app,
    httpServer,
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

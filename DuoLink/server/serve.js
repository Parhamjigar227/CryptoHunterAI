#!/usr/bin/env node
/**
 * DuoLink local signaling server launcher.
 *
 * Local development (default, loopback only):
 *   node serve.js --port 8787 --db ./data/duolink.sqlite
 *   # Android emulator connects through:  adb reverse tcp:8787 tcp:8787
 *   #   => debug build signaling URL: http://127.0.0.1:8787
 *
 * TLS (for a self-hosted deployment you run yourself; production release builds require HTTPS):
 *   node serve.js --port 8443 --https --tls-key ./certs/key.pem --tls-cert ./certs/cert.pem
 *
 * Flags:
 *   --host 0.0.0.0          bind all interfaces (default 127.0.0.1: loopback only)
 *   --db <path>             SQLite database path (default ./data/duolink.sqlite, use :memory: for tests)
 *   --server-key <pem>      receipt-signing key; generated to <db dir>/server-receipt-key.pem when absent
 *   --retention <seconds>   tombstone retention after terminal state (default 600)
 *   --sweep <ms>            retention sweeper interval (default 30000, 0 disables)
 *   --quiet                 suppress the startup banner
 *
 * Environment variable equivalents: DUOLINK_HOST, DUOLINK_PORT, DUOLINK_DB, DUOLINK_TLS_KEY,
 * DUOLINK_TLS_CERT, DUOLINK_SERVER_KEY, DUOLINK_RETENTION.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createDuoLinkServer } from './src/server.js';
import { generateServerSigningKeyPair } from './src/crypto.js';

function parseArgs(argv) {
  const args = { https: false, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${token}`);
      return argv[i];
    };
    switch (token) {
      case '--port': args.port = Number(next()); break;
      case '--host': args.host = next(); break;
      case '--db': args.db = next(); break;
      case '--server-key': args.serverKey = next(); break;
      case '--tls-key': args.tlsKey = next(); break;
      case '--tls-cert': args.tlsCert = next(); break;
      case '--retention': args.retention = Number(next()); break;
      case '--sweep': args.sweep = Number(next()); break;
      case '--https': args.https = true; break;
      case '--quiet': args.quiet = true; break;
      case '--help':
      case '-h':
        console.log(readFileSync(new URL(import.meta.url), 'utf8').split('*/')[0]);
        process.exit(0);
        break;
      default:
        throw new Error(`Unknown argument: ${token}`);
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const host = args.host ?? process.env.DUOLINK_HOST ?? '127.0.0.1';
const port = args.port ?? Number(process.env.DUOLINK_PORT ?? 8787);
const rawDb = args.db ?? process.env.DUOLINK_DB ?? join(process.cwd(), 'data', 'duolink.sqlite');
// ':memory:' must reach the SQLite driver verbatim: resolving it would create a file literally named
// ':memory:' in the working directory instead of an ephemeral in-memory database.
const dbPath = rawDb === ':memory:' ? rawDb : resolve(rawDb);

if (dbPath !== ':memory:') mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });

let serverKey = args.serverKey ?? process.env.DUOLINK_SERVER_KEY ?? null;
if (serverKey) {
  serverKey = readFileSync(resolve(serverKey), 'utf8');
} else if (dbPath !== ':memory:') {
  const keyPath = join(dirname(dbPath), 'server-receipt-key.pem');
  if (existsSync(keyPath)) {
    serverKey = readFileSync(keyPath, 'utf8');
  } else {
    serverKey = generateServerSigningKeyPair().privateKeyPem;
    writeFileSync(keyPath, serverKey, { mode: 0o600 });
  }
}

const tlsKeyPath = args.tlsKey ?? process.env.DUOLINK_TLS_KEY ?? null;
const tlsCertPath = args.tlsCert ?? process.env.DUOLINK_TLS_CERT ?? null;
if (args.https && (!tlsKeyPath || !tlsCertPath)) {
  console.error('ERROR: --https requires --tls-key and --tls-cert');
  process.exit(2);
}

const server = createDuoLinkServer({
  databasePath: dbPath,
  serverKeyPem: serverKey,
  tlsKeyPem: tlsKeyPath ? readFileSync(resolve(tlsKeyPath)) : undefined,
  tlsCertPem: tlsCertPath ? readFileSync(resolve(tlsCertPath)) : undefined,
  retentionSecondsAfterTerminal: args.retention ?? Number(process.env.DUOLINK_RETENTION ?? 600),
});

const info = await server.listen({
  host,
  port,
  sweepIntervalMs: args.sweep ?? 30_000,
});

if (!args.quiet) {
  console.log('DuoLink signaling server (Method B / protocol v1)');
  console.log(`  listening      : ${info.baseUrl}  (tls=${info.tls})`);
  console.log(`  database       : ${dbPath}`);
  console.log(`  receipt pubkey : ${server.receiptPublicKeyB64u}`);
  console.log(`  privacy        : activation codes and bearer tokens are stored only as salted SHA-256`);
  console.log(`                   digests; commits are opaque E2EE ciphertexts the server cannot decrypt.`);
  console.log(`  android dev    : adb reverse tcp:${info.port} tcp:${info.port}   # debug build URL http://127.0.0.1:${info.port}`);
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    await server.close();
    process.exit(0);
  });
}

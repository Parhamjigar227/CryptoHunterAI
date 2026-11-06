# DuoLink Signaling Server (Method B — remote pairing)

A **self-hostable** Node.js signaling server for DuoLink remote pairing. It exists only to relay
public keys and end-to-end-encrypted ciphertext between two phones; it is not a trust authority.

- Runtime: **Node.js ≥ 22.5** (uses the built-in `node:sqlite` driver — no native build step, no
  third-party runtime dependency, `npm install` installs nothing).
- Storage: SQLite in WAL mode with `synchronous=FULL`; every state transition is a single
  `BEGIN IMMEDIATE` transaction.
- Transport: plain HTTP for local development, HTTPS/TLS for a deployment you run yourself.
- Cost: **zero**. No cloud account, domain, VPS or paid service is used or required by this
  repository. Nothing in this repository deploys publicly.

## What the server stores, and what it never stores

| Stored | Never stored |
| --- | --- |
| Participants' **public** keys (identity, pairwise ACK key, signed pre-key, ephemeral) | Any private key |
| Salted SHA-256 digest of the activation code | The plaintext activation code |
| Salted SHA-256 digest of each bearer token | Bearer tokens in plaintext |
| Opaque AES-256-GCM commit/ACK ciphertexts (deleted at mutual receipt) | Pairing root key `K_pair_root` |
| SHA-256 digests of commit ciphertexts | Directional envelope keys `K_env_*` |
| ECDSA ACK signatures + timestamps | Confirmation HMAC keys `K_confirm_*` |
| | Any decryptable handshake payload |

The server **cannot decrypt** a commit, **cannot verify** a peer HMAC (it does not possess the
symmetric keys), and **cannot** become a trusted peer. The only cryptographic check it performs is
verifying an ECDSA signature over an ACK transcript, using a session-scoped public key the client
registered for exactly that purpose.

Full protocol and the server/client verification boundary: see
[`../docs/REMOTE_SIGNALING_PROTOCOL.md`](../docs/REMOTE_SIGNALING_PROTOCOL.md).

## Run it locally (development)

```bash
cd DuoLink/server
node serve.js --port 8787 --db ./data/duolink.sqlite
```

Then connect an Android **debug** build over the ADB tunnel, so the phone never needs a real
network address and nothing is exposed beyond loopback:

```bash
adb reverse tcp:8787 tcp:8787     # device/emulator now sees http://127.0.0.1:8787
```

Debug builds read the signaling URL from the app's *Remote pairing → server settings* screen
(persisted per install) and default to `http://127.0.0.1:8787`. **Release builds reject `http://`
entirely** and require `https://` — enforced in code (`SignalingEndpointPolicy`), not by convention.

## Run it with TLS (self-hosted, optional)

```bash
node serve.js --port 8443 --https \
  --tls-key ./certs/key.pem --tls-cert ./certs/cert.pem \
  --db ./data/duolink.sqlite
```

`GET /v1/server-info` returns `capabilities` that state explicitly what this server can and cannot
verify; clients display those flags verbatim rather than paraphrasing them.

## CLI flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port` | `8787` | TCP port |
| `--host` | `127.0.0.1` | Bind address; loopback-only unless you opt in to `0.0.0.0` |
| `--db` | `./data/duolink.sqlite` | SQLite path (`:memory:` supported) |
| `--server-key` | generated in the DB directory | PEM ECDSA key that signs ACK receipts |
| `--https` | off | Serve TLS (requires `--tls-key` and `--tls-cert`) |
| `--retention` | `600` | Seconds a terminal invitation row is kept before deletion |
| `--sweep` | `30000` | Retention sweeper interval in ms (`0` disables; expiry is also lazy) |

Environment equivalents: `DUOLINK_HOST`, `DUOLINK_PORT`, `DUOLINK_DB`, `DUOLINK_TLS_KEY`,
`DUOLINK_TLS_CERT`, `DUOLINK_SERVER_KEY`, `DUOLINK_RETENTION`.

## API

All responses are `application/json`, `cache-control: no-store`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | Liveness + aggregate per-state counts |
| `GET` | `/v1/server-info` | none | Protocol version, receipt key, honesty flags |
| `POST` | `/v1/invitations` | none | Create invitation; returns activation code + owner token **once** |
| `POST` | `/v1/invitations/redeem` | activation code | Redeem once; returns recipient token |
| `POST` | `/v1/invitations/:id/commit` | bearer | Submit own encrypted commit (digest bound) |
| `GET` | `/v1/invitations/:id` | bearer | Poll state; peer ciphertext released **only after quorum** |
| `POST` | `/v1/invitations/:id/ack` | bearer | Authenticated persistence ACK (ECDSA) → server receipt |
| `POST` | `/v1/invitations/:id/revoke` | owner bearer | Cancel; purges commits; refused after mutual receipt |
| `POST` | `/v1/invitations/:id/reject` | recipient bearer | Decline; terminal |

Invitation state machine (server side):

```
created ──redeem──▶ redeemed ──1st commit──▶ commits_partial ──2nd commit──▶ commit_quorum_reached
   │                   │                          │                                │
   ├─revoke─▶ revoked  ├─reject─▶ rejected        ├─revoke─▶ revoked               ├─revoke─▶ revoked
   └─ttl────▶ expired  └─ttl────▶ expired         └─ttl────▶ expired               ├─both ACKs─▶ mutual_receipt (terminal)
                                                                                   └─ttl────▶ expired
```

`commit_quorum_reached` is the **serialisation barrier**: peer commit ciphertext is not readable by
either side before both commits exist, so a one-sided commit can never be mistaken for progress.

## Security properties enforced here

- **Single use**: an activation code is redeemable exactly once; a second attempt is `409`.
- **Replay-safe**: identical commit re-submission is idempotent; a *different* commit for the same
  role is `409 commit_conflict`. Identical ACK re-submission is idempotent; a different ACK is
  `409 ack_conflict`.
- **Role binding**: a recipient token cannot submit an `owner` commit/ACK (`403 role_mismatch`).
- **Digest binding**: a commit whose declared SHA-256 digest does not match its ciphertext is
  rejected before storage.
- **Rate limiting**: per transport address on *every* route plus a global activation-code budget,
  durably stored so a restart cannot reset an attacker's allowance.
- **No code oracle**: an expired invitation and a never-existent code both answer `404`.
- **Retention**: at mutual receipt the commit ciphertexts and ephemeral keys are destroyed; terminal
  rows are deleted after the retention window.
- **Body limit**: 64 KiB enforced before JSON parsing.

## Tests

```bash
cd DuoLink/server
npm test            # node --test, 42 tests, all real crypto (no mocks)
```

Coverage includes: creation, single-use redemption, wrong/corrupt key handling, non-canonical
encoding, expired invitations, invalid owner/recipient tokens, role confusion, rate limiting
(including durability across restart), the quorum barrier, digest mismatch, commit replay/conflict,
oversized ciphertext, concurrent commits, real ECDSA ACK acceptance/rejection (wrong key, wrong
transcript, bit-flipped signature), ACK before quorum, mutual receipt, conflicting ACK, payload
destruction, all six cancellation races, revocation after mutual receipt, lazy expiry, retention
sweeper, SQLite restart recovery, transport hardening, and transcript parity vectors shared with the
Android JVM tests.

## Known limitations (honest)

- Single SQLite file: correctness under concurrency relies on SQLite's write lock. That is sound for
  one server process and for multiple processes on one host sharing the file, but it is **not** a
  distributed consensus system. Two servers with independent databases are not supported.
- Rate limiting is per address and global-per-window; it is not proof against a large botnet.
- The receipt signature proves the server *recorded* an ACK. It is **not** proof of peer consent and
  is never displayed as such.
- Transport confidentiality depends on TLS. When running over plain HTTP loopback for development,
  the only protection is the E2EE payload encryption plus the ADB tunnel.

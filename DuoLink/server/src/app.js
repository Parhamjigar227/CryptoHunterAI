/**
 * DuoLink signaling server — HTTP API.
 *
 * Transport-agnostic request handler: `createApp()` returns `{ handle(request) }`, used identically
 * by the local HTTP dev listener, the HTTPS listener and the in-process test harness. This means
 * every test exercises the *real* request path (parsing, validation, transactions, serialisation).
 *
 * Endpoints (all JSON, all `no-store`):
 *   POST /v1/invitations                        -> create (owner)
 *   POST /v1/invitations/redeem                 -> redeem activation code (recipient)
 *   POST /v1/invitations/:id/commit             -> submit own encrypted commit (both roles)
 *   GET  /v1/invitations/:id                    -> poll state + peer commit after quorum (both roles)
 *   POST /v1/invitations/:id/ack                -> authenticated persistence ACK (both roles)
 *   POST /v1/invitations/:id/revoke             -> owner cancels
 *   POST /v1/invitations/:id/reject             -> recipient declines
 *   GET  /v1/server-info                        -> protocol version, receipt key, honesty flags
 *   GET  /healthz                               -> liveness + aggregate counts
 */

import { MessageRelay, RelayError } from './relay.js';
import {
  INVITATION_TTL_SECONDS,
  LIMITS,
  PROTOCOL_VERSION,
  ROLE_OWNER,
  ROLE_RECIPIENT,
} from './protocol.js';
import {
  ProtocolError,
  b64u,
  fromB64uStrict,
  generateActivationCode,
  generateBearerToken,
  generateInvitationId,
  hashActivationCode,
  normaliseActivationCode,
  parseP256PublicKeyB64u,
} from './crypto.js';

const MAX_BODY_BYTES = 64 * 1024;

const json = (status, payload, extraHeaders = {}) => ({
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  },
  body: JSON.stringify(payload),
});

class HttpError extends Error {
  constructor(status, message, extraHeaders = {}) {
    super(message);
    this.status = status;
    this.extraHeaders = extraHeaders;
  }
}

function decodeParticipant(body, prefix) {
  const source = body?.[prefix];
  if (!source || typeof source !== 'object') {
    throw new ProtocolError('malformed_payload', `Missing participant object '${prefix}'`);
  }
  const deviceId = fromB64uStrict(source.deviceId, `${prefix}.deviceId`);
  if (deviceId.length !== LIMITS.deviceIdBytes) {
    throw new ProtocolError('malformed_payload', `${prefix}.deviceId must be ${LIMITS.deviceIdBytes} bytes`);
  }
  const nonce = fromB64uStrict(source.nonce, `${prefix}.nonce`);
  if (nonce.length !== LIMITS.nonceBytes) {
    throw new ProtocolError('malformed_payload', `${prefix}.nonce must be ${LIMITS.nonceBytes} bytes`);
  }
  const identitySignature = fromB64uStrict(source.identitySignature, `${prefix}.identitySignature`);
  if (identitySignature.length < LIMITS.minSignatureBytes || identitySignature.length > LIMITS.maxSignatureBytes) {
    throw new ProtocolError('malformed_payload', `${prefix}.identitySignature must be a DER ECDSA signature`);
  }
  // SPK self-signature. The server relays these three fields verbatim and NEVER verifies the signature:
  // it has no authority to attest a client's signed pre-key, and claiming otherwise would be a lie.
  if (!Number.isInteger(source.spkId) || source.spkId < 1) {
    throw new ProtocolError('malformed_payload', `${prefix}.spkId must be a positive integer`);
  }
  if (!Number.isInteger(source.spkCreatedAtEpochSec) || source.spkCreatedAtEpochSec < 0) {
    throw new ProtocolError('malformed_payload', `${prefix}.spkCreatedAtEpochSec must be a non-negative integer`);
  }
  const spkSignature = fromB64uStrict(source.spkSignature, `${prefix}.spkSignature`);
  if (spkSignature.length < LIMITS.minSignatureBytes || spkSignature.length > LIMITS.maxSignatureBytes) {
    throw new ProtocolError('malformed_payload', `${prefix}.spkSignature must be a DER ECDSA signature`);
  }
  return {
    deviceId,
    nonce,
    identitySignature,
    spkId: source.spkId,
    spkCreatedAtEpochSec: source.spkCreatedAtEpochSec,
    spkSignature,
    identitySpki: parseP256PublicKeyB64u(source.identitySpki, `${prefix}.identitySpki`).export({
      format: 'der',
      type: 'spki',
    }),
    ackSpki: parseP256PublicKeyB64u(source.ackSpki, `${prefix}.ackSpki`).export({
      format: 'der',
      type: 'spki',
    }),
    spkSpki: parseP256PublicKeyB64u(source.spkSpki, `${prefix}.spkSpki`).export({
      format: 'der',
      type: 'spki',
    }),
    ephemeralSpki: parseP256PublicKeyB64u(source.ephemeralSpki, `${prefix}.ephemeralSpki`).export({
      format: 'der',
      type: 'spki',
    }),
  };
}

const deviceSpki = (key) => key.export({ format: 'der', type: 'spki' });

/**
 * @param {object} options
 * @param {import('./store.js').InvitationStore} options.store
 * @param {object} options.serverKeys            `{ privateKeyPem, publicKeyDer }`
 * @param {() => number} [options.clock]
 * @param {object} [options.limits]              rate-limit overrides (tests use tiny budgets)
 */
export function createApp({ store, serverKeys, clock = () => Date.now(), limits = {} }) {
  const rateLimits = {
    generalPerWindow: limits.generalPerWindow ?? LIMITS.maxRequestsPerWindow,
    activationPerWindow: limits.activationPerWindow ?? LIMITS.maxActivationAttemptsPerWindow,
    windowSeconds: limits.windowSeconds ?? 60,
  };

  const clientAddress = (request) => request.remoteAddress ?? 'unknown';

  const enforceRate = (request, kind) => {
    const address = clientAddress(request);
    store.checkRateLimit(`general:${address}`, rateLimits.generalPerWindow, rateLimits.windowSeconds);
    if (kind === 'activation') {
      // Activation-code guessing deserves its own tight budget, independent of transport address,
      // because an attacker can rotate source addresses but cannot rotate the code alphabet space
      // fast enough within 15 minutes.
      store.checkRateLimit('activation:global', rateLimits.activationPerWindow, rateLimits.windowSeconds);
    }
  };

  const authenticate = (request) => {
    const header = request.headers?.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw new ProtocolError('unauthenticated', 'Missing bearer token', 401);
    }
    let token;
    try {
      token = fromB64uStrict(header.slice(7), 'authorization token');
    } catch {
      // A syntactically broken token is an authentication failure, never a 400 validation error:
      // the distinction matters because only 401 can be retried with different credentials.
      throw new ProtocolError('unauthenticated', 'Malformed bearer token', 401);
    }
    if (token.length !== LIMITS.tokenBytes) {
      throw new ProtocolError('unauthenticated', 'Malformed bearer token', 401);
    }
    return token;
  };

  const handle = (request) => {
    const method = (request.method ?? 'GET').toUpperCase();
    const url = new URL(request.url, 'http://localhost');
    const path = url.pathname;

    try {
      // Every route -- including liveness/health probes -- is rate limited per transport address,
      // so no unauthenticated path exists that an attacker can flood freely.
      enforceRate(request, 'general');
      if (method === 'GET' && path === '/healthz') {
        return json(200, {
          status: 'ok',
          protocolVersion: PROTOCOL_VERSION,
          serverTimeEpochSec: Math.floor(clock() / 1000),
          retention: { terminalTombstoneSeconds: 600 },
          invitationsByState: store.stats(),
        });
      }

      if (method === 'GET' && path === '/v1/server-info') {
        return json(200, {
          protocolVersion: PROTOCOL_VERSION,
          provider: 'duolink-signaling-v1',
          receiptPublicKeySpkiB64u: b64u(serverKeys.publicKeyDer),
          invitationTtlSeconds: INVITATION_TTL_SECONDS,
          // Stated explicitly so no client, operator or auditor can be misled:
          capabilities: {
            verifiesEcdsaAckSignatures: true,
            verifiesPeerHmac: false,
            decryptsCommitCiphertext: false,
            storesPlaintextActivationCode: false,
            storesPrivateKeys: false,
            // Relay-only: the server forwards each device's signed-pre-key self-signature so the *peer*
            // can verify it. It does not and cannot attest it itself.
            relaysSpkSignatureWithoutVerification: true,
            verifiesSpkSignature: false,
          },
        });
      }

      if (method === 'POST' && path === '/v1/invitations') {
        const owner = decodeParticipant(request.body, 'owner');
        // The id is client-assigned so the owner can sign the invitation transcript (which binds the id)
        // *before* uploading anything. A missing id is generated server-side for compatibility.
        const invitationId = request.body.invitationId
          ? String(request.body.invitationId)
          : generateInvitationId();
        // The activation code is normally chosen by the owner, because the owner's invitation
        // transcript binds its salted hash and that signature must be produced before the upload. The
        // server still validates the format strictly (16 symbols from the shared alphabet) and falls back
        // to generating one for clients that do not supply it (the CLI/simulated flow).
        const activationCode = request.body.activationCode
          ? normaliseActivationCode(request.body.activationCode)
          : generateActivationCode();
        const ownerToken = generateBearerToken();
        const created = store.createInvitation({
          invitationId,
          activationCode,
          ownerToken,
          owner,
          ttlSeconds: request.body.ttlSeconds ?? INVITATION_TTL_SECONDS,
        });
        return json(201, {
          invitationId: created.invitationId,
          activationCode,
          ownerToken: b64u(ownerToken),
          protocolVersion: PROTOCOL_VERSION,
          createdAtEpochSec: created.createdAt,
          expiresAtEpochSec: created.expiresAt,
          note: 'The activation code and owner token are returned exactly once and are never stored in plaintext.',
        });
      }

      if (method === 'POST' && path === '/v1/invitations/redeem') {
        enforceRate(request, 'activation');
        const code = normaliseActivationCode(request.body?.activationCode);
        const recipient = decodeParticipant(request.body, 'recipient');
        const recipientToken = generateBearerToken();
        const redeemed = store.redeemInvitation({
          activationCode: code,
          recipient: { ...recipient, token: recipientToken },
        });
        return json(200, {
          invitationId: redeemed.invitationId,
          recipientToken: b64u(recipientToken),
          state: 'redeemed',
          expiresAtEpochSec: redeemed.expiresAt,
        });
      }

      const invitationMatch = path.match(/^\/v1\/invitations\/([A-Za-z0-9_-]{8,64})(\/[a-z]+)?$/);
      if (invitationMatch) {
        const invitationId = invitationMatch[1];
        const action = invitationMatch[2] ?? '';

        if (method === 'GET' && action === '') {
          const token = authenticate(request);
          const view = store.getInvitationView({ invitationId, token });
          return json(200, {
            invitationId: view.invitationId,
            state: view.state,
            role: view.role,
            protocolVersion: view.protocolVersion,
            expiresAtEpochSec: view.expiresAt,
            redeemed: view.redeemed,
            quorumReached: view.quorumReached,
            mutualReceipt: view.mutualReceipt,
            ciphertextReceipt: view.ciphertextReceipt,
            e2eeValidityVerifiedByServer: view.e2eeValidityVerifiedByServer,
            ownCommitDigestB64u: view.ownCommitDigest ? b64u(view.ownCommitDigest) : null,
            peerCommitDigestB64u: view.peerCommitDigest ? b64u(view.peerCommitDigest) : null,
            peerCommitCiphertextB64u: view.peerCommitCiphertext ? b64u(view.peerCommitCiphertext) : null,
            ownNonceB64u: view.ownNonce ? b64u(view.ownNonce) : null,
            ownIdentitySignatureB64u: view.ownIdentitySignature ? b64u(view.ownIdentitySignature) : null,
            peer: view.peer
              ? {
                  deviceIdB64u: b64u(view.peer.deviceId),
                  identitySpkiB64u: b64u(view.peer.identitySpki),
                  spkSpkiB64u: b64u(view.peer.spkSpki),
                  ephemeralSpkiB64u: view.peer.ephemeralSpki ? b64u(view.peer.ephemeralSpki) : null,
                  nonceB64u: view.peer.nonce ? b64u(view.peer.nonce) : null,
                  identitySignatureB64u: view.peer.identitySignature ? b64u(view.peer.identitySignature) : null,
                  spkId: view.peer.spkId ?? null,
                  spkCreatedAtEpochSec: view.peer.spkCreatedAtEpochSec ?? null,
                  spkSignatureB64u: view.peer.spkSignature ? b64u(view.peer.spkSignature) : null,
                }
              : null,
            acks: {
              ownerRecorded: view.acks.ownerRecorded,
              recipientRecorded: view.acks.recipientRecorded,
              ownerSignatureB64u: view.acks.ownerSignature ? b64u(view.acks.ownerSignature) : null,
              recipientSignatureB64u: view.acks.recipientSignature ? b64u(view.acks.recipientSignature) : null,
            },
          });
        }

        if (method === 'POST' && action === '/commit') {
          const token = authenticate(request);
          const role = request.body?.role;
          if (role !== ROLE_OWNER && role !== ROLE_RECIPIENT) {
            throw new ProtocolError('malformed_payload', "role must be 'owner' or 'recipient'");
          }
          const ciphertext = fromB64uStrict(request.body?.commitCiphertextB64u, 'commitCiphertextB64u');
          const declaredDigest = fromB64uStrict(request.body?.commitDigestB64u, 'commitDigestB64u');
          const result = store.submitCommit({
            invitationId,
            token,
            role,
            ciphertext,
            commitDigest: declaredDigest,
          });
          return json(200, {
            accepted: true,
            replay: result.replay,
            quorumReached: result.quorumReached,
            commitDigestOwnerB64u: result.commitDigestOwner ? b64u(result.commitDigestOwner) : null,
            commitDigestRecipientB64u: result.commitDigestRecipient ? b64u(result.commitDigestRecipient) : null,
            ciphertextReceiptOnly: true,
            e2eeValidityVerifiedByServer: false,
          });
        }

        if (method === 'POST' && action === '/ack') {
          const token = authenticate(request);
          const role = request.body?.role;
          if (role !== ROLE_OWNER && role !== ROLE_RECIPIENT) {
            throw new ProtocolError('malformed_payload', "role must be 'owner' or 'recipient'");
          }
          const signature = fromB64uStrict(request.body?.ackSignatureB64u, 'ackSignatureB64u');
          const result = store.submitAck({ invitationId, token, role, signature });
          const row = store.rawRow(invitationId);
          const receipt = store.buildReceipt({
            row,
            role,
            serverSigner: (msg) => serverKeys.sign(msg),
          });
          return json(200, {
            ackRecorded: true,
            replay: result.replay,
            role: result.role,
            mutualReceipt: result.mutualReceipt,
            ackDigestOwnerB64u: result.ackDigestOwner ? b64u(result.ackDigestOwner) : null,
            ackDigestRecipientB64u: result.ackDigestRecipient ? b64u(result.ackDigestRecipient) : null,
            // Peer ACK signatures are released so each client can verify the *peer's* identity
            // signature itself; the server's own verification is reported separately.
            ackSignatures: {
              ownerB64u: result.ackOwnerSignature ? b64u(result.ackOwnerSignature) : null,
              recipientB64u: result.ackRecipientSignature ? b64u(result.ackRecipientSignature) : null,
            },
            serverReceipt: {
              transcriptB64u: b64u(receipt.transcript),
              signatureB64u: b64u(receipt.signature),
              meaning: 'Server recorded this ACK. It is NOT a proof of peer consent.',
            },
            e2eeHmacVerifiedByServer: false,
          });
        }

        if (method === 'POST' && action === '/revoke') {
          const token = authenticate(request);
          const result = store.revokeInvitation({ invitationId, token, reason: request.body?.reason });
          return json(200, { ...result, durablePeerTrustUnaffected: true });
        }

        if (method === 'POST' && action === '/reject') {
          const token = authenticate(request);
          const result = store.rejectInvitation({ invitationId, token, reason: request.body?.reason });
          return json(200, { ...result });
        }
      }

      // ---- encrypted relay: HTTP fallback path -------------------------------------
      // These exist so a client that cannot hold a WebSocket open (hostile network, aggressive
      // doze, or simply no upgrade support in front of a proxy) can still send and receive. They
      // share one queue with the socket, so the two paths are interchangeable, not divergent.
      if (method === 'POST' && path === '/v1/relay/messages') {
        // The sending device must be named in the body; the recipient is bound by the envelope and
        // cannot be redirected by the caller.
        const from = request.body?.fromDeviceId;
        if (typeof from !== 'string') {
          return json(400, { error: 'malformed_payload', message: 'fromDeviceId is required' });
        }
        try {
          const result = relay.enqueue(request.body?.envelope, {
            expectedRecipientDeviceIdB64u: request.body?.envelope?.to ?? null,
          });
          return json(202, { accepted: true, duplicate: result.duplicate, queued: result.queued });
        } catch (error) {
          return relayErrorResponse(error);
        }
      }

      if (method === 'GET' && path.startsWith('/v1/relay/messages')) {
        // Fetching requires the caller to identify itself; the relay only ever returns envelopes
        // addressed to that exact device id.
        const deviceId = url.searchParams.get('deviceId');
        const sinceSeq = Number(url.searchParams.get('sinceSeq') ?? '0');
        if (!deviceId) {
          return json(400, { error: 'malformed_payload', message: 'deviceId is required' });
        }
        if (!Number.isSafeInteger(sinceSeq) || sinceSeq < 0) {
          return json(400, { error: 'malformed_payload', message: 'sinceSeq must be a non-negative integer' });
        }
        let waiting;
        try {
          waiting = relay.fetchSince(deviceId, sinceSeq);
        } catch (error) {
          return relayErrorResponse(error);
        }
        return json(200, {
          envelopes: waiting,
          // `online` lets the client decide whether to keep the socket or lean on polling.
          online: relay.isOnline(deviceId),
        });
      }

      if (method === 'POST' && path === '/v1/relay/ack') {
        const deviceId = request.body?.deviceId;
        const messageId = request.body?.messageId;
        if (typeof deviceId !== 'string' || typeof messageId !== 'string') {
          return json(400, { error: 'malformed_payload', message: 'deviceId and messageId are required' });
        }
        return json(200, { acknowledged: relay.acknowledge(deviceId, messageId) });
      }

      if (method === 'POST' && path === '/v1/relay/receipts') {
        try {
          const result = relay.recordReceipt({
            kind: request.body?.kind,
            messageId: request.body?.messageId,
            from: request.body?.from,
            to: request.body?.to,
          });
          return json(202, { accepted: true, duplicate: result.duplicate, downgraded: result.downgraded });
        } catch (error) {
          return relayErrorResponse(error);
        }
      }

      if (method === 'GET' && path === '/v1/relay-status') {
        return json(200, {
          relay: relay.stats(),
          capabilities: {
            webSocket: true,
            httpPollingFallback: true,
            storesPlaintextMessages: false,
            canDecryptMessages: false,
          },
        });
      }

      return json(404, { error: 'not_found', message: `No route for ${method} ${path}` });
    } catch (error) {
      if (error instanceof ProtocolError) {
        const headers = error.status === 429 ? { 'retry-after': String(rateLimits.windowSeconds) } : {};
        return json(error.status, { error: error.code, message: error.message }, headers);
      }
      if (error instanceof HttpError) {
        return json(error.status, { error: 'request_error', message: error.message }, error.extraHeaders);
      }
      // Never leak stack traces or internal paths to a network peer.
      return json(500, { error: 'internal_error', message: 'Unexpected server error' });
    }
  };

  /**
   * Normalises a raw transport request (streams, headers, body buffer) into the shape `handle`
   * expects, enforcing the body-size limit before any JSON parsing happens.
   */
  /**
   * The encrypted-message relay.
   *
   * Deliberately created here (not in server.js) so the HTTP fallback routes and the WebSocket upgrade
   * handler share exactly one queue: a message sent over the socket is visible to a client that
   * reconnects over plain HTTP polling, which is the whole point of having both.
   */
  const relay = new MessageRelay({ clock });

  /** Shared JSON error translation for relay operations used by both transports. */
  const relayErrorResponse = (error) => {
    if (error instanceof RelayError) {
      const status = error.code === 'recipient_mismatch' ? 403 : 400;
      return json(status, { error: error.code, message: error.message });
    }
    throw error;
  };

  const handleTransport = async (rawRequest) => {
    const chunks = [];
    let total = 0;
    for await (const chunk of rawRequest) {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        return json(413, { error: 'payload_too_large', message: 'Request body exceeds 64 KiB' });
      }
      chunks.push(chunk);
    }
    let body = null;
    if (chunks.length > 0) {
      const text = Buffer.concat(chunks).toString('utf8');
      try {
        body = JSON.parse(text);
      } catch {
        return json(400, { error: 'malformed_json', message: 'Request body is not valid JSON' });
      }
      if (body === null || typeof body !== 'object' || Array.isArray(body)) {
        return json(400, { error: 'malformed_json', message: 'Request body must be a JSON object' });
      }
    }
    return handle({
      method: rawRequest.method,
      url: rawRequest.url,
      headers: rawRequest.headers,
      body,
      remoteAddress: rawRequest.socket?.remoteAddress ?? 'unknown',
    });
  };

  return { handle, handleTransport, rateLimits, hashActivationCode, deviceSpki, relay };
}

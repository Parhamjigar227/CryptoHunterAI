/**
 * Test harness: a real, in-process client that speaks the protocol with genuine JCA-equivalent
 * cryptography (Node WebCrypto / node:crypto P-256). Nothing here is mocked at the crypto layer:
 * every signature the server verifies in tests is a real ECDSA signature over the real transcript,
 * and every ACK is rejected when the transcript is altered in the slightest.
 *
 * The commit ciphertexts used by these tests are *opaque blobs of realistic size*: the server has no
 * key to decrypt them (that is the point), so the tests intentionally assert on receipt/digest
 * behaviour rather than on contents the server must never be able to read. The actual AES-256-GCM
 * envelope crypto is covered by the Android JVM suite (`RemoteEnvelopeTest`) and by the two-device
 * end-to-end test (`RemotePairingEndToEndTest`).
 */

import { createHash, randomBytes } from 'node:crypto';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createDuoLinkServer } from '../src/server.js';
import { InvitationStore } from '../src/store.js';
import { createApp } from '../src/app.js';
import { generateServerSigningKeyPair, loadServerSigningKey, signReceipt } from '../src/crypto.js';
import { ackTranscript } from '../src/protocol.js';
import { createPrivateKey } from 'node:crypto';

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const sha256 = (buf) => createHash('sha256').update(buf).digest();

/** Generates a P-256 key that can both sign and do ECDH (the server only sees the public half). */
export function generateParticipantKeys() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const deviceId = createHash('sha256')
    .update(Buffer.from('DuoLink-DeviceId-v1', 'utf8'))
    .update(spki)
    .digest()
    .subarray(0, 16);
  return {
    privateKey,
    publicKey,
    spki,
    deviceId,
    sign: (message) => sign('sha256', message, { key: privateKey, dsaEncoding: 'der' }),
    seal: b64u,
  };
}

export function makeParticipant() {
  const identity = generateParticipantKeys();
  const ackKey = generateParticipantKeys();
  const spk = generateParticipantKeys();
  const ephemeral = generateParticipantKeys();
  return {
    identity,
    ackKey,
    spk,
    ephemeral,
    deviceId: identity.deviceId,
    deviceIdB64u: b64u(identity.deviceId),
    identitySpkiB64u: b64u(identity.spki),
    ackSpkiB64u: b64u(ackKey.spki),
    spkSpkiB64u: b64u(spk.spki),
    ephemeralSpkiB64u: b64u(ephemeral.spki),
    wire() {
      return {
        deviceId: b64u(identity.deviceId),
        identitySpki: b64u(identity.spki),
        ackSpki: b64u(ackKey.spki),
        spkSpki: b64u(spk.spki),
        ephemeralSpki: b64u(ephemeral.spki),
      };
    },
  };
}

/** Deterministic-ish fake commit payload of valid protocol size (opaque to the server by design). */
export function fakeCommitCiphertext(seed = randomBytes(8)) {
  const body = Buffer.concat([seed, randomBytes(160)]);
  return Buffer.concat([Buffer.from([0x02]), body]); // 0x02 = envelope version marker, like the Android client
}

export function createTestServer(options = {}) {
  const clock = options.clock ?? (() => Date.now());
  const store = new InvitationStore({
    databasePath: options.databasePath ?? ':memory:',
    clock,
    retentionSecondsAfterTerminal: options.retentionSecondsAfterTerminal ?? 600,
  });
  const serverKeys = generateServerSigningKeyPair();
  const privateKey = loadServerSigningKey(serverKeys.privateKeyPem);
  const app = createApp({
    store,
    clock,
    limits: options.limits ?? {},
    serverKeys: {
      publicKeyDer: serverKeys.publicKeyDer,
      privateKeyPem: serverKeys.privateKeyPem,
      sign: (message) => signReceipt(privateKey, message),
    },
  });
  return { store, app, serverKeys, clock };
}

/** Full client-side flow helper used by the integration-style server tests. */
export class TestClient {
  /**
   * @param {object} app  `{ handle }` from createApp
   * @param {string} remoteAddress optional transport address for rate-limit bucket tests
   */
  constructor(app, remoteAddress = '127.0.0.1') {
    this.app = app;
    this.remoteAddress = remoteAddress;
  }

  async call(method, path, { body = null, token = null } = {}) {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    const response = this.app.handle({
      method,
      url: path,
      headers,
      body,
      remoteAddress: this.remoteAddress,
    });
    return { status: response.status, json: JSON.parse(response.body) };
  }
}

/** Builds the ACK signature a real client would produce (server then verifies it for real). */
export function buildAckSignature({ participant, invitationId, role, commitDigestOwner, commitDigestRecipient }) {
  const transcript = ackTranscript({
    invitationId,
    role,
    deviceId: participant.deviceId,
    commitDigestOwner,
    commitDigestRecipient,
  });
  return { transcript, signature: participant.ackKey.sign(transcript) };
}

export { createDuoLinkServer };

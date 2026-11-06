import assert from 'node:assert/strict';
import test from 'node:test';
import { parityVectors, PROTOCOL_VERSION, ackTranscript, receiptTranscript } from '../src/protocol.js';

/**
 * Golden vectors consumed byte-for-byte by the Android JVM test
 * `DuoLink/app/src/test/java/com/duolink/app/RemoteTranscriptParityTest.kt`.
 *
 * If either side changes the transcript layout, this test still passes (both sides changed
 * consistently would be caught by the Kotlin test), but any *accidental* unilateral change breaks
 * the Kotlin test immediately, which is exactly the failure we want before a pairing attempt is ever
 * made between devices that disagree about signed bytes.
 */
test('parity vectors are stable and self-consistent', () => {
  const vectors = parityVectors();
  assert.equal(vectors.protocolVersion, PROTOCOL_VERSION);

  assert.equal(
    vectors.ack.hex,
    '44554f4c494e4b2d52454d4f54452d41434b2d56310000000100000013696e765f7061726974795f3030303030303031' +
      '000000056f776e65720000001000112233445566778899aabbccddeeff00000020111111111111111111111111111111' +
      '111111111111111111111111111111111100000020222222222222222222222222222222222222222222222222222222' +
      '2222222222'
  );
  assert.equal(
    vectors.receipt.hex,
    '44554f4c494e4b2d52454d4f54452d524543454950542d56310000000100000013696e765f7061726974795f30303030' +
      '3030303100000009726563697069656e740000001000112233445566778899aabbccddeeff0000002011111111111111' +
      '111111111111111111111111111111111111111111111111110000002022222222222222222222222222222222222222' +
      '222222222222222222222222220000002033333333333333333333333333333333333333333333333333333333333333' +
      '33'
  );

  // Deterministic: recomputing must give the identical bytes.
  assert.equal(ackTranscript(vectors.ack.input).toString('hex'), vectors.ack.hex);
  assert.equal(receiptTranscript(vectors.receipt.input).toString('hex'), vectors.receipt.hex);
});

test('transcript layout is length-prefixed and unambiguous', () => {
  const deviceId = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const a = ackTranscript({
    invitationId: 'inv_a',
    role: 'owner',
    deviceId,
    commitDigestOwner: Buffer.alloc(32, 1),
    commitDigestRecipient: Buffer.alloc(32, 2),
  });
  // Changing any single field must change the bytes (and therefore invalidate the signature).
  const b = ackTranscript({
    invitationId: 'inv_b',
    role: 'owner',
    deviceId,
    commitDigestOwner: Buffer.alloc(32, 1),
    commitDigestRecipient: Buffer.alloc(32, 2),
  });
  assert.notEqual(a.toString('hex'), b.toString('hex'));
  // Concatenation ambiguity is impossible: ("ab","c") and ("a","bc") differ because lengths prefix.
  const left = ackTranscript({
    invitationId: 'ab',
    role: 'owner',
    deviceId,
    commitDigestOwner: Buffer.alloc(32, 1),
    commitDigestRecipient: Buffer.alloc(32, 2),
  });
  const right = ackTranscript({
    invitationId: 'a',
    role: 'owner',
    deviceId,
    commitDigestOwner: Buffer.alloc(32, 1),
    commitDigestRecipient: Buffer.alloc(32, 2),
  });
  assert.notEqual(left.toString('hex'), right.toString('hex'));
});

test('ack transcripts reject structurally invalid inputs', () => {
  assert.throws(() => ackTranscript({ invitationId: 'x', role: 'attacker', deviceId: Buffer.alloc(16), commitDigestOwner: Buffer.alloc(32), commitDigestRecipient: Buffer.alloc(32) }));
  assert.throws(() => ackTranscript({ invitationId: 'x', role: 'owner', deviceId: Buffer.alloc(15), commitDigestOwner: Buffer.alloc(32), commitDigestRecipient: Buffer.alloc(32) }));
  assert.throws(() => ackTranscript({ invitationId: 'x', role: 'owner', deviceId: Buffer.alloc(16), commitDigestOwner: Buffer.alloc(31), commitDigestRecipient: Buffer.alloc(32) }));
});

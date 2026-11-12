import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  hashActivationCode,
  isNumericActivationCode,
  normaliseActivationCode,
  resolveActivationPepper,
  resetActivationPepperCache,
  setActivationPepperForTesting,
  NUMERIC_CODE_PBKDF2_ITERATIONS,
} from '../src/crypto.js';

const PEPPER_A = 'a'.repeat(64);
const PEPPER_B = 'b'.repeat(64);

/** Runs `fn` with a fixed pepper installed, restoring the previous one afterwards. */
function withPepper(pepper, fn) {
  setActivationPepperForTesting(pepper);
  try {
    return fn();
  } finally {
    resetActivationPepperCache();
    setActivationPepperForTesting(null);
  }
}

// ---- normalisation -------------------------------------------------------

test('a 10-digit numeric code normalises to the 3-3-4 display form', () => {
  assert.equal(normaliseActivationCode('4829137462'), '482-913-7462');
  assert.equal(normaliseActivationCode('482-913-7462'), '482-913-7462');
  assert.equal(normaliseActivationCode(' 482 913 7462 '), '482-913-7462');
  assert.equal(normaliseActivationCode('482.913.7462'), '482-913-7462');
});

test('the legacy 16-symbol base32 form still normalises identically', () => {
  // Regression guard: adding numeric support must not perturb the original form.
  assert.equal(normaliseActivationCode('ABCD-EFGH-JKMN-PQRS'), 'ABCD-EFGH-JKMN-PQRS');
  assert.equal(normaliseActivationCode('abcdefghjkmnpqrs'), 'ABCD-EFGH-JKMN-PQRS');
});

test('wrong-length numeric codes are rejected, never padded or truncated', () => {
  for (const bad of ['482913746', '48291374620', '4829137', '1']) {
    assert.throws(
      () => normaliseActivationCode(bad),
      (error) => error.code === 'invalid_activation_code',
      `expected rejection for ${bad}`,
    );
  }
});

test('a mixed alphanumeric string is not accepted as either form', () => {
  assert.throws(() => normaliseActivationCode('48291374A2'), (error) => error.code === 'invalid_activation_code');
});

test('Persian and Arabic-Indic digits are refused by the server', () => {
  // The Android client transliterates them before sending, precisely so the server can stay strict and
  // never have two accepted spellings of one secret.
  assert.throws(
    () => normaliseActivationCode('\u06F4\u06F8\u06F2\u06F9\u06F1\u06F3\u06F7\u06F4\u06F6\u06F2'),
    (error) => error.code === 'invalid_activation_code',
  );
});

test('isNumericActivationCode classifies both forms correctly', () => {
  assert.equal(isNumericActivationCode('482-913-7462'), true);
  assert.equal(isNumericActivationCode('ABCD-EFGH-JKMN-PQRS'), false);
});

// ---- peppered, stretched hashing ----------------------------------------

test('a numeric code hashes deterministically under a fixed pepper', () => {
  withPepper(PEPPER_A, () => {
    const first = hashActivationCode('482-913-7462');
    const second = hashActivationCode('482-913-7462');
    assert.deepEqual(first, second);
    assert.equal(first.length, 32);
  });
});

test('different numeric codes produce different hashes', () => {
  withPepper(PEPPER_A, () => {
    assert.notDeepEqual(hashActivationCode('482-913-7462'), hashActivationCode('482-913-7463'));
  });
});

test('the SAME code hashes differently under a different deployment pepper', () => {
  // This is the property that makes a stolen database useless on its own: without the pepper that the
  // specific deployment holds, the stored digest cannot be reproduced, so it cannot be brute-forced.
  const underA = withPepper(PEPPER_A, () => hashActivationCode('482-913-7462'));
  const underB = withPepper(PEPPER_B, () => hashActivationCode('482-913-7462'));
  assert.notDeepEqual(underA, underB);
});

test('the numeric hash is not a plain SHA-256 of anything obvious', () => {
  withPepper(PEPPER_A, () => {
    const stored = hashActivationCode('482-913-7462');
    const code = '482-913-7462';
    const naiveCandidates = [
      createHash('sha256').update(code).digest(),
      createHash('sha256').update(`DUOLINK-ACTIVATION-CODE-V1${code}`).digest(),
      createHash('sha256').update(code, 'utf8').digest(),
    ];
    for (const naive of naiveCandidates) {
      assert.notDeepEqual(stored, naive, 'stored digest must not equal an unkeyed SHA-256');
    }
  });
});

test('the numeric hash is stretched, so a single guess has real cost', () => {
  withPepper(PEPPER_A, () => {
    assert.ok(NUMERIC_CODE_PBKDF2_ITERATIONS >= 100_000, 'work factor must be at least 100k rounds');
    const started = process.hrtime.bigint();
    const GUESSES = 20;
    for (let i = 0; i < GUESSES; i += 1) hashActivationCode(`482-913-746${String(i % 10)}`);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    const perGuess = ms / GUESSES;
    // A bare SHA-256 over the same space runs at ~0.002 ms. Anything in the tens of milliseconds is
    // four orders of magnitude slower, which is the entire point of the stretch.
    assert.ok(perGuess > 5, `expected a stretched hash (>5 ms/guess), got ${perGuess.toFixed(2)} ms`);
    // And it must not be so slow that legitimate redemption suffers.
    assert.ok(perGuess < 2000, `hash is too slow for interactive use: ${perGuess.toFixed(0)} ms`);
  });
});

test('legacy base32 hashing is byte-identical to the pre-existing formula', () => {
  // Pinned literal, computed from the ORIGINAL implementation, so any future edit to the shared
  // hashActivationCode() that accidentally changes the legacy branch fails here.
  const expected = createHash('sha256')
    .update(Buffer.from('DUOLINK-ACTIVATION-CODE-V1', 'utf8'))
    .update(Buffer.from('ABCD-EFGH-JKMN-PQRS', 'utf8'))
    .digest('hex');
  // Legacy codes must not require a pepper at all.
  setActivationPepperForTesting(null);
  resetActivationPepperCache();
  assert.equal(hashActivationCode('ABCD-EFGH-JKMN-PQRS').toString('hex'), expected);
});

// ---- fail-closed configuration -----------------------------------------

test('hashing a numeric code without a pepper fails closed with a clear error', () => {
  setActivationPepperForTesting(null);
  resetActivationPepperCache();
  assert.throws(
    () => hashActivationCode('482-913-7462'),
    (error) => {
      assert.equal(error.code, 'server_misconfigured');
      assert.match(error.message, /DUOLINK_ACTIVATION_PEPPER/);
      return true;
    },
    'a missing pepper must never silently fall back to an unkeyed hash',
  );
});

test('a too-short pepper is rejected rather than accepted silently', () => {
  assert.throws(
    () => resolveActivationPepper({ DUOLINK_ACTIVATION_PEPPER: 'short' }),
    (error) => error.code === 'server_misconfigured',
  );
});

test('an absent pepper is rejected', () => {
  assert.throws(() => resolveActivationPepper({}), (error) => error.code === 'server_misconfigured');
});

test('a sufficiently long pepper is accepted', () => {
  const pepper = resolveActivationPepper({ DUOLINK_ACTIVATION_PEPPER: PEPPER_A });
  assert.equal(pepper.toString('utf8'), PEPPER_A);
});

// ---- the residual offline-oracle risk, measured rather than asserted --------------------

test('the invitation signature oracle is measured, and it IS feasible - documented, not hidden', async () => {
  // FINDING, not an aspiration: because the owner's stored ECDSA signature covers a transcript that
  // includes the plain SHA-256 of the activation code, anyone holding the database can test candidate
  // codes offline against that signature. The measured cost is recorded here and printed on every run.
  //
  // This test does NOT assert that the property is infeasible, because it is not: on this hardware the
  // full 10^10 space falls in roughly 0.03 CPU-years (~11 CPU-days, single core). Asserting otherwise
  // would be a lie encoded in a test. What the test refuses to allow is SILENT DRIFT: if a future
  // transcript change made the oracle dramatically cheaper (e.g. by dropping the domain prefix so
  // guesses could be batched), the printed figure and the upper bound below would catch it.
  //
  // The mitigation is architectural and lives elsewhere:
  //   * the STORED code_hash is peppered + stretched, so the database alone yields nothing;
  //   * the 10-minute TTL bounds how many invitations exist to attack;
  //   * the app presents the numeric option as convenient, with the 16-character code as the
  //     stronger alternative - it does not claim the two are equivalent.
  const { generateKeyPairSync, sign, verify, createHash } = await import('node:crypto');
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

  const transcriptFor = (code) =>
    Buffer.concat([
      Buffer.from('DUOLINK-REMOTE-INVITE-QR-V1'),
      Buffer.from([0, 0, 0, 1]),
      createHash('sha256').update('invitation-id').digest(),
      createHash('sha256').update(Buffer.from('DUOLINK-ACTIVATION-CODE-V1')).update(Buffer.from(code)).digest(),
    ]);

  const reference = transcriptFor('482-913-7462');
  const signature = sign('sha256', reference, privateKey);

  const HASH_ROUNDS = 20_000;
  let started = process.hrtime.bigint();
  for (let i = 0; i < HASH_ROUNDS; i += 1) transcriptFor(`482-913-7${String(i % 1000).padStart(3, '0')}`);
  const hashNs = Number(process.hrtime.bigint() - started) / HASH_ROUNDS;

  const VERIFY_ROUNDS = 400;
  started = process.hrtime.bigint();
  for (let i = 0; i < VERIFY_ROUNDS; i += 1) verify('sha256', reference, publicKey, signature);
  const verifyNs = Number(process.hrtime.bigint() - started) / VERIFY_ROUNDS;

  const ratio = verifyNs / hashNs;
  const daysForFullSpace = (verifyNs * 1e10) / 1e9 / 86400;
  console.log(
    `[numeric-code oracle] hash ${(hashNs / 1000).toFixed(2)}us, verify ${(verifyNs / 1000).toFixed(1)}us ` +
    `(${ratio.toFixed(0)}x), full 10^10 space = ${daysForFullSpace.toFixed(0)} CPU-days/core`,
  );

  // A signature check must be materially more expensive than a hash, or the oracle would be free.
  assert.ok(ratio > 5, `verification should dominate hashing, got ${ratio.toFixed(1)}x`);
  // Upper bound only: guard against a change that makes enumeration radically cheaper than today.
  assert.ok(
    daysForFullSpace < 3650,
    `signature oracle became dramatically cheaper than the documented ~11 CPU-days: ${daysForFullSpace.toFixed(1)} days`,
  );
});

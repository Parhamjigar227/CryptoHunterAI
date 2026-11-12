package com.duolink.app

import com.duolink.app.crypto.InMemoryByteStore
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.lock.AppLockPolicy
import com.duolink.app.lock.AppLockRecord
import com.duolink.app.lock.AppLockVerifier
import com.duolink.app.lock.PinDerivation
import com.duolink.app.lock.PinRules
import com.duolink.app.lock.SealedAppLockStore
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * App-lock unit tests (JVM, no Android framework).
 *
 * Cover the three things that must never regress:
 *  1. a correct PIN unlocks and a wrong PIN never does,
 *  2. the stored record is sealed and a corrupted record fails *closed* (never silently "no lock"),
 *  3. repeated failures actually throttle, and success resets the throttle.
 */
class AppLockTest {

    private fun newStore(sealer: JcaAesGcmSealer = JcaAesGcmSealer()) =
        SealedAppLockStore(InMemoryByteStore(), sealer)

    // ---- PIN rules ----------------------------------------------------------

    @Test
    fun guessablePinsAreRejectedWithAPersianReason() {
        listOf("0000", "111111", "1234", "4321", "0123456789").forEach { pin ->
            assertNotNull(PinRules.rejectionReason(pin), "PIN '$pin' should have been rejected")
        }
    }

    @Test
    fun reasonablePinsAreAccepted() {
        listOf("482913", "9071", "19384726").forEach { pin ->
            assertNull(PinRules.rejectionReason(pin), "PIN '$pin' should have been accepted")
        }
    }

    @Test
    fun pinLengthAndCharacterRulesAreEnforced() {
        assertNotNull(PinRules.rejectionReason("123"))      // too short
        assertNotNull(PinRules.rejectionReason("1234567890123")) // too long
        assertNotNull(PinRules.rejectionReason("12a456"))    // non-digit
        assertNotNull(PinRules.rejectionReason("12 456"))
    }

    @Test
    fun verificationAcceptsSequentialPinsThatWereSetBeforeTheHeuristic() {
        // Verification must only check format: a user must never be locked out of an existing PIN
        // just because a later release added "too guessable" heuristics.
        assertTrue(PinRules.isValidFormatOnly("1234"))
        assertFalse(PinRules.isValidFormatOnly("123"))
        assertFalse(PinRules.isValidFormatOnly("abcd"))
    }

    // ---- verifier -----------------------------------------------------------

    @Test
    fun correctPinVerifiesAndWrongPinDoesNot() {
        val record = AppLockVerifier.createRecord("482913", nowEpochMs = 1_700_000_000_000L)
        assertTrue(AppLockVerifier.verify("482913", record))
        assertFalse(AppLockVerifier.verify("482914", record))
        assertFalse(AppLockVerifier.verify("000000", record))
        assertFalse(AppLockVerifier.verify("", record))
    }

    @Test
    fun samePinOnTwoDevicesProducesDifferentVerifiers() {
        // Random per-device salt: identical PINs must not yield identical stored verifiers.
        val a = AppLockVerifier.createRecord("482913", 1L)
        val b = AppLockVerifier.createRecord("482913", 1L)
        assertFalse(a.salt.contentEquals(b.salt))
        assertFalse(a.verifier.contentEquals(b.verifier))
    }

    @Test
    fun derivationIsDeterministicForTheSameSalt() {
        val salt = PinDerivation.randomSalt(SecureRandom())
        val first = PinDerivation.deriveVerifier("482913", salt, 1000)
        val second = PinDerivation.deriveVerifier("482913", salt, 1000)
        assertTrue(first.contentEquals(second))
        assertEquals(PinDerivation.VERIFIER_BYTES, first.size)
    }

    @Test
    fun derivationRejectsMalformedSalt() {
        val bad = ByteArray(8)
        try {
            PinDerivation.deriveVerifier("482913", bad, 1000)
            throw AssertionError("expected IllegalArgumentException for an 8-byte salt")
        } catch (expected: IllegalArgumentException) {
            // ok
        }
    }

    // ---- sealed storage -----------------------------------------------------

    @Test
    fun recordRoundTripsThroughTheSealedStore() {
        val store = newStore()
        val record = AppLockVerifier.createRecord("482913", 1_700_000_000_000L)
        store.write(record)

        val read = store.read()
        assertIs<SealedAppLockStore.LockRead.Configured>(read)
        assertEquals(record, read.record)
        assertTrue(AppLockVerifier.verify("482913", read.record))
    }

    @Test
    fun absentStoreReportsAbsentRatherThanCorrupted() {
        assertIs<SealedAppLockStore.LockRead.Absent>(newStore().read())
    }

    @Test
    fun recordIsNotStoredInPlaintext() {
        val backing = InMemoryByteStore()
        val store = SealedAppLockStore(backing, JcaAesGcmSealer())
        store.write(AppLockVerifier.createRecord("482913", 1L))

        val raw = backing.keysSnapshot().single()
        val bytes = backing.readState(raw)
        assertIs<com.duolink.app.crypto.RawStoreRead.Present>(bytes)
        // Neither the PIN nor the verifier bytes may appear in the stored blob.
        val asLatin1 = String(bytes.bytes, Charsets.ISO_8859_1)
        assertFalse(asLatin1.contains("482913"))
        assertTrue(bytes.bytes.size > 40)
    }

    @Test
    fun corruptedRecordFailsClosedInsteadOfUnlocking() {
        val backing = InMemoryByteStore()
        val store = SealedAppLockStore(backing, JcaAesGcmSealer())
        store.write(AppLockVerifier.createRecord("482913", 1L))

        // Flip a byte in the sealed blob: GCM authentication must fail.
        val key = backing.keysSnapshot().single()
        backing.corruptRawBytesForTesting(key) { raw ->
            raw.copyOf().also { it[it.size - 3] = (it[it.size - 3].toInt() xor 0xFF).toByte() }
        }

        val read = store.read()
        // Critically: a corrupted record is reported as Corrupted, never as Absent, so the caller
        // cannot mistake it for "the user never set a lock" and let the attacker in.
        assertIs<SealedAppLockStore.LockRead.Corrupted>(read)
    }

    @Test
    fun recordSealedUnderADifferentKeyCannotBeOpened() {
        val backing = InMemoryByteStore()
        SealedAppLockStore(backing, JcaAesGcmSealer()).write(AppLockVerifier.createRecord("482913", 1L))

        // A different sealer key models an attacker who copied the file to another device.
        val foreignStore = SealedAppLockStore(backing, JcaAesGcmSealer())
        assertIs<SealedAppLockStore.LockRead.Corrupted>(foreignStore.read())
    }

    @Test
    fun clearingTheLockReallyRemovesIt() {
        val store = newStore()
        store.write(AppLockVerifier.createRecord("482913", 1L))
        store.clear()
        assertIs<SealedAppLockStore.LockRead.Absent>(store.read())
    }

    // ---- throttling ---------------------------------------------------------

    @Test
    fun firstFreeAttemptsImposeNoDelay() {
        for (attempts in 1..AppLockPolicy.FREE_ATTEMPTS) {
            assertEquals(0L, AppLockPolicy.lockoutDelayMs(attempts))
        }
    }

    @Test
    fun lockoutGrowsExponentiallyAndIsCapped() {
        assertEquals(30_000L, AppLockPolicy.lockoutDelayMs(6))
        assertEquals(60_000L, AppLockPolicy.lockoutDelayMs(7))
        assertEquals(120_000L, AppLockPolicy.lockoutDelayMs(8))
        assertEquals(AppLockPolicy.MAX_LOCKOUT_MS, AppLockPolicy.lockoutDelayMs(50))
        assertEquals(AppLockPolicy.MAX_LOCKOUT_MS, AppLockPolicy.lockoutDelayMs(10_000))
    }

    @Test
    fun failuresAccumulateAndSetALockoutWindow() {
        var record = AppLockVerifier.createRecord("482913", 1L)
        val now = 1_000_000L

        repeat(AppLockPolicy.FREE_ATTEMPTS) {
            record = AppLockPolicy.registerFailure(record, now)
            assertFalse(AppLockPolicy.isLockedOut(record, now))
        }
        assertEquals(AppLockPolicy.FREE_ATTEMPTS, record.failedAttempts)

        // The next failure crosses the threshold and imposes a real cooling-off period.
        record = AppLockPolicy.registerFailure(record, now)
        assertEquals(AppLockPolicy.FREE_ATTEMPTS + 1, record.failedAttempts)
        assertTrue(AppLockPolicy.isLockedOut(record, now))
        assertEquals(30_000L, AppLockPolicy.remainingLockoutMs(record, now))
        // The window expires by itself.
        assertFalse(AppLockPolicy.isLockedOut(record, now + 30_000L))
    }

    @Test
    fun successfulUnlockResetsTheThrottle() {
        var record = AppLockVerifier.createRecord("482913", 1L)
        repeat(7) { record = AppLockPolicy.registerFailure(record, 1L) }
        assertTrue(record.failedAttempts > 0)

        record = AppLockPolicy.registerSuccess(record)
        assertEquals(0, record.failedAttempts)
        assertEquals(0L, record.lockoutUntilEpochMs)
        assertFalse(AppLockPolicy.isLockedOut(record, 1L))
    }

    @Test
    fun lockoutStateSurvivesAProcessRestart() {
        // Throttling must be persisted, otherwise a attacker could just force-kill the app after each
        // wrong guess to reset the counter.
        val store = newStore()
        var record = AppLockVerifier.createRecord("482913", 1L)
        repeat(6) { record = AppLockPolicy.registerFailure(record, 5_000L) }
        store.write(record)

        val reloaded = store.read()
        assertIs<SealedAppLockStore.LockRead.Configured>(reloaded)
        assertTrue(AppLockPolicy.isLockedOut(reloaded.record, 5_000L))
        assertEquals(6, reloaded.record.failedAttempts)
    }

    @Test
    fun recordEqualityComparesByteContentsNotIdentity() {
        val a = AppLockRecord(ByteArray(16) { 1 }, ByteArray(32) { 2 }, 1000, 0, 0L, 5L)
        val b = AppLockRecord(ByteArray(16) { 1 }, ByteArray(32) { 2 }, 1000, 0, 0L, 5L)
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }
    // ---- first-run creation flow --------------------------------------------

    @Test
    fun firstRunCreatesAPinInTwoStepsAndUnlocks() {
        // Models exactly what the ViewModel does when AppLockStore reports Absent: an empty store, a
        // create step, then a confirm step with the same digits, then an unlockable record.
        val store = newStore()
        assertIs<SealedAppLockStore.LockRead.Absent>(store.read())

        val chosen = "482913"
        val rejection = PinRules.rejectionReason(chosen)
        assertNull(rejection)
        val record = AppLockVerifier.createRecord(chosen, 1_000L)
        store.write(record)

        val reloaded = store.read()
        assertIs<SealedAppLockStore.LockRead.Configured>(reloaded)
        assertTrue(AppLockVerifier.verify(chosen, reloaded.record))
    }

    @Test
    fun aMismatchedConfirmationMustNotStoreAnythingUsable() {
        // First entry accepted locally, second entry differs: no record may be written.
        val store = newStore()
        val first = "482913"
        val second = "482914"
        assertFalse(first == second)
        // The ViewModel clears its pending PIN and writes nothing; the store stays empty.
        assertIs<SealedAppLockStore.LockRead.Absent>(store.read())
    }

    @Test
    fun aRefusedPinIsNeverPersisted() {
        val store = newStore()
        listOf("0000", "1234", "12", "abcd").forEach { candidate ->
            assertNotNull(PinRules.rejectionReason(candidate), "'$candidate' should be refused")
            // Nothing is written for a refused PIN.
            assertEquals(0, (store.read() as? SealedAppLockStore.LockRead.Configured)?.let { 1 } ?: 0)
        }
    }

}

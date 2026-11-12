package com.duolink.app.lock

import com.duolink.app.crypto.ByteEncoding
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Password-based key derivation parameters for the PIN gate.
 *
 * Why PBKDF2-HMAC-SHA256 with a random per-device salt rather than a plain hash:
 * a 6-digit PIN has only 10^6 possibilities, so *any* unsalted fast hash can be brute-forced in
 * milliseconds from a copy of the file. PBKDF2 with a high iteration count plus a 16-byte random salt
 * makes an offline attack against the stored verifier cost real work, and makes precomputed tables
 * useless because each device has its own salt.
 *
 * Honest limitation, stated on purpose and never papered over in the UI:
 * PBKDF2 raises the cost of an offline attack but cannot make a 6-digit PIN *strong*. The real
 * protection against someone who has the unlocked device's storage is the Android Keystore-bound
 * AES-256-GCM sealer that encrypts the whole lock record — the PIN verifier is a second layer, not
 * the only one. A 6-digit PIN also cannot resist a targeted shoulder-surf against a known device
 * owner. This is why the lock is described to the user as a local privacy gate, not as
 * "military-grade encryption of your messages".
 */
object PinDerivation {
    /** PBKDF2 iterations. Chosen to stay under ~250 ms on a low-end API 26 phone. */
    const val ITERATIONS = 120_000

    /** Length of the random per-device salt in bytes. */
    const val SALT_BYTES = 16

    /** Length of the derived verifier in bytes. */
    const val VERIFIER_BYTES = 32

    /** Minimum and maximum accepted PIN lengths (digits only). */
    const val MIN_PIN_LENGTH = 4
    const val MAX_PIN_LENGTH = 12

    /**
     * Derives the PIN verifier.
     *
     * [pin] is the raw digit string; [salt] must be the per-device random salt.
     * The result is a 32-byte PBKDF2-HMAC-SHA256 output.
     */
    fun deriveVerifier(pin: String, salt: ByteArray, iterations: Int = ITERATIONS): ByteArray {
        require(salt.size == SALT_BYTES) { "salt must be $SALT_BYTES bytes" }
        require(iterations > 0) { "iterations must be positive" }
        val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, VERIFIER_BYTES * 8)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            // Zero the intermediate char[] copy so the PIN does not linger in the heap.
            spec.clearPassword()
        }
    }

    /** Constant-time comparison, so a wrong PIN cannot be recovered via timing. */
    fun verifierMatches(expected: ByteArray, actual: ByteArray): Boolean =
        MessageDigest.isEqual(expected, actual)

    fun randomSalt(random: SecureRandom = SecureRandom()): ByteArray =
        ByteArray(SALT_BYTES).also { random.nextBytes(it) }
}

/**
 * Validation rules for a PIN. Kept separate from the storage layer so the rules can be unit-tested
 * without touching the Android Keystore.
 */
object PinRules {
    /**
     * Rejects PINs that an attacker (or a person looking over a shoulder) would guess first.
     *
     * Returns a Persian message describing *why* the PIN was refused, or `null` when it is acceptable.
     * Rules, in order:
     *  1. length must be within [PinDerivation.MIN_PIN_LENGTH]..[PinDerivation.MAX_PIN_LENGTH]
     *  2. only ASCII digits
     *  3. not a single repeated digit (0000, 1111, ...)
     *  4. not a straight ascending or descending run (1234, 4321, 0123456789, ...)
     */
    fun rejectionReason(pin: String): String? {
        if (pin.length < PinDerivation.MIN_PIN_LENGTH || pin.length > PinDerivation.MAX_PIN_LENGTH) {
            return "طول رمز باید بین ${PinDerivation.MIN_PIN_LENGTH} تا ${PinDerivation.MAX_PIN_LENGTH} رقم باشد."
        }
        if (!pin.all { it in '0'..'9' }) {
            return "رمز فقط می‌تواند شامل رقم باشد."
        }
        if (pin.all { it == pin[0] }) {
            return "رمز نباید از یک رقم تکراری تشکیل شده باشد."
        }
        val ascending = pin.zipWithNext().all { (a, b) -> b - a == 1 }
        val descending = pin.zipWithNext().all { (a, b) -> a - b == 1 }
        if (ascending || descending) {
            return "رمز نباید دنبالهٔ پشت‌سرهم اعداد باشد."
        }
        return null
    }

    fun isValid(pin: String): Boolean = rejectionReason(pin) == null

    /**
     * Length + digits only, skipping the "too guessable" heuristics.
     *
     * Used when *verifying* an existing PIN: a user whose (older) PIN happens to look sequential must
     * still be able to unlock. The guessability rules apply only when choosing a new PIN.
     */
    fun isValidFormatOnly(pin: String): Boolean =
        pin.length in PinDerivation.MIN_PIN_LENGTH..PinDerivation.MAX_PIN_LENGTH &&
            pin.all { it in '0'..'9' }
}

/**
 * Persisted lock configuration.
 *
 * [failedAttempts] and [lockoutUntilEpochMs] implement progressive throttling: after
 * [AppLockPolicy.FREE_ATTEMPTS] wrong PINs the gate starts imposing a cooling-off period that grows
 * with every further failure. This is a real mitigation against someone tapping guesses on a stolen
 * unlocked phone; it is not a defence against an attacker with the device's storage, who would attack
 * the verifier offline instead (which is what PBKDF2 is for).
 */
data class AppLockRecord(
    val salt: ByteArray,
    val verifier: ByteArray,
    val iterations: Int,
    val failedAttempts: Int,
    val lockoutUntilEpochMs: Long,
    val createdAtEpochMs: Long
) {
    // data class with ByteArray needs explicit equals/hashCode that compares contents,
    // otherwise two records with identical bytes would compare unequal.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AppLockRecord) return false
        return ByteEncoding.constantTimeEquals(salt, other.salt) &&
            ByteEncoding.constantTimeEquals(verifier, other.verifier) &&
            iterations == other.iterations &&
            failedAttempts == other.failedAttempts &&
            lockoutUntilEpochMs == other.lockoutUntilEpochMs &&
            createdAtEpochMs == other.createdAtEpochMs
    }

    override fun hashCode(): Int {
        var result = salt.contentHashCode()
        result = 31 * result + verifier.contentHashCode()
        result = 31 * result + iterations
        result = 31 * result + failedAttempts.hashCode()
        result = 31 * result + lockoutUntilEpochMs.hashCode()
        result = 31 * result + createdAtEpochMs.hashCode()
        return result
    }
}

/**
 * Pure, deterministic lock policy: attempt counting and lockout scheduling.
 *
 * Deliberately free of Android and clock dependencies so it can be exhaustively unit-tested.
 */
object AppLockPolicy {
    /** Wrong attempts tolerated before any cooling-off period is imposed. */
    const val FREE_ATTEMPTS = 5

    /** Cooling-off base. Doubles with each attempt beyond the free allowance. */
    const val BASE_LOCKOUT_MS = 30_000L

    /** Cap so a user is never locked out for an unreasonable amount of time. */
    const val MAX_LOCKOUT_MS = 15 * 60_000L

    /** How long an unlocked session remains valid before the gate re-arms. */
    const val AUTO_LOCK_AFTER_MS = 60_000L

    /**
     * Delay to impose after the given number of consecutive failures.
     *
     * 0..[FREE_ATTEMPTS] => no delay. Each subsequent failure doubles the delay, capped at
     * [MAX_LOCKOUT_MS]. Example with the defaults: attempt 6 -> 30 s, 7 -> 60 s, 8 -> 120 s, ...
     */
    fun lockoutDelayMs(failedAttempts: Int): Long {
        if (failedAttempts <= FREE_ATTEMPTS) return 0L
        val exponent = (failedAttempts - FREE_ATTEMPTS - 1).coerceIn(0, 20)
        val delay = BASE_LOCKOUT_MS shl exponent
        return if (delay <= 0L) MAX_LOCKOUT_MS else minOf(delay, MAX_LOCKOUT_MS)
    }

    /** True when the user must wait before another attempt is even evaluated. */
    fun isLockedOut(record: AppLockRecord, nowEpochMs: Long): Boolean =
        nowEpochMs < record.lockoutUntilEpochMs

    /** Remaining wait in milliseconds, or 0 when not locked out. */
    fun remainingLockoutMs(record: AppLockRecord, nowEpochMs: Long): Long =
        (record.lockoutUntilEpochMs - nowEpochMs).coerceAtLeast(0L)

    /**
     * Applies one wrong attempt. Returns the updated record, with the failure count incremented and a
     * lockout window set when the free allowance is exhausted.
     */
    fun registerFailure(record: AppLockRecord, nowEpochMs: Long): AppLockRecord {
        val attempts = record.failedAttempts + 1
        val delay = lockoutDelayMs(attempts)
        return record.copy(
            failedAttempts = attempts,
            lockoutUntilEpochMs = if (delay > 0L) nowEpochMs + delay else record.lockoutUntilEpochMs
        )
    }

    /** Applies a successful unlock: the failure counter and lockout are cleared. */
    fun registerSuccess(record: AppLockRecord): AppLockRecord =
        record.copy(failedAttempts = 0, lockoutUntilEpochMs = 0L)
}

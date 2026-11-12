package com.duolink.app.lock

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.StorageSealer
import com.duolink.app.crypto.zeroize

/**
 * Persists the app-lock record as an AES-256-GCM sealed blob.
 *
 * The record (salt + PBKDF2 verifier + attempt counters) is never written in the clear, and the
 * associated data binds it to this app and this record version. Sealing means that a copy of the file
 * taken from the device storage cannot even be *read* without the Keystore key, so an attacker cannot
 * run an offline PBKDF2 attack against the verifier without first defeating the Keystore boundary.
 * That composition — Keystore-wrapped ciphertext *containing* a salted, iterated verifier — is what
 * makes the offline attack window small; the PIN alone is not the defence.
 *
 * Storage layout (inside the sealed plaintext):
 * `[version = 0x01][iterations int32][saltLen 1][salt][verifierLen 1][verifier][failedAttempts int32][lockoutUntil int64][createdAt int64]`
 */
class SealedAppLockStore(
    private val store: KeyValueByteStore,
    private val sealer: StorageSealer
) {
    /**
     * Reads the lock configuration.
     *
     *  - [LockRead.Absent]      no lock has been configured yet (first run, or the user removed it).
     *  - [LockRead.Configured]  a usable lock record.
     *  - [LockRead.Corrupted]   the blob exists but cannot be authenticated or decoded.
     *
     * Corruption is a *fail-closed* state: the caller must not silently treat it as "no lock",
     * because that would let an attacker who damaged the file remove the lock. The UI offers an
     * explicit, user-confirmed recovery instead.
     */
    sealed class LockRead {
        object Absent : LockRead()
        data class Configured(val record: AppLockRecord) : LockRead()
        data class Corrupted(val detail: String) : LockRead()
    }

    fun read(): LockRead = when (val raw = store.readState(KEY)) {
        is RawStoreRead.Present -> decode(raw.bytes)
        is RawStoreRead.CorruptedIo -> LockRead.Corrupted(raw.detail)
        is RawStoreRead.Missing -> LockRead.Absent
    }

    fun write(record: AppLockRecord) {
        store.write(KEY, sealer.seal(encode(record), ASSOCIATED_DATA))
    }

    fun clear() {
        store.delete(KEY)
    }

    private fun decode(sealed: ByteArray): LockRead {
        val plain = try {
            sealer.unseal(sealed, ASSOCIATED_DATA)
        } catch (t: Throwable) {
            return LockRead.Corrupted("unseal_failed:${t.javaClass.simpleName}")
        }
        return try {
            LockRead.Configured(decodePlaintext(plain))
        } catch (t: Throwable) {
            LockRead.Corrupted("decode_failed:${t.javaClass.simpleName}")
        } finally {
            plain.zeroize()
        }
    }

    private fun encode(record: AppLockRecord): ByteArray {
        require(record.salt.size <= 255) { "salt too long" }
        require(record.verifier.size <= 255) { "verifier too long" }
        val out = java.io.ByteArrayOutputStream()
        out.write(VERSION.toInt())
        writeInt(out, record.iterations)
        out.write(record.salt.size)
        out.write(record.salt)
        out.write(record.verifier.size)
        out.write(record.verifier)
        writeInt(out, record.failedAttempts)
        writeLong(out, record.lockoutUntilEpochMs)
        writeLong(out, record.createdAtEpochMs)
        return out.toByteArray()
    }

    private fun decodePlaintext(plain: ByteArray): AppLockRecord {
        val input = java.io.ByteArrayInputStream(plain)
        val version = input.read()
        require(version == VERSION.toInt()) { "unsupported lock record version $version" }
        val iterations = readInt(input)
        require(iterations > 0) { "invalid iterations" }
        val saltLen = input.read()
        require(saltLen in 1..64) { "invalid salt length" }
        val salt = readFully(input, saltLen)
        val verifierLen = input.read()
        require(verifierLen in 1..64) { "invalid verifier length" }
        val verifier = readFully(input, verifierLen)
        val failedAttempts = readInt(input)
        require(failedAttempts >= 0) { "invalid failedAttempts" }
        val lockoutUntil = readLong(input)
        val createdAt = readLong(input)
        require(input.available() == 0) { "trailing bytes in lock record" }
        return AppLockRecord(
            salt = salt,
            verifier = verifier,
            iterations = iterations,
            failedAttempts = failedAttempts,
            lockoutUntilEpochMs = lockoutUntil,
            createdAtEpochMs = createdAt
        )
    }

    private fun writeInt(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write(byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte()
        ))
    }

    private fun writeLong(out: java.io.ByteArrayOutputStream, value: Long) {
        out.write(ByteArray(8) { i -> (value ushr (56 - 8 * i)).toByte() })
    }

    private fun readInt(input: java.io.ByteArrayInputStream): Int {
        val b = readFully(input, 4)
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun readLong(input: java.io.ByteArrayInputStream): Long {
        var value = 0L
        readFully(input, 8).forEach { value = (value shl 8) or (it.toLong() and 0xFF) }
        return value
    }

    private fun readFully(input: java.io.ByteArrayInputStream, count: Int): ByteArray {
        val buffer = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(buffer, offset, count - offset)
            require(read > 0) { "truncated lock record" }
            offset += read
        }
        return buffer
    }

    companion object {
        const val KEY = "duolink.applock.v1"
        private const val VERSION: Byte = 0x01
        private val ASSOCIATED_DATA =
            "DuoLink-AppLock-Record-v1".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Verifies a PIN against a record. Pure function over the record so tests can exercise the
 * accept/reject path without Android.
 */
object AppLockVerifier {
    /**
     * Checks [pin] against [record].
     *
     * Does *not* mutate throttling state — the caller decides what to persist, so that a wrong PIN
     * followed by a process kill still counts the attempt.
     */
    fun verify(pin: String, record: AppLockRecord): Boolean {
        if (!PinRules.isValidFormatOnly(pin)) return false
        val candidate = PinDerivation.deriveVerifier(pin, record.salt, record.iterations)
        return try {
            PinDerivation.verifierMatches(record.verifier, candidate)
        } finally {
            candidate.zeroize()
        }
    }

    /** Builds a fresh record for [pin]. */
    fun createRecord(pin: String, nowEpochMs: Long): AppLockRecord {
        val salt = PinDerivation.randomSalt()
        val verifier = PinDerivation.deriveVerifier(pin, salt, PinDerivation.ITERATIONS)
        return AppLockRecord(
            salt = salt,
            verifier = verifier,
            iterations = PinDerivation.ITERATIONS,
            failedAttempts = 0,
            lockoutUntilEpochMs = 0L,
            createdAtEpochMs = nowEpochMs
        )
    }
}

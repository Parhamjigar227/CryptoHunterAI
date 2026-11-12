package com.duolink.app.media

import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.RawStoreRead
import com.duolink.app.crypto.StorageSealer
import java.security.SecureRandom

/**
 * Owns the AES-256 master key that seals attachments, and keeps that key itself sealed at rest under
 * the Keystore-backed [StorageSealer].
 *
 * Two-layer design, on purpose:
 *  `Keystore key (non-exportable, hardware if available)` wraps `media master key` wraps `attachment`.
 *
 * The attachment master key has to be a raw AES key because it must be usable for bulk GCM; it cannot
 * itself live in the Keystore and still be same-key-every-file with a deterministic content address.
 * So it is generated once, sealed under the Keystore key, and only unsealed into memory when an
 * attachment is being read or written. On a device with a TEE/StrongBox, an attacker who extracts the
 * storage cannot unwrap it.
 *
 * Rotation/limit note: the key is never stored in plaintext, never logged, and never leaves the device.
 * If the sealed blob is corrupted the vault fails closed and reports it — it does not generate a new key
 * silently, because that would make every existing attachment unreadable while appearing to work.
 */
class MediaKeyManager(
    private val store: KeyValueByteStore,
    private val sealer: StorageSealer,
    private val random: SecureRandom = SecureRandom()
) {
    sealed class KeyState {
        data class Ready(val masterKey: ByteArray) : KeyState()
        object NotInitialised : KeyState()
        data class Corrupted(val detail: String) : KeyState()
    }

    /** Reads the sealed master key, creating one on genuine first use. */
    fun obtainOrCreate(): KeyState = when (val raw = store.readState(KEY)) {
        is RawStoreRead.Present -> {
            try {
                val master = sealer.unseal(raw.bytes, ASSOCIATED_DATA)
                if (master.size != KEY_BYTES) {
                    KeyState.Corrupted("unexpected key length ${master.size}")
                } else {
                    KeyState.Ready(master)
                }
            } catch (t: Throwable) {
                KeyState.Corrupted("unseal_failed:${t.javaClass.simpleName}")
            }
        }
        is RawStoreRead.CorruptedIo -> KeyState.Corrupted(raw.detail)
        is RawStoreRead.Missing -> {
            val fresh = ByteArray(KEY_BYTES).also { random.nextBytes(it) }
            store.write(KEY, sealer.seal(fresh, ASSOCIATED_DATA))
            KeyState.Ready(fresh)
        }
    }

    /** Explicit, user-initiated reset. Destroys readability of every existing attachment on purpose. */
    fun destroyAllAccess() {
        store.delete(KEY)
    }

    companion object {
        const val KEY = "duolink.media.master.v1"
        const val KEY_BYTES = 32
        private val ASSOCIATED_DATA = "DuoLink-Media-Key-v1".toByteArray(Charsets.UTF_8)
    }
}

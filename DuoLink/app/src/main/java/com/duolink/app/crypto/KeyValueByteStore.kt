package com.duolink.app.crypto

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Tri-state raw byte read result so filesystem corruption, zero-byte truncation, or I/O errors
 * can never be conflated with a genuinely absent record.
 */
sealed class RawStoreRead {
    data object Missing : RawStoreRead()
    data class Present(val bytes: ByteArray) : RawStoreRead()
    data class CorruptedIo(val detail: String) : RawStoreRead()
}

/**
 * Persistence interface for sealed cryptographic & trust blobs.
 */
interface KeyValueByteStore {
    fun readState(key: String): RawStoreRead
    fun write(key: String, bytes: ByteArray)
    fun delete(key: String)
}

/**
 * Crash-safe directory-backed store inside app-private `Context.filesDir` (`allowBackup="false"`).
 *
 * Durability & atomicity guarantees:
 * 1. Writes go to `<name>.tmp`, flush Java buffers, invoke `FileDescriptor.sync()` (`fsync`) to commit
 *    file blocks before updating directory metadata, and replace `<name>` via POSIX `ATOMIC_MOVE`.
 * 2. Never falls back to truncating `<name>` in-place.
 * 3. Orphaned `<name>.tmp` files from an interrupted write are cleaned up on next read without touching
 *    any committed `<name>` file.
 * 4. Zero-byte regular files or unreadable entries return [RawStoreRead.CorruptedIo], never [RawStoreRead.Missing].
 */
class DirectoryFileByteStore(private val directory: File) : KeyValueByteStore {

    init {
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("Unable to create security store directory: ${directory.absolutePath}")
        }
    }

    @Synchronized
    override fun readState(key: String): RawStoreRead {
        val target = fileFor(key)
        val tmp = tempFileFor(target)
        if (tmp.exists()) {
            // An earlier write crashed before ATOMIC_MOVE committed; remove the uncommitted temp file.
            tmp.delete()
        }
        if (!target.exists()) {
            return RawStoreRead.Missing
        }
        if (!target.isFile) {
            return RawStoreRead.CorruptedIo("Security store entry is not a regular file: ${target.name}")
        }
        return try {
            val bytes = Files.readAllBytes(target.toPath())
            if (bytes.isEmpty()) {
                RawStoreRead.CorruptedIo("Zero-byte truncated security store entry: ${target.name}")
            } else {
                RawStoreRead.Present(bytes)
            }
        } catch (e: IOException) {
            RawStoreRead.CorruptedIo("I/O error reading ${target.name}: ${e.message ?: "unknown"}")
        }
    }

    @Synchronized
    override fun write(key: String, bytes: ByteArray) {
        require(bytes.isNotEmpty()) { "Refusing to write empty security record for key '$key'" }
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("Security store directory missing: ${directory.absolutePath}")
        }
        val target = fileFor(key)
        val tmp = tempFileFor(target)

        FileOutputStream(tmp).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }

        try {
            Files.move(
                tmp.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(
                tmp.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING
            )
        }

        fsyncDirectoryBestEffort()
    }

    @Synchronized
    override fun delete(key: String) {
        val target = fileFor(key)
        val tmp = tempFileFor(target)
        Files.deleteIfExists(tmp.toPath())
        Files.deleteIfExists(target.toPath())
        fsyncDirectoryBestEffort()
    }

    private fun fileFor(key: String): File {
        require(key.isNotBlank()) { "Store key must not be blank" }
        val safeName = key.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        return File(directory, "$safeName.bin")
    }

    private fun tempFileFor(target: File): File = File(directory, "${target.name}.tmp")

    private fun fsyncDirectoryBestEffort() {
        try {
            FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { channel ->
                channel.force(true)
            }
        } catch (_: Exception) {
            // Directory FileChannel.open(READ) is supported on Linux/Android ext4/f2fs; ignore if unsupported.
        }
    }
}

/**
 * In-memory [KeyValueByteStore] for deterministic unit testing (including simulated corruption injection).
 */
class InMemoryByteStore : KeyValueByteStore {
    private val map = LinkedHashMap<String, ByteArray>()
    private val forcedIoCorruptions = HashSet<String>()

    @Synchronized
    override fun readState(key: String): RawStoreRead {
        if (forcedIoCorruptions.contains(key)) {
            return RawStoreRead.CorruptedIo("Simulated I/O corruption for '$key'")
        }
        val value = map[key] ?: return RawStoreRead.Missing
        if (value.isEmpty()) {
            return RawStoreRead.CorruptedIo("Zero-byte entry for '$key'")
        }
        return RawStoreRead.Present(value.copyOf())
    }

    @Synchronized
    override fun write(key: String, bytes: ByteArray) {
        require(bytes.isNotEmpty()) { "Refusing to write empty security record for key '$key'" }
        forcedIoCorruptions.remove(key)
        map[key] = bytes.copyOf()
    }

    @Synchronized
    override fun delete(key: String) {
        forcedIoCorruptions.remove(key)
        map.remove(key)
    }

    @Synchronized
    fun corruptRawBytesForTesting(key: String, mutator: (ByteArray) -> ByteArray) {
        val existing = map[key] ?: error("Key '$key' does not exist in store")
        map[key] = mutator(existing.copyOf())
    }

    @Synchronized
    fun writeZeroByteEntryForTesting(key: String) {
        map[key] = ByteArray(0)
    }

    @Synchronized
    fun keysSnapshot(): Set<String> = map.keys.toSet()
}

package com.duolink.app

import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.crypto.DeviceKeyVault
import com.duolink.app.crypto.JcaAesGcmSealer
import com.duolink.app.crypto.KeyValueByteStore
import com.duolink.app.crypto.InMemoryByteStore
import com.duolink.app.pairing.PeerTrustStore
import com.duolink.app.crypto.SealedSoftwareKeyVault
import com.duolink.app.remote.RemotePairingCoordinator
import com.duolink.app.remote.RemotePendingSessionStore
import java.security.KeyPair
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * Shared fixtures for the Method B tests: a real sealed key vault, a real trust store, and a real
 * session-scoped ACK key provider.
 *
 * Nothing here stubs cryptography. The vault is [SealedSoftwareKeyVault] (the same implementation the
 * JVM regression suite uses, with the same SPK metadata codec as the Android Keystore vault), the trust
 * store is the production [PeerTrustStore], and ACK keys are genuine P-256 pairs. That matters because
 * the point of these tests is to catch integration mistakes between real components - a mock that
 * "signs" with a constant would happily agree with itself while the real device pair disagreed.
 */
object RemotePairingTestHarness {

    /**
     * Session-scoped ACK key provider, which the production code required but never had an
     * implementation of.
     *
     * The ACK key is deliberately NOT the long-term identity key: it is regenerated per invitation and
     * signs the final mutual receipt, so compromising it after a pairing completes does not let an
     * attacker forge receipts for that pairing. [rotateAckKey] is called whenever a new invitation starts.
     */
    class TestAckKeyProvider(
        private val secureRandom: SecureRandom = SecureRandom()
    ) : RemotePairingCoordinator.LocalAckKeyProvider {

        private var keyPair: KeyPair = EcP256Crypto.generateSoftwareP256KeyPair(secureRandom)
        private val rotations = AtomicInteger(0)

        override fun currentAckPublicSpki(): ByteArray =
            keyPair.public.encoded

        override fun signAck(transcript: ByteArray): ByteArray? =
            runCatching { EcP256Crypto.signSha256Ecdsa(keyPair.private, transcript) }.getOrNull()

        override fun rotateAckKey() {
            keyPair = EcP256Crypto.generateSoftwareP256KeyPair(secureRandom)
            rotations.incrementAndGet()
        }

        override val isHardwareBacked: Boolean get() = false

        /** How many times the key has been rotated, so a test can assert rotation actually happens. */
        fun rotationCount(): Int = rotations.get()
    }

    /** One simulated phone: real vault, real trust store, real ACK keys, real coordinator. */
    class SimulatedDevice(
        val byteStore: KeyValueByteStore = InMemoryByteStore(),
        val secureRandom: SecureRandom = SecureRandom(),
        nowEpochSec: () -> Long = { System.currentTimeMillis() / 1000L }
    ) {
        private val sealer = JcaAesGcmSealer(secureRandom = secureRandom)
        val vault: DeviceKeyVault = SealedSoftwareKeyVault(
            sealer = sealer,
            byteStore = byteStore,
            secureRandom = secureRandom
        )
        val trustStore = PeerTrustStore(store = byteStore, sealer = sealer)
        val pendingStore = RemotePendingSessionStore(store = byteStore, sealer = sealer)
        val ackKeys = TestAckKeyProvider(secureRandom)
        val coordinator = RemotePairingCoordinator(
            keyVault = vault,
            trustStore = trustStore,
            pendingStore = pendingStore,
            localAckKeyProvider = ackKeys,
            secureRandom = secureRandom,
            nowEpochSec = nowEpochSec
        )

        fun destroy() = coordinator.destroy()
    }

    /** Deterministic SecureRandom so failures are reproducible: SHA-1 counter mode over a fixed seed. */
    fun deterministicRandom(seed: Long): SecureRandom =
        SecureRandom.getInstance("SHA1PRNG").apply {
            setSeed(seed)
        }
}

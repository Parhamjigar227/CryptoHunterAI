package com.duolink.app

import com.duolink.app.crypto.EcP256Crypto
import com.duolink.app.remote.ActivationCodeDigest
import com.duolink.app.remote.RemoteTranscripts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Proves the owner's signed invitation transcript is *verifiable by the joining device* and that a
 * forged or tampered invitation is rejected.
 *
 * Background: until this test was added, `redeemInvitation` verified only the owner's SPK
 * self-signature. That proves nothing about identity, because whoever supplies the identity key can
 * also supply a matching self-signature. A malicious signalling server could therefore mint an
 * invitation with keys of its own choosing and the recipient would pair with it happily.
 *
 * The fix relies on `ActivationCodeDigest.sha256` being a *plain* SHA-256 (never the server's
 * peppered storage hash), because the joiner must recompute the value to rebuild the transcript.
 * See the long note on that function: the design anticipated this check; it was simply never wired up.
 *
 * The vectors below were produced by `node:crypto` against `server/src/protocol.js`
 * `invitationTranscript()` with a real P-256 owner key, then frozen here. Signing is randomised, so
 * the signature cannot be regenerated on demand -- these are fixed test vectors, not a snapshot.
 */
class OwnerInvitationSignatureTest {

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { i -> value.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private val transcriptHex = "44554f4c494e4b2d52454d4f54452d494e564954452d51522d56310000000100000016696e765f6f776e65725f7369675f303030303030"
            + "303100000020611007bc5ddb5ca3e7e7aaac3da1e211d783ef635358117bf5c1b2f0de1dcba1000000100ce23597c9d32528e552340f25"
            + "318e8600000007000000006553f100000000483046022100e1016a7440c1d1c3891b7fa999e5750247403257b9f45106961433515bac89"
            + "da022100cde0fa2953373b85bba80ff2be28bd548b4e2751926868f149b16da0ec45ecff0000005b3059301306072a8648ce3d02010608"
            + "2a8648ce3d030107034200045471304f1e30edf37b6eb689d16d178868ddc82d564a3af1b6ba5c3b451ef8fe80bfec0753de07b770973f"
            + "4482f5cbb9b8295621537eb2601fbe2434ead49b960000005b3059301306072a8648ce3d020106082a8648ce3d03010703420004954c6c"
            + "4fb622127f141cf316d368bb7ea58596788522f6fe3aad3e6c1248ad22852aafe39fd5019b499feca3fece0467f3ed97f86cc009ad7fe5"
            + "961e8267565f0000005b3059301306072a8648ce3d020106082a8648ce3d03010703420004bb6ebcff2a051222f80f0de24d1fe241c6cb"
            + "899da51b96981e8f2162807d9b1efc88b107c6b31dbaad799eee91036d63e5ad4b79d95321f6a9b0234b51eb42ef0000005b3059301306"
            + "072a8648ce3d020106082a8648ce3d03010703420004b7fbf5fe644e485f9e26348d37434ed43551f9ca9b74668b446581ee8a20e41d92"
            + "53504cc19b972eeab308c94dc6cda9615ba1a9038fa91961599015ca2f11df000000109999999999999999999999999999999900000000"
            + "6553f358"
    private val ownerSignature = hex("304502204afb7410ea88df2d2588d2116e2c3d633dfce4dbe5f695060840c6ed40847b2d022100fbf709bf54bdcd368a6599b56b671f8b"
            + "bf737f6351ba4b829e1275c29eaaf3ff")
    private val identitySpki = hex("3059301306072a8648ce3d020106082a8648ce3d030107034200045471304f1e30edf37b6eb689d16d178868ddc82d564a3af1b6ba5c3b"
            + "451ef8fe80bfec0753de07b770973f4482f5cbb9b8295621537eb2601fbe2434ead49b96")
    private val ackSpki = hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004954c6c4fb622127f141cf316d368bb7ea58596788522f6fe3aad3e6c"
            + "1248ad22852aafe39fd5019b499feca3fece0467f3ed97f86cc009ad7fe5961e8267565f")
    private val spkSpki = hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004bb6ebcff2a051222f80f0de24d1fe241c6cb899da51b96981e8f2162"
            + "807d9b1efc88b107c6b31dbaad799eee91036d63e5ad4b79d95321f6a9b0234b51eb42ef")
    private val ephemeralSpki = hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004b7fbf5fe644e485f9e26348d37434ed43551f9ca9b74668b446581ee"
            + "8a20e41d9253504cc19b972eeab308c94dc6cda9615ba1a9038fa91961599015ca2f11df")
    private val spkSignature = hex("3046022100e1016a7440c1d1c3891b7fa999e5750247403257b9f45106961433515bac89da022100cde0fa2953373b85bba80ff2be28bd"
            + "548b4e2751926868f149b16da0ec45ecff")
    private val deviceId = hex("0ce23597c9d32528e552340f25318e86")
    private val codeHash = hex("611007bc5ddb5ca3e7e7aaac3da1e211d783ef635358117bf5c1b2f0de1dcba1")

    @Test
    fun activationCodeDigestMatchesTheFrozenVector() {
        // Guards the joiner's ability to rebuild the transcript at all.
        assertEquals("611007bc5ddb5ca3e7e7aaac3da1e211d783ef635358117bf5c1b2f0de1dcba1", ActivationCodeDigest.sha256("ABCD-EFGH-JKMN-PQRS").joinToString("") { "%02x".format(it) })
    }

    @Test
    fun transcriptRebuiltByTheJoinerMatchesTheSignedBytes() {
        val rebuilt = RemoteTranscripts.invitationTranscript(
            invitationId = "inv_owner_sig_00000001",
            activationCodeHash = codeHash,
            deviceId = deviceId,
            spkId = 7,
            spkCreatedAtEpochSec = 1_700_000_000L,
            spkSignature = spkSignature,
            identityPublicSpki = identitySpki,
            ackPublicSpki = ackSpki,
            spkPublicSpki = spkSpki,
            ephemeralPublicSpki = ephemeralSpki,
            nonce = ByteArray(16) { 0x99.toByte() },
            expiresAtEpochSec = 1_700_000_600L
        )
        assertEquals(transcriptHex, rebuilt.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun genuineOwnerSignatureVerifies() {
        assertTrue(
            EcP256Crypto.verifySha256Ecdsa(identitySpki, hex(transcriptHex), ownerSignature)
        )
    }

    @Test
    fun tamperingWithAnyBoundFieldBreaksVerification() {
        fun verify(
            code: String = "ABCD-EFGH-JKMN-PQRS",
            expiry: Long = 1_700_000_600L,
            nonce: ByteArray = ByteArray(16) { 0x99.toByte() },
            ack: ByteArray = ackSpki,
            invitationId: String = "inv_owner_sig_00000001"
        ) = EcP256Crypto.verifySha256Ecdsa(
            identitySpki,
            RemoteTranscripts.invitationTranscript(
                invitationId = invitationId,
                activationCodeHash = ActivationCodeDigest.sha256(code),
                deviceId = deviceId,
                spkId = 7,
                spkCreatedAtEpochSec = 1_700_000_000L,
                spkSignature = spkSignature,
                identityPublicSpki = identitySpki,
                ackPublicSpki = ack,
                spkPublicSpki = spkSpki,
                ephemeralPublicSpki = ephemeralSpki,
                nonce = nonce,
                expiresAtEpochSec = expiry
            ),
            ownerSignature
        )

        assertTrue("baseline must verify", verify())
        assertFalse("swapped activation code", verify(code = "ZZZZ-ZZZZ-ZZZZ-ZZZZ"))
        assertFalse("expiry extended by one second", verify(expiry = 1_700_000_601L))
        assertFalse("nonce replaced", verify(nonce = ByteArray(16) { 0x11.toByte() }))
        assertFalse("ack key replaced", verify(ack = spkSpki))
        assertFalse("invitation id swapped", verify(invitationId = "inv_owner_sig_00000002"))
    }

    @Test
    fun forgedInvitationCannotVerifyAgainstTheRealOwnerKey() {
        // Simulates a malicious server: it controls the identity it *hands over*, so it can produce a
        // perfectly valid SPK self-signature -- but it cannot produce a signature that verifies
        // against the owner key the human actually holds out of band.
        val attackerSpki = spkSpki
        assertFalse(
            EcP256Crypto.verifySha256Ecdsa(attackerSpki, hex(transcriptHex), ownerSignature)
        )
    }
}

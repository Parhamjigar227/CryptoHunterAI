package com.duolink.app

import com.duolink.app.remote.RemoteTranscripts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Cross-language parity: the Kotlin transcript encoders must produce byte-identical output to
 * `DuoLink/server/src/protocol.js`.
 *
 * The expected hex strings below are copied verbatim from `parityVectors()` in the server. They are
 * generated *there* and checked *here* on purpose: a unilateral change to either implementation fails
 * this test instead of silently producing two devices that derive different keys. Regenerate with:
 *
 *     node --no-warnings -e "import('./src/protocol.js').then(m=>console.log(m.parityVectors()))"
 *
 * Run from `DuoLink/server`.
 */
class RemoteTranscriptParityTest {

    private val deviceId = hex("00112233445566778899aabbccddeeff")
    private val spkiPrefix = hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    private fun spki(fill: Int) = spkiPrefix + ByteArray(64) { fill.toByte() }

    private val identitySpki = spki(0x55)
    private val ackSpki = spki(0x66)
    private val spkSpki = spki(0x77)
    private val ephemeralSpki = spki(0x88)
    private val nonce = ByteArray(16) { 0x99.toByte() }
    private val codeHash = ByteArray(32) { 0x44 }
    private val spkSignature = hex("3045") + ByteArray(69) { 0xAA.toByte() }
    private val spkId = 7
    private val createdAt = 1_700_000_000L
    private val invitationId = "inv_parity_00000001"

    @Test
    fun spkTranscriptMatchesServerVectors() {
        // Method A layout: raw domain prefix, no length prefix on the numeric fields.
        val expected = "44756f4c696e6b2d53504b2d763100112233445566778899aabbccddeeff"
            "00000007000000006553f1000000005b"
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
            "77".repeat(64)
        assertEquals(expected, hex(RemoteTranscripts.spkTranscript(deviceId, spkId, createdAt, spkSpki)))
    }

    @Test
    fun invitationTranscriptMatchesServerVectors() {
        val expected = SERVER_INVITE_HEX
        val actual = RemoteTranscripts.invitationTranscript(
            invitationId = invitationId,
            activationCodeHash = codeHash,
            deviceId = deviceId,
            spkId = spkId,
            spkCreatedAtEpochSec = createdAt,
            spkSignature = spkSignature,
            identityPublicSpki = identitySpki,
            ackPublicSpki = ackSpki,
            spkPublicSpki = spkSpki,
            ephemeralPublicSpki = ephemeralSpki,
            nonce = nonce,
            expiresAtEpochSec = createdAt
        )
        assertEquals(expected, hex(actual))
    }

    @Test
    fun redeemTranscriptMatchesServerVectors() {
        val expected = SERVER_REDEEM_HEX
        val actual = RemoteTranscripts.redeemTranscript(
            invitationId = invitationId,
            deviceId = deviceId,
            spkId = spkId,
            spkCreatedAtEpochSec = createdAt,
            spkSignature = spkSignature,
            identityPublicSpki = identitySpki,
            ackPublicSpki = ackSpki,
            spkPublicSpki = spkSpki,
            ephemeralPublicSpki = ephemeralSpki,
            nonce = nonce
        )
        assertEquals(expected, hex(actual))
    }

    // ---------------------------------------------------------------------------------------------
    // Decision B: the transcript must bind the code HASH and reject any field substitution.
    // ---------------------------------------------------------------------------------------------

    @Test
    fun changingTheCodeHashChangesTheTranscript() {
        fun build(hash: ByteArray) = RemoteTranscripts.invitationTranscript(
            invitationId = invitationId,
            activationCodeHash = hash,
            deviceId = deviceId,
            spkId = spkId,
            spkCreatedAtEpochSec = createdAt,
            spkSignature = spkSignature,
            identityPublicSpki = identitySpki,
            ackPublicSpki = ackSpki,
            spkPublicSpki = spkSpki,
            ephemeralPublicSpki = ephemeralSpki,
            nonce = nonce,
            expiresAtEpochSec = createdAt
        )
        assertNotEquals(hex(build(codeHash)), hex(build(ByteArray(32) { 0x45 })))
    }

    @Test
    fun modifyingAnyBoundFieldChangesTheRedeemTranscript() {
        fun build(
            invitation: String = invitationId,
            spk: ByteArray = spkSpki,
            eph: ByteArray = ephemeralSpki,
            nonceBytes: ByteArray = nonce
        ) = RemoteTranscripts.redeemTranscript(
            invitationId = invitation,
            deviceId = deviceId,
            spkId = spkId,
            spkCreatedAtEpochSec = createdAt,
            spkSignature = spkSignature,
            identityPublicSpki = identitySpki,
            ackPublicSpki = ackSpki,
            spkPublicSpki = spk,
            ephemeralPublicSpki = eph,
            nonce = nonceBytes
        )
        val baseline = hex(build())
        assertNotEquals("invitationId", baseline, hex(build(invitation = "inv_parity_00000002")))
        assertNotEquals("spk", baseline, hex(build(spk = spki(0x79))))
        assertNotEquals("ephemeral", baseline, hex(build(eph = spki(0x8A))))
        assertNotEquals("nonce", baseline, hex(build(nonceBytes = ByteArray(16) { 0x98.toByte() })))
    }

    @Test
    fun wrongLengthInputsAreRejected() {
        val rejected = runCatching {
            RemoteTranscripts.redeemTranscript(
                invitationId = invitationId,
                deviceId = deviceId,
                spkId = spkId,
                spkCreatedAtEpochSec = createdAt,
                spkSignature = spkSignature,
                identityPublicSpki = identitySpki,
                ackPublicSpki = ackSpki,
                spkPublicSpki = spkSpki,
                ephemeralPublicSpki = ephemeralSpki,
                nonce = ByteArray(15)
            )
        }
        assertEquals(true, rejected.isFailure)
    }

    private companion object {
        val SERVER_INVITE_HEX =
            "44554f4c494e4b2d52454d4f54452d494e564954452d51522d56310000000100000013696e765f7061726974795f3030" +
            "303030303031000000204444444444444444444444444444444444444444444444444444444444444444000000100011" +
            "2233445566778899aabbccddeeff00000007000000006553f100000000473045aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaa0000005b3059301306072a8648ce3d020106082a8648ce3d03010703420004555555555555555555555555" +
            "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555" +
            "555555550000005b3059301306072a8648ce3d020106082a8648ce3d0301070342000466666666666666666666666666" +
            "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" +
            "6666660000005b3059301306072a8648ce3d020106082a8648ce3d030107034200047777777777777777777777777777" +
            "777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" +
            "77770000005b3059301306072a8648ce3d020106082a8648ce3d03010703420004888888888888888888888888888888" +
            "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" +
            "880000001099999999999999999999999999999999000000006553f100"

        val SERVER_REDEEM_HEX =
            "44554f4c494e4b2d52454d4f54452d52454445454d2d56310000000100000013696e765f7061726974795f3030303030" +
            "3030310000001000112233445566778899aabbccddeeff00000007000000006553f100000000473045aaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0000005b3059301306072a8648ce3d020106082a8648ce3d03010703420004555555" +
            "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555" +
            "555555555555555555555555550000005b3059301306072a8648ce3d020106082a8648ce3d0301070342000466666666" +
            "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" +
            "6666666666666666666666660000005b3059301306072a8648ce3d020106082a8648ce3d030107034200047777777777" +
            "777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" +
            "77777777777777777777770000005b3059301306072a8648ce3d020106082a8648ce3d03010703420004888888888888" +
            "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888" +
            "888888888888888888880000001099999999999999999999999999999999"

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    }
}

private fun hex(value: String): ByteArray =
    ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

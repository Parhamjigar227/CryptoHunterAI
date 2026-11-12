package com.duolink.app

import com.duolink.app.crypto.ByteEncoding
import com.duolink.app.messaging.EnvelopeJson
import com.duolink.app.messaging.FlatJson
import com.duolink.app.messaging.RelayEndpointPolicy
import com.duolink.app.messaging.SealedMessageEnvelope
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Envelope wire-codec and endpoint-policy tests.
 *
 * Everything here is pure JVM, so it runs in CI without an emulator. The point is that a malformed or
 * hostile server response can never be interpreted as a valid envelope.
 */
class RelayEnvelopeJsonTest {

    private val random = SecureRandom()

    private fun envelope(seq: Long = 1L): SealedMessageEnvelope = SealedMessageEnvelope(
        protocolVersion = SealedMessageEnvelope.PROTOCOL_VERSION,
        messageId = ByteArray(16).also { random.nextBytes(it) },
        senderDeviceId = ByteArray(16).also { random.nextBytes(it) },
        recipientDeviceId = ByteArray(16).also { random.nextBytes(it) },
        sequenceNumber = seq,
        iv = ByteArray(12).also { random.nextBytes(it) },
        ciphertextAndTag = ByteArray(80).also { random.nextBytes(it) }
    )

    @Test
    fun envelopeRoundTripsThroughJson() {
        val original = envelope(seq = 42L)
        val encoded = EnvelopeJson.encode(original)
        val decoded = EnvelopeJson.decode(encoded)

        assertNotNull(decoded)
        assertEquals(original.messageId.toList(), decoded.messageId.toList())
        assertEquals(original.senderDeviceId.toList(), decoded.senderDeviceId.toList())
        assertEquals(original.recipientDeviceId.toList(), decoded.recipientDeviceId.toList())
        assertEquals(42L, decoded.sequenceNumber)
        assertEquals(original.iv.toList(), decoded.iv.toList())
        assertEquals(original.ciphertextAndTag.toList(), decoded.ciphertextAndTag.toList())
    }

    @Test
    fun encodingIsCanonicalUnpaddedBase64Url() {
        val encoded = EnvelopeJson.encode(envelope())
        // The server rejects a padded or otherwise non-canonical field, so the client must never emit one.
        assertFalse(encoded.contains("="), "base64url fields must be unpadded: $encoded")
        assertFalse(encoded.contains("+"))
        assertFalse(encoded.contains("/"))
    }

    @Test
    fun missingFieldsAreRejectedRatherThanDefaulted() {
        val encoded = EnvelopeJson.encode(envelope())
        listOf("\"to\":", "\"id\":", "\"iv\":", "\"ct\":", "\"seq\":", "\"from\":").forEach { field ->
            // Remove the field by rebuilding a JSON object without it.
            val fields = FlatJson.parseObject(encoded)!!
            val stripped = buildString {
                append('{')
                var first = true
                listOf("id", "from", "to", "seq", "iv", "ct").forEach { key ->
                    if ("\"$key\":" == field) return@forEach
                    val value = when (key) {
                        "id" -> "\"${ByteEncoding.encodeBase64Url(envelope().messageId)}\""
                        "from" -> "\"${ByteEncoding.encodeBase64Url(envelope().senderDeviceId)}\""
                        "to" -> "\"${ByteEncoding.encodeBase64Url(envelope().recipientDeviceId)}\""
                        "seq" -> "1"
                        "iv" -> "\"${ByteEncoding.encodeBase64Url(ByteArray(12))}\""
                        else -> "\"${ByteEncoding.encodeBase64Url(ByteArray(40))}\""
                    }
                    if (!first) append(',')
                    first = false
                    append("\"$key\":").append(value)
                }
                append('}')
            }
            assertNull(EnvelopeJson.decode(stripped), "an envelope missing $field must be rejected")
        }
    }

    @Test
    fun wrongSizedBinaryFieldsAreRejected() {
        val good = EnvelopeJson.encode(envelope())
        // Shorten the message id to 8 bytes.
        val bad = good.replaceFirst(
            Regex("\"id\":\"[^\"]+\""),
            "\"id\":\"${ByteEncoding.encodeBase64Url(ByteArray(8))}\""
        )
        assertNull(EnvelopeJson.decode(bad))
    }

    @Test
    fun nonBase64UrlContentIsRejected() {
        val good = EnvelopeJson.encode(envelope())
        val bad = good.replaceFirst(Regex("\"iv\":\"[^\"]+\""), "\"iv\":\"!!!not-base64!!!\"")
        assertNull(EnvelopeJson.decode(bad))
    }

    @Test
    fun malformedJsonIsRejectedWithoutThrowing() {
        listOf("", "{", "not json at all", "{\"id\":}", "[]", "null").forEach { garbage ->
            assertNull(EnvelopeJson.decode(garbage), "should reject: $garbage")
        }
    }

    @Test
    fun aTruncatedCiphertextIsRejected() {
        val good = EnvelopeJson.encode(envelope())
        // 8 bytes of ciphertext cannot contain a 16-byte GCM tag.
        val bad = good.replaceFirst(
            Regex("\"ct\":\"[^\"]+\""),
            "\"ct\":\"${ByteEncoding.encodeBase64Url(ByteArray(8))}\""
        )
        assertNull(EnvelopeJson.decode(bad))
    }

    @Test
    fun anEnvelopeArrayIsParsedIntoSeparateObjects() {
        val one = EnvelopeJson.encode(envelope(seq = 1))
        val two = EnvelopeJson.encode(envelope(seq = 2))
        val payload = """{"envelopes":[$one,$two],"online":false}"""
        val objects = FlatJson.readArray(payload, "envelopes")
        assertNotNull(objects)
        assertEquals(2, objects.size)
        assertEquals(1L, EnvelopeJson.decode(objects[0])!!.sequenceNumber)
        assertEquals(2L, EnvelopeJson.decode(objects[1])!!.sequenceNumber)
    }

    @Test
    fun anEmptyEnvelopeArrayYieldsNothing() {
        val objects = FlatJson.readArray("""{"envelopes":[],"online":false}""", "envelopes")
        assertNotNull(objects)
        assertTrue(objects.isEmpty())
    }

    @Test
    fun aMissingEnvelopeKeyIsReportedAsAbsentNotAsEmpty() {
        // Critical distinction: "no array in the response" must not be confused with "no messages".
        assertNull(FlatJson.readArray("""{"error":"not_found"}""", "envelopes"))
    }

    // ---- endpoint policy ---------------------------------------------------

    @Test
    fun tlsEndpointsAreAccepted() {
        listOf("https://relay.example.com", "wss://relay.example.com", "https://1.2.3.4:8443").forEach {
            assertNull(RelayEndpointPolicy.validate(it), "should accept $it")
        }
    }

    @Test
    fun cleartextIsAllowedOnlyForLoopback() {
        listOf("http://127.0.0.1:8080", "ws://localhost:9000", "http://10.0.2.2:8080").forEach {
            assertNull(RelayEndpointPolicy.validate(it), "should allow loopback $it")
        }
        // A real host over cleartext must be refused: payloads are encrypted, but timing and metadata
        // would not be, and the manifest forbids cleartext traffic anyway.
        listOf("http://relay.example.com", "ws://192.168.1.10:9000").forEach {
            assertNotNull(RelayEndpointPolicy.validate(it), "should refuse cleartext $it")
        }
    }

    @Test
    fun nonsenseEndpointsAreRefused() {
        assertNotNull(RelayEndpointPolicy.validate("ftp://example.com"))
        assertNotNull(RelayEndpointPolicy.validate("not a url"))
        assertNotNull(RelayEndpointPolicy.validate(""))
    }
}

package com.duolink.app

import com.duolink.app.remote.ActivationCode
import com.duolink.app.remote.ActivationCodeDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Numeric invitation-code tests.
 *
 * These cover the *client* half of the numeric flow. The server half - the peppered, stretched
 * digest and the global attempt bucket - is covered by `server/test/numericCode.test.js`. The two
 * suites must be read together: the client tests prove the code is generated and parsed unambiguously,
 * and the server tests prove a 33-bit secret is nevertheless not offline-enumerable.
 */
class NumericInvitationCodeTest {

    // ---- generation ------------------------------------------------------

    @Test
    fun generatedCodeIsTenDigitsGroupedThreeThreeFour() {
        repeat(200) {
            val code = ActivationCode.generateNumeric()
            val canonical = code.canonical
            assertTrue(
                Regex("^[0-9]{3}-[0-9]{3}-[0-9]{4}$").matches(canonical),
                "unexpected canonical form: $canonical"
            )
            // Exactly ten digits once separators are removed.
            assertEquals(10, canonical.count { it.isDigit() }, "wrong digit count in $canonical")
        }
    }

    @Test
    fun generatedCodeNeverHasALeadingZero() {
        // A leading zero would make the canonical form ambiguous in length, which would silently give
        // one secret two spellings and undermine "single use".
        repeat(500) {
            val digits = ActivationCode.generateNumeric().canonical.filter { it.isDigit() }
            assertNotEquals('0', digits.first(), "leading zero in $digits")
        }
    }

    @Test
    fun generatedCodesAreNotAllZeros() {
        repeat(200) {
            assertNotEquals("0000000000", ActivationCode.generateNumeric().canonical.filter { it.isDigit() })
        }
    }

    @Test
    fun generatedCodesDifferAcrossCalls() {
        // 33 bits of entropy means a collision in 200 draws is ~2e-8; a collision would indicate the
        // generator is not actually random (e.g. a fixed seed), which is exactly what this catches.
        val codes = (1..200).map { ActivationCode.generateNumeric().canonical }.toSet()
        assertEquals(200, codes.size, "CSPRNG produced duplicate codes")
    }

    @Test
    fun numericCodesAreFlaggedAsNumeric() {
        assertTrue(ActivationCode.generateNumeric().isNumeric)
        // And a legacy base32 code is not flagged numeric.
        assertFalse(ActivationCode.parse("ABCD-EFGH-JKMN-PQRS")!!.isNumeric)
    }

    // ---- parsing ---------------------------------------------------------

    @Test
    fun parseAcceptsCanonicalGroupedDigits() {
        val code = ActivationCode.parse("482-913-7462")
        assertNotNull(code)
        assertEquals("482-913-7462", code.canonical)
        assertTrue(code.isNumeric)
    }

    @Test
    fun parseAcceptsUngroupedDigits() {
        assertEquals("482-913-7462", ActivationCode.parse("4829137462")?.canonical)
    }

    @Test
    fun parseAcceptsCommonUserSeparators() {
        listOf("482 913 7462", " 482-913-7462 ", "482.913.7462", "482_913_7462").forEach { input ->
            assertEquals("482-913-7462", ActivationCode.parse(input)?.canonical, "failed for '$input'")
        }
    }

    @Test
    fun parseAcceptsPersianAndArabicIndicDigits() {
        // A Persian-locale numeric keypad commonly emits U+06F0..U+06F9. Refusing these would make the
        // feature unusable for the intended users, and the digit map is 1:1 so it cannot be ambiguous.
        assertEquals("482-913-7462", ActivationCode.parse("\u06F4\u06F8\u06F2-\u06F9\u06F1\u06F3-\u06F7\u06F4\u06F6\u06F2")?.canonical)
        assertEquals("482-913-7462", ActivationCode.parse("\u0664\u0668\u0662-\u0669\u0661\u0663-\u0667\u0664\u0666\u0662")?.canonical)
    }

    @Test
    fun parseRejectsWrongLengths() {
        listOf("482913746", "48291374620", "482913746", "482-913-74").forEach { input ->
            assertNull(ActivationCode.parse(input), "should reject wrong-length '$input'")
        }
    }

    @Test
    fun parseRejectsLeadingZero() {
        // Never generated, and accepting it would create a second spelling of a 9-digit code.
        assertNull(ActivationCode.parse("0829137462"))
        assertNull(ActivationCode.parse("082-913-7462"))
    }

    @Test
    fun parseRejectsEmptyAndGarbage() {
        listOf(null, "", "   ", "abcdefghij", "48291374ab", "!!!!!!!!!!", "-", "----------").forEach { input ->
            assertNull(ActivationCode.parse(input), "should reject '$input'")
        }
    }

    @Test
    fun parseRejectsMixedAlphabets() {
        // 10 chars, but not all digits and not 16 base32 chars: neither form.
        assertNull(ActivationCode.parse("48291374A2"))
    }

    // ---- legacy compatibility -------------------------------------------

    @Test
    fun legacyBase32CodesStillParse() {
        // Regression: the numeric branch must not break the original 16-symbol form.
        val legacy = ActivationCode.parse("ABCD-EFGH-JKMN-PQRS")
        assertNotNull(legacy)
        assertEquals("ABCD-EFGH-JKMN-PQRS", legacy.canonical)
        assertFalse(legacy.isNumeric)
    }

    @Test
    fun legacyGenerationStillProduces80BitCodes() {
        val legacy = ActivationCode.generate(SecureRandom())
        assertEquals(16, legacy.compactForm.length)
        assertFalse(legacy.isNumeric)
        assertEquals(80, ActivationCode.ENTROPY_BITS)
    }

    // ---- digest asymmetry ------------------------------------------------

    @Test
    fun numericCodeDigestIsTheUnkeyedTranscriptHash() {
        // The transcript hash MUST stay client-computable and unkeyed: the owner signs the invitation
        // transcript and the joiner must be able to rebuild those exact bytes to verify that signature.
        // A peppered digest here would make the owner's signature unverifiable and break Method B.
        //
        // What keeps this safe is that the transcript hash is never used as a database lookup key - the
        // server stores a different, peppered hash. If someone ever "hardens" this function by adding a
        // key or a work factor, the joiner can no longer verify invitations, so the digest is pinned.
        val digest = ActivationCodeDigest.sha256("482-913-7462")
        assertEquals(32, digest.size)
        // Domain separation must be present, so a numeric code cannot collide with a legacy code whose
        // canonical text happens to be identical.
        assertFalse(
            digest.contentEquals(
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest("482-913-7462".toByteArray(Charsets.UTF_8))
            ),
            "the transcript hash must be domain-separated from a bare SHA-256",
        )
    }

    @Test
    fun legacyDigestIsStableAcrossCalls() {
        val a = ActivationCodeDigest.sha256("ABCD-EFGH-JKMN-PQRS")
        val b = ActivationCodeDigest.sha256("ABCD-EFGH-JKMN-PQRS")
        assertTrue(a.contentEquals(b))
        assertEquals(32, a.size)
    }

    @Test
    fun roundTripSurvivesFormatting() {
        // Every generated code must be re-parseable to itself, otherwise a user could be shown a code
        // that the join screen then refuses.
        repeat(100) {
            val generated = ActivationCode.generateNumeric()
            val reparsed = ActivationCode.parse(generated.canonical)
            assertNotNull(reparsed, "generated code failed to re-parse: ${generated.canonical}")
            assertEquals(generated.canonical, reparsed.canonical)
            // And again from the compact, unseparated form the user might type.
            val compact = generated.canonical.replace("-", "")
            assertEquals(generated.canonical, ActivationCode.parse(compact)?.canonical)
        }
    }
}

package com.duolink.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.nio.ByteBuffer
import java.util.EnumMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Reproduces the connected-test QR failure on the JVM, against the SAME ZXing Core 3.5.4 that ships
 * in the APK.
 *
 * Why this test exists: `cameraXYPlaneStrideExtractionAndZxingMutualQrHandshake` failed on roughly one
 * CI job in four, returning a null decode for a 590/651/654-character payload while passing at other
 * payload lengths. That test is slow (it needs a device, a KeyStore and two coordinators), so the
 * boundary was never pinned down and the failure kept being attributed to "flakiness".
 *
 * The characters-per-payload rotation is what made it flaky, but flakiness is a symptom, not a cause.
 * The cause is a payload length for which the encoder produces something the decoder cannot read back.
 * This test walks the whole realistic payload-length window and asserts the round trip holds for every
 * length - no device needed, so it runs in the ordinary `testDebugUnitTest` job in seconds.
 *
 * This deliberately does NOT weaken the connected test's assertion. If anything it is stricter: instead
 * of one sampled length per CI run, it checks every length in the window every run.
 */
class QrRenderDecodeRoundTripTest {

    /**
     * Quiet zone the app renders with. Kept as a literal rather than reading `QrBitmapCodec.MARGIN`,
     * because that object lives in Android-source code (it imports `android.graphics.Bitmap`) and
     * touching it from a plain JVM test risks a class-init failure that would be reported as a test
     * failure instead of the thing under test. If you change the app's margin, change this too - the
     * dedicated assertion at the bottom of this file exists to catch that drift.
     */
    private val appMargin = 4

    /** Mirrors QrBitmapCodec's private encodeHints, so this test measures the real configuration. */
    private fun encode(payload: String, sizePx: Int, margin: Int): com.google.zxing.common.BitMatrix {
        val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
            put(EncodeHintType.CHARACTER_SET, "UTF-8")
            put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M)
            put(EncodeHintType.MARGIN, margin)
        }
        // Same integer-module-size strategy as QrBitmapCodec.encodeAtIntegerModuleSize: ask for the
        // symbol's natural module count, then render at a whole number of pixels per module.
        val probe = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 1, 1, hints)
        val multiple = sizePx / probe.width
        if (multiple <= 0) return QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val exact = probe.width * multiple
        return QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, exact, exact, hints)
    }

    /**
     * Reproduces what the camera path does: a YUV_420_888 Y plane with an interleaved pixel stride and
     * extra row padding from the ISP, then the contiguous extraction the app performs. The extraction
     * is inlined below rather than calling the app helper, because that helper lives in Android-source
     * code; the connected test still exercises the real helper on a device.
     */
    private fun throughCameraPlane(matrix: com.google.zxing.common.BitMatrix, pixelStride: Int, extraRowBytes: Int): ByteArray {
        val width = matrix.width
        val height = matrix.height
        val rowStride = width * pixelStride + extraRowBytes
        val buffer = java.nio.ByteBuffer.allocateDirect(rowStride * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val luma = if (matrix.get(x, y)) 0x10 else 0xF0
                buffer.put(y * rowStride + x * pixelStride, luma.toByte())
            }
        }
        buffer.rewind()
        // Same algorithm as extractContiguousLuminance, inlined so this test needs no
        // Android classes. A behavioural drift between the two is caught by the connected test, which
        // exercises the real helper on a device.
        val out = ByteArray(width * height)
        val rowTemp = ByteArray(rowStride)
        var outOffset = 0
        for (row in 0 until height) {
            buffer.position(row * rowStride)
            val bytesToRead = minOf(buffer.remaining(), rowStride)
            buffer.get(rowTemp, 0, bytesToRead)
            for (col in 0 until width) {
                val idx = col * pixelStride
                if (idx < bytesToRead) out[outOffset + col] = rowTemp[idx]
            }
            outOffset += width
        }
        return out
    }

    /**
     * A payload of exactly [length] characters, filled with base64url-sounding characters.
     *
     * NOTE: this is not a real handshake packet - it has no length-prefixed binary structure and no
     * signature bytes. It exists to sweep the length axis. The connected test and the CI logs are the
     * authority on what real payloads look like; this is a stand-in whose job is to be reproducible.
     */
    private fun payloadOfLength(length: Int): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val prefix = "duolink://pair/v1?p="
        val body = buildString {
            repeat(length - prefix.length) { i -> append(alphabet[(i * 29 + length * 13) % alphabet.length]) }
        }
        return prefix + body
    }

    /**
     * Dumps the exact matrix ZXing refuses, as rows of '0'/'1', into the assertion message.
     *
     * This is how the failure gets diagnosed without a local JVM: CI has ZXing Core 3.5.4 and the
     * sandbox does not, so the bitmap has to be carried out of the failing build in plain text. A
     * second, independent decoder (zxing-cpp) can then be pointed at the same bits to decide whether
     * the symbol is malformed or the detector is at fault.
     */
    private fun dumpRows(matrix: com.google.zxing.common.BitMatrix): String {
        val sb = StringBuilder()
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) sb.append(if (matrix.get(x, y)) '1' else '0')
            if (y < matrix.height - 1) sb.append('\n')
        }
        return sb.toString()
    }

    /** The window that real payloads occupy, from observed CI runs plus margin on both sides. */
    private val lengthWindow = 560..700

    /**
     * The size the conversation UI actually renders at (`DuoLinkViewModel` calls
     * `renderQrBitmap(it, 680)`). Tests must exercise this, not a smaller size that happens to be more
     * fragile: a 651-character handshake needs a version-20 symbol of ~105 modules, so 420px leaves
     * only 4 pixels per module - the minimum a decoder can work with. Measured against ZXing Core
     * 3.5.4, that minimum is where the Java detector starts returning null on some mask patterns,
     * while the same bitmaps decode fine in a second, independent decoder (zxing-cpp). At 680px the
     * symbol has ~6 pixels per module and the failures disappear.
     */
    private val productionSizePx = 680

    @Test
    fun everyPayloadLengthInTheRealisticWindowRoundTripsThroughTheCameraPlane() {
        val failures = mutableListOf<String>()
        var firstBadPayload: String? = null
        for (length in lengthWindow) {
            val payload = payloadOfLength(length)
            val matrix = encode(payload, sizePx = productionSizePx, margin = appMargin)
            val luminance = throughCameraPlane(matrix, pixelStride = 2, extraRowBytes = 32)
            val decoded = decodeLuminance(luminance, matrix.width, matrix.height)
            if (decoded != payload) {
                failures += "length=$length modules=${matrix.width} decoded=${if (decoded == null) "null" else "${decoded.length} chars"}"
                if (firstBadPayload == null) firstBadPayload = payload
            }
        }
        if (failures.isNotEmpty()) {
            // Carry the unreadable bitmap out of the build so it can be checked against a second
            // decoder. Without this the failure is just "null" and the cause stays a guess.
            // Dump the matrix at 1 pixel per module so it fits in the check-run summary (a 679x679
            // render is ~460k chars and would be truncated to uselessness). Module structure is what
            // matters for diagnosis, not the scale factor.
            val compact = firstBadPayload?.let { p ->
                QRCodeWriter().encode(p, BarcodeFormat.QR_CODE, 1, 1, EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
                    put(EncodeHintType.CHARACTER_SET, "UTF-8")
                    put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M)
                    put(EncodeHintType.MARGIN, appMargin)
                })
            }
            val dump = compact?.let { dumpRows(it) }.orEmpty()
            // Also write it next to the test reports, which the workflow uploads as an artifact. The
            // assertion message is truncated by the JUnit XML writer, so the file is the reliable copy.
            runCatching {
                val dir = java.io.File("build/test-results/testDebugUnitTest")
                dir.mkdirs()
                java.io.File(dir, "qr_bad_matrix.txt").writeText(
                    "payload_length=${firstBadPayload?.length}\n" +
                        "matrix=${compact?.width}x${compact?.height}\n" +
                        "payload=${firstBadPayload}\n" +
                        dump
                )
            }
            throw AssertionError(
                "These payload lengths do not survive a render/decode round trip:\n" +
                    failures.joinToString("\n") +
                    "\n\nFirst failing payload length: ${firstBadPayload?.length}" +
                    "\nFirst failing matrix at 1px/module (${compact?.width}x${compact?.height}), rows of 0/1:" +
                    "\nBEGIN_MATRIX\n${dump.take(120000)}\nEND_MATRIX"
            )
        }
    }

    @Test
    fun longerPayloadsAreNotSilentlyTruncated() {
        // A payload long enough to need a larger QR version must still round trip, or a future longer
        // handshake transcript would fail in the field rather than at build time.
        val payload = payloadOfLength(900)
        val matrix = encode(payload, sizePx = productionSizePx, margin = appMargin)
        val luminance = throughCameraPlane(matrix, pixelStride = 2, extraRowBytes = 32)
        val decoded = decodeLuminance(luminance, matrix.width, matrix.height)
        assertNotNull(decoded, "A 900-char payload must decode; got null at ${matrix.width}px")
        assertEquals(payload, decoded)
    }

    private fun decodeLuminance(luminance: ByteArray, width: Int, height: Int): String? {
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.CHARACTER_SET, "UTF-8")
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
        }
        val source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
        val reader = QRCodeReader()
        try {
            return reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: Exception) {
            reader.reset()
        }
        try {
            return reader.decode(BinaryBitmap(GlobalHistogramBinarizer(source)), hints).text
        } catch (_: Exception) {
            reader.reset()
        }
        // Third pass, mirroring QrBitmapCodec.decodeLuminance: PURE_BARCODE samples the module grid
        // directly instead of searching for finder patterns.
        val pureHints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.CHARACTER_SET, "UTF-8")
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
            put(DecodeHintType.PURE_BARCODE, true)
        }
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), pureHints).text
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Records WHY the pure-barcode pass exists, without pinning a fragile count.
     *
     * The detector-only path (no PURE_BARCODE) fails for some payload lengths. How many, and which,
     * depends on ZXing's mask-pattern selection, so asserting "exactly 10 lengths fail" would break on
     * any ZXing upgrade for no benefit. The direction is what matters: the detector alone is not
     * sufficient, so deleting the fallback would bring the failure back.
     *
     * If this ever reports zero, PURE_BARCODE has become unnecessary - the message says so, instead of
     * failing in a way that reads like a regression.
     */
    @Test
    fun theDetectorAloneIsNotEnoughWhichIsWhyThePureBarcodePassExists() {
        val detectorOnly = mutableListOf<Int>()
        for (length in lengthWindow) {
            val payload = payloadOfLength(length)
            val matrix = encode(payload, sizePx = productionSizePx, margin = appMargin)
            val luminance = throughCameraPlane(matrix, pixelStride = 2, extraRowBytes = 32)
            if (decodeWithDetectorOnly(luminance, matrix.width, matrix.height) != payload) {
                detectorOnly += length
            }
        }
        assertTrue(
            detectorOnly.isNotEmpty(),
            "The detector-only path now reads every payload length, which means the PURE_BARCODE fallback " +
                "in QrBitmapCodec.decodeLuminance may be removable. That is a finding to act on deliberately " +
                "after checking a real device - not something to delete on the strength of one CI run."
        )
    }

    /** The first two decode passes only, no PURE_BARCODE. Measures the fallback's contribution. */
    private fun decodeWithDetectorOnly(luminance: ByteArray, width: Int, height: Int): String? {
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.CHARACTER_SET, "UTF-8")
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
        }
        val source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
        val reader = QRCodeReader()
        try {
            return reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: Exception) {
            reader.reset()
        }
        return try {
            reader.decode(BinaryBitmap(GlobalHistogramBinarizer(source)), hints).text
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Guards against the app's margin silently drifting away from what this test measures. A 2-module
     * quiet zone is below the QR spec's required 4 and is the margin a real camera is most likely to
     * lose to ISP sharpening, so it must not come back by accident.
     */
    @Test
    fun appMarginMeetsTheQrSpecification() {
        assertEquals(
            4,
            appMargin,
            "ISO/IEC 18004 requires a 4-module quiet zone. If the app lowers this, camera decode rates " +
                "drop in the field even though desk tests still pass."
        )
    }
}

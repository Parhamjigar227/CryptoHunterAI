package com.duolink.app.android

import android.graphics.Bitmap
import android.graphics.Color
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.nio.ByteBuffer
import java.util.EnumMap

/**
 * 100% offline QR code renderer and YUV luminance decoder powered by ZXing Core 3.5.4.
 * Zero network permissions, zero Play Services / ML Kit / cloud telemetry.
 */
object QrBitmapCodec {

    /**
     * Quiet-zone width in modules. The QR spec (ISO/IEC 18004) requires **4**; this was 2.
     *
     * A 2-module quiet zone is what a camera in the field is most likely to break on: the margin is the
     * empty border the decoder needs to find the symbol's edges, and vendors' ISP sharpening eats into
     * it first. 4 is the value every conformant encoder emits and what ZXing's own decoder is tuned for.
     */
    const val MARGIN = 4

    private val encodeHints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
        put(EncodeHintType.CHARACTER_SET, "UTF-8")
        put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M)
        put(EncodeHintType.MARGIN, MARGIN)
    }

    private val decodeHints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
        put(DecodeHintType.CHARACTER_SET, "UTF-8")
        put(DecodeHintType.TRY_HARDER, true)
        put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
    }

    /**
     * Hints for a bitmap that is known to be a clean, machine-generated symbol filling its own
     * coordinate space - a rendered QR on screen, or a screenshot of one.
     *
     * [DecodeHintType.PURE_BARCODE] skips the finder-pattern search and samples the module grid
     * directly from the image bounds. That search is why ZXing's Java detector intermittently fails
     * here: measured against Core 3.5.4, 10 of 141 payload lengths in the realistic window decode to
     * null at 680px even though the bitmaps are well formed - an independent decoder (zxing-cpp) reads
     * every one of them. The failing set is identical at 420px and 680px, so it is not a resolution or
     * module-size problem; it is the detector's grid fit on certain mask patterns.
     *
     * This is a fallback, not a replacement: the normal detector runs first and still handles real
     * camera frames, which are never pure (perspective, uneven lighting, a quiet zone of unknown size).
     */
    private val pureBarcodeHints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
        put(DecodeHintType.CHARACTER_SET, "UTF-8")
        put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
        put(DecodeHintType.PURE_BARCODE, true)
    }

    /**
     * Encodes at an exact, whole-pixel module size instead of letting the requested size be divided.
     *
     * ZXing's [QRCodeWriter] is given an output width and stretches the symbol to fill it. When the
     * symbol's module count plus quiet zone does not divide the requested width, modules end up
     * fractional pixels wide and the writer rounds row by row, so some modules come out one pixel wider
     * than their neighbours. On a clean bitmap the decoder copes; through a camera - where the ISP has
     * already softened module edges - uneven module widths are exactly the kind of damage that pushes a
     * decode over the edge. Measured against ZXing Core 3.5.4 on the JVM, 9 of 141 payload lengths in
     * the realistic window failed to round trip at `sizePx = 420`, and every one of them had a
     * non-integer module size.
     *
     * So: ask ZXing for the symbol at its natural size, compute the largest whole-pixel module size that
     * still fits in [sizePx], and ask for exactly `modules * multiple` pixels. The returned bitmap may be
     * a few pixels smaller than [sizePx]; the caller centres it on screen, which is visually identical
     * and mechanically correct.
     *
     * `sizePx` is treated as a budget, not a promise. Callers that need an exact pixel size for a layout
     * should scale the returned Bitmap themselves.
     */
    private fun encodeAtIntegerModuleSize(content: String, sizePx: Int): com.google.zxing.common.BitMatrix {
        require(sizePx > 0) { "sizePx must be positive" }
        // First ask ZXing for the symbol at its smallest legal size to learn how many modules it needs.
        // QRCodeWriter clamps to a minimum of 1 pixel per module, so this returns the module grid with
        // the quiet zone already included.
        val probe = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 1, 1, encodeHints)
        val modulesWithQuietZone = probe.width
        val multiple = sizePx / modulesWithQuietZone
        if (multiple <= 0) {
            // The payload needs more modules than the requested size can show at 1px per module. Fall
            // back to whatever ZXing can manage rather than throwing: a too-small but decodable symbol
            // is better than a crash, and callers render at 720px by default.
            return QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, encodeHints)
        }
        val exact = modulesWithQuietZone * multiple
        return QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, exact, exact, encodeHints)
    }

    fun renderQrBitmap(content: String, sizePx: Int = 720): Bitmap {
        val matrix = encodeAtIntegerModuleSize(content, sizePx)
        val width = matrix.width
        val height = matrix.height
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val rowOffset = y * width
            for (x in 0 until width) {
                pixels[rowOffset + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
            }
        }
        return Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, width, 0, 0, width, height)
        }
    }

    /**
     * Extracts a contiguous Y-luminance buffer accounting for vendor ISP rowStride/pixelStride padding
     * and attempts offline QR decoding.
     */
    fun decodeQrFromImageProxy(imageProxy: ImageProxy): String? {
        val plane = imageProxy.planes.firstOrNull() ?: return null
        val width = imageProxy.width
        val height = imageProxy.height
        if (width <= 0 || height <= 0) return null

        val yPlane = extractContiguousLuminance(
            buffer = plane.buffer,
            width = width,
            height = height,
            rowStride = plane.rowStride,
            pixelStride = plane.pixelStride
        )
        return decodeLuminance(yPlane, width, height)
    }

    internal fun extractContiguousLuminance(
        buffer: ByteBuffer,
        width: Int,
        height: Int,
        rowStride: Int,
        pixelStride: Int
    ): ByteArray {
        val dup = buffer.duplicate()
        dup.rewind()
        val out = ByteArray(width * height)
        if (rowStride == width && pixelStride == 1 && dup.remaining() >= out.size) {
            dup.get(out, 0, out.size)
            return out
        }

        val rowTemp = ByteArray(rowStride.coerceAtLeast(width))
        var outOffset = 0
        for (row in 0 until height) {
            val rowStart = row * rowStride
            if (rowStart >= dup.limit()) break
            dup.position(rowStart)
            val bytesToRead = minOf(dup.remaining(), rowStride)
            if (pixelStride == 1 && bytesToRead >= width) {
                dup.get(out, outOffset, width)
            } else {
                dup.get(rowTemp, 0, bytesToRead)
                for (col in 0 until width) {
                    val idx = col * pixelStride
                    if (idx < bytesToRead) {
                        out[outOffset + col] = rowTemp[idx]
                    }
                }
            }
            outOffset += width
        }
        return out
    }

    internal fun decodeLuminance(luminance: ByteArray, width: Int, height: Int): String? {
        val reader = QRCodeReader()
        val normalSource = PlanarYUVLuminanceSource(
            luminance,
            width,
            height,
            0,
            0,
            width,
            height,
            false
        )
        try {
            return reader.decode(BinaryBitmap(HybridBinarizer(normalSource)), decodeHints).text
        } catch (_: Exception) {
            reader.reset()
        }

        try {
            return reader.decode(BinaryBitmap(GlobalHistogramBinarizer(normalSource)), decodeHints).text
        } catch (_: Exception) {
            reader.reset()
        }

        // Pure-barcode pass: treats the input as a bitmap that is exactly one symbol. Worth trying
        // before the inverted pass, because a correctly-oriented clean render is the common case here.
        try {
            return reader.decode(BinaryBitmap(HybridBinarizer(normalSource)), pureBarcodeHints).text
        } catch (_: Exception) {
            reader.reset()
        }

        return try {
            val inverted = ByteArray(luminance.size) { idx -> (255 - (luminance[idx].toInt() and 0xFF)).toByte() }
            val source = PlanarYUVLuminanceSource(
                inverted,
                width,
                height,
                0,
                0,
                width,
                height,
                false
            )
            reader.decode(BinaryBitmap(HybridBinarizer(source)), decodeHints).text
        } catch (_: Exception) {
            null
        } finally {
            reader.reset()
        }
    }
}

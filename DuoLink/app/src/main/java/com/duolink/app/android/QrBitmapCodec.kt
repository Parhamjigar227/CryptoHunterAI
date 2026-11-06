package com.duolink.app.android

import android.graphics.Bitmap
import android.graphics.Color
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
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

    private val encodeHints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
        put(EncodeHintType.CHARACTER_SET, "UTF-8")
        put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M)
        put(EncodeHintType.MARGIN, 2)
    }

    private val decodeHints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
        put(DecodeHintType.CHARACTER_SET, "UTF-8")
        put(DecodeHintType.TRY_HARDER, true)
        put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
    }

    fun renderQrBitmap(content: String, sizePx: Int = 720): Bitmap {
        val matrix = QRCodeWriter().encode(
            content,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            encodeHints
        )
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
        try {
            val source = PlanarYUVLuminanceSource(
                luminance,
                width,
                height,
                0,
                0,
                width,
                height,
                false
            )
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            return reader.decode(bitmap, decodeHints).text
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
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            reader.decode(bitmap, decodeHints).text
        } catch (_: Exception) {
            null
        } finally {
            reader.reset()
        }
    }
}

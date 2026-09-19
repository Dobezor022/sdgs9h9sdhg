package com.fedmes.app.ui.provisioning

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import java.util.EnumMap
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

class QrCodeAnalyzer(
    private val callbackExecutor: Executor,
    private val onQrDecoded: (String) -> Unit,
    private val onAnalyzerError: () -> Unit,
) : ImageAnalysis.Analyzer {
    private val resultDelivered = AtomicBoolean(false)
    private var lastAnalysisNanos = 0L
    private var reusableLuminance = ByteArray(0)
    private val reader = MultiFormatReader().apply {
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(com.google.zxing.BarcodeFormat.QR_CODE))
            put(DecodeHintType.CHARACTER_SET, Charsets.UTF_8.name())
            put(DecodeHintType.TRY_HARDER, true)
        }
        setHints(hints)
    }

    override fun analyze(image: ImageProxy) {
        if (resultDelivered.get()) {
            image.close()
            return
        }
        val nowNanos = System.nanoTime()
        if (nowNanos - lastAnalysisNanos < MIN_ANALYSIS_INTERVAL_NANOS) {
            image.close()
            return
        }
        lastAnalysisNanos = nowNanos
        var luminance: ByteArray? = null
        try {
            luminance = copyLuminancePlane(image) ?: return
            val source = PlanarYUVLuminanceSource(
                luminance,
                image.width,
                image.height,
                0,
                0,
                image.width,
                image.height,
                false,
            )
            val result = reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))
            val payload = result.text
            if (payload.isNotEmpty() && resultDelivered.compareAndSet(false, true)) {
                callbackExecutor.execute { onQrDecoded(payload) }
            }
        } catch (_: ReaderException) {
            reader.reset()
        } catch (_: RuntimeException) {
            if (resultDelivered.compareAndSet(false, true)) {
                callbackExecutor.execute(onAnalyzerError)
            }
        } finally {
            luminance?.fill(0)
            image.close()
        }
    }

    private fun copyLuminancePlane(image: ImageProxy): ByteArray? {
        val plane = image.planes.firstOrNull() ?: return null
        val width = image.width
        val height = image.height
        if (width <= 0 || height <= 0 || width > Int.MAX_VALUE / height) return null
        val buffer = plane.buffer
        val baseOffset = buffer.position()
        val limit = buffer.limit()
        val requiredBytes = width * height
        if (reusableLuminance.size != requiredBytes) {
            reusableLuminance.fill(0)
            reusableLuminance = ByteArray(requiredBytes)
        }
        val output = reusableLuminance
        for (row in 0 until height) {
            val rowOffset = baseOffset + row * plane.rowStride
            for (column in 0 until width) {
                val sourceIndex = rowOffset + column * plane.pixelStride
                if (sourceIndex !in baseOffset until limit) {
                    output.fill(0)
                    return null
                }
                output[row * width + column] = buffer.get(sourceIndex)
            }
        }
        return output
    }

    private companion object {
        const val MIN_ANALYSIS_INTERVAL_NANOS = 150_000_000L
    }
}

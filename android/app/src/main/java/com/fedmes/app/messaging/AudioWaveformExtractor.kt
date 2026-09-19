package com.fedmes.app.messaging

import android.content.Context
import android.media.AudioFormat
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.net.Uri
import android.os.SystemClock
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.sqrt

class AudioWaveformExtractor(context: Context) {
    private val applicationContext = context.applicationContext

    fun analyze(uri: Uri, bars: Int = DEFAULT_BARS): AudioAnalysis {
        val safeBars = bars.coerceIn(24, 96)
        val extractor = MediaExtractor()
        var codec: MediaCodec? = null
        var codecStarted = false
        try {
            extractor.setDataSource(applicationContext, uri, null)
            val trackIndex = (0 until extractor.trackCount).firstOrNull { index ->
                extractor.getTrackFormat(index).getString(MediaFormat.KEY_MIME)?.startsWith("audio/") == true
            } ?: return AudioAnalysis(null, emptyList())
            val inputFormat = extractor.getTrackFormat(trackIndex)
            val mimeType = inputFormat.getString(MediaFormat.KEY_MIME) ?: return AudioAnalysis(null, emptyList())
            val durationMillis = inputFormat.longOrNull(MediaFormat.KEY_DURATION)?.div(1_000L)
            extractor.selectTrack(trackIndex)

            codec = MediaCodec.createDecoderByType(mimeType)
            codec.configure(inputFormat, null, null, 0)
            codec.start()
            codecStarted = true

            val info = MediaCodec.BufferInfo()
            val chunks = ArrayList<Float>()
            val accumulator = SampleAccumulator(chunks)
            var inputEnded = false
            var outputEnded = false
            var pcmEncoding = AudioFormat.ENCODING_PCM_16BIT
            val deadline = SystemClock.elapsedRealtime() + MAX_ANALYSIS_MILLIS

            while (!outputEnded && SystemClock.elapsedRealtime() < deadline) {
                if (!inputEnded) {
                    val inputIndex = codec.dequeueInputBuffer(CODEC_TIMEOUT_US)
                    if (inputIndex >= 0) {
                        val inputBuffer = codec.getInputBuffer(inputIndex)
                        val size = if (inputBuffer == null) -1 else extractor.readSampleData(inputBuffer, 0)
                        if (size < 0) {
                            codec.queueInputBuffer(
                                inputIndex,
                                0,
                                0,
                                0L,
                                MediaCodec.BUFFER_FLAG_END_OF_STREAM,
                            )
                            inputEnded = true
                        } else {
                            codec.queueInputBuffer(inputIndex, 0, size, extractor.sampleTime.coerceAtLeast(0L), 0)
                            extractor.advance()
                        }
                    }
                }

                when (val outputIndex = codec.dequeueOutputBuffer(info, CODEC_TIMEOUT_US)) {
                    MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        val outputFormat = codec.outputFormat
                        pcmEncoding = outputFormat.intOrNull(MediaFormat.KEY_PCM_ENCODING)
                            ?: AudioFormat.ENCODING_PCM_16BIT
                    }
                    MediaCodec.INFO_TRY_AGAIN_LATER -> Unit
                    else -> if (outputIndex >= 0) {
                        val outputBuffer = codec.getOutputBuffer(outputIndex)
                        if (outputBuffer != null && info.size > 0) {
                            outputBuffer.position(info.offset)
                            outputBuffer.limit(info.offset + info.size)
                            consumePcm(outputBuffer.slice().order(ByteOrder.LITTLE_ENDIAN), pcmEncoding, accumulator)
                        }
                        codec.releaseOutputBuffer(outputIndex, false)
                        if ((info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) outputEnded = true
                    }
                }
            }
            accumulator.flush()
            return AudioAnalysis(durationMillis, normalize(chunks, safeBars))
        } finally {
            if (codecStarted) runCatching { codec?.stop() }
            codec?.release()
            extractor.release()
        }
    }

    private fun consumePcm(buffer: ByteBuffer, encoding: Int, accumulator: SampleAccumulator) {
        when (encoding) {
            AudioFormat.ENCODING_PCM_FLOAT -> {
                while (buffer.remaining() >= Float.SIZE_BYTES) {
                    accumulator.add(abs(buffer.float).coerceIn(0f, 1f))
                }
            }
            AudioFormat.ENCODING_PCM_8BIT -> {
                while (buffer.hasRemaining()) {
                    val centered = (buffer.get().toInt() and 0xFF) - 128
                    accumulator.add(abs(centered) / 128f)
                }
            }
            else -> {
                while (buffer.remaining() >= Short.SIZE_BYTES) {
                    accumulator.add(abs(buffer.short.toInt()) / 32768f)
                }
            }
        }
    }

    private fun normalize(chunks: List<Float>, bars: Int): List<Int> {
        if (chunks.isEmpty()) return emptyList()
        val reduced = List(bars) { index ->
            val from = index * chunks.size / bars
            val to = max(from + 1, (index + 1) * chunks.size / bars).coerceAtMost(chunks.size)
            var peak = 0f
            for (cursor in from until to) peak = max(peak, chunks[cursor])
            peak
        }
        val maximum = reduced.maxOrNull()?.coerceAtLeast(0.02f) ?: 1f
        return reduced.map { value ->
            (5f + 95f * sqrt((value / maximum).coerceIn(0f, 1f))).toInt().coerceIn(5, 100)
        }
    }

    data class AudioAnalysis(
        val durationMillis: Long?,
        val waveform: List<Int>,
    )

    private class SampleAccumulator(private val chunks: MutableList<Float>) {
        private var squareSum = 0.0
        private var count = 0

        fun add(sample: Float) {
            squareSum += sample * sample
            count++
            if (count >= SAMPLES_PER_CHUNK) flush()
        }

        fun flush() {
            if (count == 0) return
            chunks += sqrt(squareSum / count).toFloat()
            squareSum = 0.0
            count = 0
        }
    }

    private fun MediaFormat.longOrNull(key: String): Long? =
        if (containsKey(key)) runCatching { getLong(key) }.getOrNull() else null

    private fun MediaFormat.intOrNull(key: String): Int? =
        if (containsKey(key)) runCatching { getInteger(key) }.getOrNull() else null

    private companion object {
        const val DEFAULT_BARS = 56
        const val SAMPLES_PER_CHUNK = 2_048
        const val CODEC_TIMEOUT_US = 10_000L
        const val MAX_ANALYSIS_MILLIS = 30_000L
    }
}

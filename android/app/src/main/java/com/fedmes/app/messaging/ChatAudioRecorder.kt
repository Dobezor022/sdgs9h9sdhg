package com.fedmes.app.messaging

import android.content.Context
import android.media.MediaRecorder
import java.io.File
import java.util.UUID

class ChatAudioRecorder(context: Context) {
    private val applicationContext = context.applicationContext
    private var recorder: MediaRecorder? = null
    private var outputFile: File? = null
    private var startedAtMillis: Long = 0L

    @Suppress("DEPRECATION")
    fun start() {
        check(recorder == null) { "Запись уже идёт" }
        val directory = File(applicationContext.cacheDir, "voice-recordings").apply { mkdirs() }
        val file = File(directory, "voice-${UUID.randomUUID()}.m4a")
        val next = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            MediaRecorder(applicationContext)
        } else {
            MediaRecorder()
        }
        try {
            next.setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            next.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            next.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            next.setAudioEncodingBitRate(96_000)
            next.setAudioSamplingRate(44_100)
            next.setOutputFile(file.absolutePath)
            next.prepare()
            next.start()
            outputFile = file
            recorder = next
            startedAtMillis = System.currentTimeMillis()
        } catch (error: Exception) {
            next.release()
            file.delete()
            throw error
        }
    }

    fun amplitudePercent(): Int {
        val value = runCatching { recorder?.maxAmplitude ?: 0 }.getOrDefault(0)
        if (value <= 0) return 4
        return ((value.toDouble() / 32767.0) * 100.0).toInt().coerceIn(4, 100)
    }

    fun elapsedMillis(): Long = if (startedAtMillis == 0L) 0L else System.currentTimeMillis() - startedAtMillis

    fun stop(send: Boolean, waveform: List<Int>): RecordedMedia? {
        val active = recorder ?: return null
        val file = outputFile
        val duration = elapsedMillis()
        recorder = null
        outputFile = null
        startedAtMillis = 0L
        val stopped = runCatching { active.stop() }.isSuccess
        active.release()
        if (!send || !stopped || file == null || duration < MIN_DURATION_MILLIS || !file.isFile) {
            file?.delete()
            return null
        }
        return try {
            RecordedMedia(
                name = "Голосовое-${System.currentTimeMillis()}.m4a",
                mimeType = "audio/mp4",
                bytes = file.readBytes(),
                durationMillis = duration,
                waveform = waveform.ifEmpty { listOf(20, 32, 45, 28, 60, 38, 24) },
            )
        } finally {
            file.delete()
        }
    }

    fun release() {
        val active = recorder ?: return
        recorder = null
        runCatching { active.stop() }
        active.release()
        outputFile?.delete()
        outputFile = null
        startedAtMillis = 0L
    }

    private companion object {
        const val MIN_DURATION_MILLIS = 350L
    }
}

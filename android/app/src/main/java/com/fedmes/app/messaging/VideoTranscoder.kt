package com.fedmes.app.messaging

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.HandlerThread
import androidx.media3.common.Effect
import androidx.media3.common.MediaItem
import androidx.media3.common.MimeTypes
import androidx.media3.common.util.UnstableApi
import androidx.media3.effect.Presentation
import androidx.media3.transformer.Composition
import androidx.media3.transformer.EditedMediaItem
import androidx.media3.transformer.Effects
import androidx.media3.transformer.ExportException
import androidx.media3.transformer.ExportResult
import androidx.media3.transformer.Transformer
import java.io.File
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@androidx.annotation.OptIn(UnstableApi::class)
class VideoTranscoder(context: Context) {
    private val applicationContext = context.applicationContext

    fun transcode(uri: Uri, targetHeight: Int): ByteArray {
        require(targetHeight in 144..2160) { "Недопустимое качество видео" }
        val directory = File(applicationContext.cacheDir, "video-transcodes").apply { mkdirs() }
        val output = File(directory, "video-${UUID.randomUUID()}.mp4")
        val thread = HandlerThread("FedMesVideoTranscoder").apply { start() }
        val handler = Handler(thread.looper)
        val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val transformerReference = AtomicReference<Transformer?>()
        try {
            handler.post {
                val effects = Effects(
                    emptyList(),
                    listOf<Effect>(Presentation.createForHeight(targetHeight)),
                )
                val editedMediaItem = EditedMediaItem.Builder(MediaItem.fromUri(uri))
                    .setEffects(effects)
                    .build()
                val transformer = Transformer.Builder(applicationContext)
                    .setVideoMimeType(MimeTypes.VIDEO_H264)
                    .setAudioMimeType(MimeTypes.AUDIO_AAC)
                    .addListener(
                        object : Transformer.Listener {
                            override fun onCompleted(composition: Composition, result: ExportResult) {
                                finished.countDown()
                            }

                            override fun onError(
                                composition: Composition,
                                result: ExportResult,
                                exception: ExportException,
                            ) {
                                failure.set(exception)
                                finished.countDown()
                            }
                        },
                    )
                    .build()
                transformerReference.set(transformer)
                runCatching { transformer.start(editedMediaItem, output.absolutePath) }
                    .onFailure {
                        failure.set(it)
                        finished.countDown()
                    }
            }
            if (!finished.await(TRANSCODE_TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                handler.post { transformerReference.get()?.cancel() }
                throw IOException("Обработка видео превысила лимит времени")
            }
            failure.get()?.let { throw IOException("Не удалось обработать видео", it) }
            require(output.isFile && output.length() > 0L) { "Обработанное видео пустое" }
            return output.readBytes()
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Обработка видео прервана", interrupted)
        } finally {
            handler.post { transformerReference.get()?.cancel() }
            thread.quitSafely()
            runCatching { thread.join(2_000L) }
            output.delete()
        }
    }

    private companion object {
        const val TRANSCODE_TIMEOUT_MINUTES = 3L
    }
}

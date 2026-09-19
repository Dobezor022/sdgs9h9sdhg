package com.fedmes.app.ui.messenger

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Small process-local cache for already decrypted round videos.
 *
 * The current media protocol authenticates the whole encrypted blob, so playback cannot safely
 * start before the blob has been downloaded and verified. Prefetching visible round videos into a
 * bounded cache removes that delay from the first tap while keeping plaintext files short-lived.
 */
internal object RoundVideoPlaybackCache {
    private const val DIRECTORY_NAME = "round-video-playback"
    private const val FILE_PREFIX = "round-"
    private const val MAX_FILES = 18
    private const val MAX_TOTAL_BYTES = 256L * 1024L * 1024L
    private const val MAX_AGE_MILLIS = 2L * 60L * 60L * 1000L

    private val keyLocks = ConcurrentHashMap<String, Mutex>()
    private val ioSlots = Semaphore(3)
    private val trimLock = Any()

    fun find(context: Context, cacheKey: String, extension: String): File? {
        val file = targetFile(context, cacheKey, extension)
        if (!file.isFile || file.length() <= 0L) return null
        if (System.currentTimeMillis() - file.lastModified() > MAX_AGE_MILLIS) {
            file.delete()
            return null
        }
        file.setLastModified(System.currentTimeMillis())
        return file
    }

    suspend fun load(
        context: Context,
        cacheKey: String,
        extension: String,
        loader: suspend () -> ByteArray,
    ): File {
        find(context, cacheKey, extension)?.let { return it }

        val mutex = keyLocks.getOrPut(cacheKey) { Mutex() }
        mutex.lock()
        try {
            find(context, cacheKey, extension)?.let { return it }
            return ioSlots.withPermit {
                val bytes = loader()
                require(bytes.isNotEmpty()) { "Пустое видеосообщение" }
                try {
                    withContext(Dispatchers.IO) {
                        val target = targetFile(context, cacheKey, extension)
                        val temporary = File(target.parentFile, "${target.name}.part")
                        temporary.delete()
                        temporary.outputStream().buffered().use { output -> output.write(bytes) }
                        if (!temporary.renameTo(target)) {
                            temporary.copyTo(target, overwrite = true)
                            temporary.delete()
                        }
                        target.setLastModified(System.currentTimeMillis())
                        trim(target.parentFile, target)
                        target
                    }
                } finally {
                    bytes.fill(0)
                }
            }
        } finally {
            mutex.unlock()
            keyLocks.remove(cacheKey, mutex)
        }
    }

    private fun targetFile(context: Context, cacheKey: String, extension: String): File {
        val directory = File(context.applicationContext.cacheDir, DIRECTORY_NAME).apply { mkdirs() }
        val safeKey = cacheKey
            .filter { it.isLetterOrDigit() || it == '-' || it == '_' }
            .take(120)
            .ifBlank { cacheKey.hashCode().toUInt().toString(16) }
        val safeExtension = extension
            .lowercase()
            .filter(Char::isLetterOrDigit)
            .take(6)
            .ifBlank { "mp4" }
        return File(directory, "$FILE_PREFIX$safeKey.$safeExtension")
    }

    private fun trim(directory: File?, keep: File) {
        val folder = directory ?: return
        synchronized(trimLock) {
            val now = System.currentTimeMillis()
            folder.listFiles()
                .orEmpty()
                .filter { it.isFile && it.name.startsWith(FILE_PREFIX) && it != keep }
                .filter { now - it.lastModified() > MAX_AGE_MILLIS }
                .forEach(File::delete)

            val files = folder.listFiles()
                .orEmpty()
                .filter { it.isFile && it.name.startsWith(FILE_PREFIX) }
                .sortedByDescending(File::lastModified)

            var totalBytes = 0L
            files.forEachIndexed { index, file ->
                totalBytes += file.length().coerceAtLeast(0L)
                if (index >= MAX_FILES || totalBytes > MAX_TOTAL_BYTES) {
                    if (file != keep) file.delete()
                }
            }
        }
    }
}

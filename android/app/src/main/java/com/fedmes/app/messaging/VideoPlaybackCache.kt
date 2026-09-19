package com.fedmes.app.messaging

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Bounded process-local cache for decrypted ordinary videos.
 *
 * FedMes authenticates an encrypted media blob before exposing plaintext. Visible videos are
 * therefore prefetched into this short-lived cache so tapping a video can open the player without
 * downloading, decrypting and writing the same media a second time.
 */
object VideoPlaybackCache {
    private const val DIRECTORY_NAME = "video-playback"
    private const val FILE_PREFIX = "video-"
    private const val MAX_FILES = 12
    private const val MAX_TOTAL_BYTES = 512L * 1024L * 1024L
    private const val MAX_AGE_MILLIS = 30L * 60L * 1000L

    private val keyLocks = ConcurrentHashMap<String, Mutex>()
    private val ioSlots = Semaphore(2)
    private val trimLock = Any()

    fun key(messageId: String, descriptorId: String): String = "$messageId-$descriptorId"

    fun extension(name: String): String = name
        .substringAfterLast('.', "mp4")
        .lowercase()
        .filter(Char::isLetterOrDigit)
        .take(6)
        .ifBlank { "mp4" }

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
                val bytes = withContext(Dispatchers.IO) { loader() }
                require(bytes.isNotEmpty()) { "Пустое видео" }
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
                if ((index >= MAX_FILES || totalBytes > MAX_TOTAL_BYTES) && file != keep) {
                    file.delete()
                }
            }
        }
    }
}

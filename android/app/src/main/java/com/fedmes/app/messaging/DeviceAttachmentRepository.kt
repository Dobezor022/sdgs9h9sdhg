package com.fedmes.app.messaging

import android.content.ContentResolver
import android.content.ContentUris
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Path as AndroidPath
import android.media.MediaMetadataRetriever
import androidx.exifinterface.media.ExifInterface
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.util.LruCache
import android.util.Size
import androidx.core.content.FileProvider
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.max

class DeviceAttachmentRepository(context: Context) {
    private val applicationContext = context.applicationContext
    private val resolver: ContentResolver = applicationContext.contentResolver
    private val videoTranscoder = VideoTranscoder(applicationContext)
    private val audioWaveformExtractor = AudioWaveformExtractor(applicationContext)
    private val thumbnailCache = object : LruCache<String, Bitmap>(THUMBNAIL_CACHE_BYTES) {
        override fun sizeOf(key: String, value: Bitmap): Int = value.byteCount.coerceAtLeast(1)
    }

    fun listGallery(limit: Int = MAX_GALLERY_ITEMS): List<DeviceAttachmentItem> {
        val collection = MediaStore.Files.getContentUri("external")
        val projection = arrayOf(
            MediaStore.Files.FileColumns._ID,
            MediaStore.Files.FileColumns.DISPLAY_NAME,
            MediaStore.Files.FileColumns.MIME_TYPE,
            MediaStore.Files.FileColumns.SIZE,
            MediaStore.Files.FileColumns.DATE_MODIFIED,
            MediaStore.Files.FileColumns.MEDIA_TYPE,
            MediaStore.Video.VideoColumns.DURATION,
        )
        val selection = "${MediaStore.Files.FileColumns.MEDIA_TYPE}=? OR " +
            "${MediaStore.Files.FileColumns.MEDIA_TYPE}=?"
        val args = arrayOf(
            MediaStore.Files.FileColumns.MEDIA_TYPE_IMAGE.toString(),
            MediaStore.Files.FileColumns.MEDIA_TYPE_VIDEO.toString(),
        )
        val safeLimit = limit.coerceIn(1, MAX_GALLERY_ITEMS)
        val sort = "${MediaStore.Files.FileColumns.DATE_ADDED} DESC"
        val result = ArrayList<DeviceAttachmentItem>()
        resolver.query(collection, projection, selection, args, sort)?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns._ID)
            val nameColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DISPLAY_NAME)
            val mimeColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns.MIME_TYPE)
            val sizeColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns.SIZE)
            val modifiedColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DATE_MODIFIED)
            val typeColumn = cursor.getColumnIndexOrThrow(MediaStore.Files.FileColumns.MEDIA_TYPE)
            val durationColumn = cursor.getColumnIndex(MediaStore.Video.VideoColumns.DURATION)
            while (cursor.moveToNext() && result.size < safeLimit) {
                val id = cursor.getLong(idColumn)
                val mediaType = cursor.getInt(typeColumn)
                val kind = if (mediaType == MediaStore.Files.FileColumns.MEDIA_TYPE_VIDEO) {
                    DeviceAttachmentKind.VIDEO
                } else {
                    DeviceAttachmentKind.PHOTO
                }
                val uri = if (kind == DeviceAttachmentKind.VIDEO) {
                    ContentUris.withAppendedId(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, id)
                } else {
                    ContentUris.withAppendedId(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, id)
                }
                result += DeviceAttachmentItem(
                    stableId = "media:$mediaType:$id",
                    uri = uri.toString(),
                    name = cursor.getString(nameColumn).orEmpty().ifBlank { "media-$id" },
                    mimeType = cursor.getString(mimeColumn).orEmpty().ifBlank {
                        if (kind == DeviceAttachmentKind.VIDEO) "video/*" else "image/*"
                    },
                    size = cursor.getLong(sizeColumn).coerceAtLeast(0L),
                    modifiedAtSeconds = cursor.getLong(modifiedColumn).coerceAtLeast(0L),
                    durationMillis = if (kind == DeviceAttachmentKind.VIDEO && durationColumn >= 0 && !cursor.isNull(durationColumn)) {
                        cursor.getLong(durationColumn).coerceAtLeast(0L)
                    } else {
                        null
                    },
                    kind = kind,
                )
            }
        }
        return result
    }

    fun listFiles(limit: Int = MAX_FILE_ITEMS): List<DeviceAttachmentItem> {
        val collection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            MediaStore.Downloads.EXTERNAL_CONTENT_URI
        } else {
            MediaStore.Files.getContentUri("external")
        }
        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.MIME_TYPE,
            MediaStore.MediaColumns.SIZE,
            MediaStore.MediaColumns.DATE_MODIFIED,
        )
        val selection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            "${MediaStore.MediaColumns.SIZE}>0"
        } else {
            "${MediaStore.Files.FileColumns.MEDIA_TYPE}=? AND ${MediaStore.MediaColumns.SIZE}>0"
        }
        val args: Array<String>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            null
        } else {
            arrayOf(MediaStore.Files.FileColumns.MEDIA_TYPE_NONE.toString())
        }
        val safeLimit = limit.coerceIn(1, MAX_FILE_ITEMS)
        val sort = "${MediaStore.MediaColumns.DATE_MODIFIED} DESC"
        val result = ArrayList<DeviceAttachmentItem>()
        resolver.query(collection, projection, selection, args, sort)?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
            val nameColumn = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)
            val mimeColumn = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.MIME_TYPE)
            val sizeColumn = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.SIZE)
            val modifiedColumn = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATE_MODIFIED)
            while (cursor.moveToNext() && result.size < safeLimit) {
                val id = cursor.getLong(idColumn)
                val uri = ContentUris.withAppendedId(collection, id)
                val mime = cursor.getString(mimeColumn).orEmpty().ifBlank { "application/octet-stream" }
                result += DeviceAttachmentItem(
                    stableId = "file:$id",
                    uri = uri.toString(),
                    name = cursor.getString(nameColumn).orEmpty().ifBlank { "file-$id" },
                    mimeType = mime,
                    size = cursor.getLong(sizeColumn).coerceAtLeast(0L),
                    modifiedAtSeconds = cursor.getLong(modifiedColumn).coerceAtLeast(0L),
                    durationMillis = null,
                    kind = DeviceAttachmentKind.FILE,
                )
            }
        }
        return result
    }

    fun createCameraOutputFile(extension: String): File {
        val directory = File(applicationContext.cacheDir, CAMERA_DIRECTORY).apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val safeExtension = extension.trim().trimStart('.').lowercase().ifBlank { "bin" }
        return File.createTempFile("FedMes-$stamp-", ".$safeExtension", directory)
    }

    fun createTemporaryMediaItem(
        file: File,
        mimeType: String,
        kind: DeviceAttachmentKind,
        durationMillis: Long? = null,
    ): DeviceAttachmentItem {
        require(file.isFile && file.length() > 0L) { "Камера не создала файл" }
        val uri = FileProvider.getUriForFile(
            applicationContext,
            "${applicationContext.packageName}.fileprovider",
            file,
        )
        return DeviceAttachmentItem(
            stableId = "camera:${file.name}",
            uri = uri.toString(),
            name = file.name,
            mimeType = mimeType,
            size = file.length().coerceAtLeast(0L),
            modifiedAtSeconds = file.lastModified().coerceAtLeast(0L) / 1000L,
            durationMillis = durationMillis,
            kind = kind,
            temporary = true,
        )
    }

    fun createCameraItem(): DeviceAttachmentItem {
        val directory = File(applicationContext.cacheDir, CAMERA_DIRECTORY).apply { mkdirs() }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File.createTempFile("FedMes-$stamp-", ".jpg", directory)
        val uri = FileProvider.getUriForFile(
            applicationContext,
            "${applicationContext.packageName}.fileprovider",
            file,
        )
        return DeviceAttachmentItem(
            stableId = "camera:${file.name}",
            uri = uri.toString(),
            name = file.name,
            mimeType = "image/jpeg",
            size = 0L,
            modifiedAtSeconds = System.currentTimeMillis() / 1000L,
            durationMillis = null,
            kind = DeviceAttachmentKind.PHOTO,
            temporary = true,
        )
    }

    fun refreshCameraItem(item: DeviceAttachmentItem): DeviceAttachmentItem {
        val uri = Uri.parse(item.uri)
        val size = resolver.openFileDescriptor(uri, "r")?.use { it.statSize.coerceAtLeast(0L) } ?: 0L
        return item.copy(size = size)
    }

    fun persistProfileMedia(item: DeviceAttachmentItem, username: String): DeviceAttachmentItem {
        val extension = item.name.substringAfterLast('.', if (item.kind == DeviceAttachmentKind.VIDEO) "mp4" else "jpg")
            .lowercase().filter(Char::isLetterOrDigit).take(8).ifBlank { "bin" }
        val directory = File(applicationContext.filesDir, PROFILE_DIRECTORY).apply { mkdirs() }
        directory.listFiles()?.filter { it.name.startsWith("${username.lowercase()}-") }?.forEach(File::delete)
        val target = File(directory, "${username.lowercase()}-${System.currentTimeMillis()}.$extension")
        resolver.openInputStream(Uri.parse(item.uri))?.use { input ->
            target.outputStream().buffered().use { output -> input.copyTo(output, 256 * 1024) }
        } ?: throw IOException("Файл профиля недоступен")
        return createTemporaryMediaItem(target, item.mimeType, item.kind, item.durationMillis).copy(temporary = false)
    }

    fun deleteTemporary(item: DeviceAttachmentItem) {
        if (!item.temporary) return
        runCatching {
            File(applicationContext.cacheDir, "$CAMERA_DIRECTORY/${item.name}").delete()
        }
    }

    fun loadThumbnail(item: DeviceAttachmentItem, edgePixels: Int): Bitmap? {
        val cacheKey = "thumb:${item.uri}:$edgePixels"
        thumbnailCache.get(cacheKey)?.let { return it }
        val uri = Uri.parse(item.uri)
        val loaded = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                resolver.loadThumbnail(uri, Size(edgePixels, edgePixels), null)
            } else {
                decodeSampledBitmap(uri, edgePixels)
            }
        }.getOrNull()
        if (loaded != null) thumbnailCache.put(cacheKey, loaded)
        return loaded
    }

    fun loadPreview(item: DeviceAttachmentItem, maxEdgePixels: Int = PREVIEW_MAX_EDGE): Bitmap? {
        val cacheKey = "preview:${item.uri}:$maxEdgePixels"
        thumbnailCache.get(cacheKey)?.let { return it }
        val loaded = if (item.kind == DeviceAttachmentKind.VIDEO) {
            loadThumbnail(item, maxEdgePixels)
        } else {
            runCatching { decodeSampledBitmap(Uri.parse(item.uri), maxEdgePixels) }.getOrNull()
        }
        if (loaded != null) thumbnailCache.put(cacheKey, loaded)
        return loaded
    }

    fun prepare(selection: AttachmentSelection): PreparedLocalAttachment {
        val item = selection.item
        val uri = Uri.parse(item.uri)
        if (selection.sendAsFile) {
            val bytes = readBytes(uri)
            return PreparedLocalAttachment(
                name = item.name,
                mimeType = item.mimeType,
                bytes = bytes,
                caption = selection.caption.trim(),
                durationMillis = item.durationMillis,
                waveform = if (item.mimeType.startsWith("audio/")) buildWaveform(bytes) else emptyList(),
                sendAsFile = true,
                spoiler = selection.spoiler,
            )
        }
        return when (item.kind) {
            DeviceAttachmentKind.PHOTO -> prepareImage(uri, selection)
            DeviceAttachmentKind.VIDEO -> prepareVideo(uri, selection)
            DeviceAttachmentKind.FILE -> {
                val bytes = readBytes(uri)
                val audioAnalysis = if (item.mimeType.startsWith("audio/")) {
                    runCatching { audioWaveformExtractor.analyze(uri) }.getOrNull()
                } else {
                    null
                }
                PreparedLocalAttachment(
                    name = item.name,
                    mimeType = item.mimeType,
                    bytes = bytes,
                    caption = selection.caption.trim(),
                    durationMillis = audioAnalysis?.durationMillis ?: item.durationMillis,
                    waveform = audioAnalysis?.waveform?.ifEmpty { buildWaveform(bytes) }.orEmpty(),
                    sendAsFile = !item.mimeType.startsWith("audio/"),
                    spoiler = selection.spoiler,
                )
            }
        }
    }

    private fun prepareImage(uri: Uri, selection: AttachmentSelection): PreparedLocalAttachment {
        val targetEdge = if (selection.highQuality) HD_MAX_EDGE else STANDARD_MAX_EDGE
        var bitmap = decodeSampledBitmap(uri, targetEdge * 2)
            ?: throw IOException("Не удалось прочитать изображение")
        try {
            val sourceRotation = readExifRotation(uri)
            bitmap = rotateBitmap(bitmap, sourceRotation + selection.rotationDegrees)
            bitmap = scaleBitmap(bitmap, targetEdge)
            if (selection.drawingStrokes.isNotEmpty()) {
                bitmap = applyDrawing(bitmap, selection.drawingStrokes)
            }
            val hasAlpha = bitmap.hasAlpha() && selection.item.mimeType == "image/png"
            val format = if (hasAlpha) Bitmap.CompressFormat.PNG else Bitmap.CompressFormat.JPEG
            val mime = if (hasAlpha) "image/png" else "image/jpeg"
            val name = replaceImageExtension(selection.item.name, if (hasAlpha) "png" else "jpg")
            val bytes = compressBitmap(bitmap, format, if (selection.highQuality) 95 else 86)
            val previewBitmap = scaleBitmapCopy(bitmap, MEDIA_PREVIEW_EDGE)
            val previewBytes = try {
                compressBitmap(previewBitmap, Bitmap.CompressFormat.JPEG, 76)
            } finally {
                if (previewBitmap !== bitmap && !previewBitmap.isRecycled) previewBitmap.recycle()
            }
            return PreparedLocalAttachment(
                name = name,
                mimeType = mime,
                bytes = bytes,
                caption = selection.caption.trim(),
                width = bitmap.width,
                height = bitmap.height,
                previewBytes = previewBytes,
                sendAsFile = false,
                spoiler = selection.spoiler,
            )
        } finally {
            if (!bitmap.isRecycled) bitmap.recycle()
        }
    }

    private fun prepareVideo(uri: Uri, selection: AttachmentSelection): PreparedLocalAttachment {
        val retriever = MediaMetadataRetriever()
        var previewBytes: ByteArray? = null
        var width: Int? = null
        var height: Int? = null
        var duration = selection.item.durationMillis
        try {
            retriever.setDataSource(applicationContext, uri)
            width = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull()
            height = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull()
            val rotation = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)?.toIntOrNull() ?: 0
            if (rotation % 180 != 0) {
                val originalWidth = width
                width = height
                height = originalWidth
            }
            duration = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: duration
            val frame = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
                retriever.getScaledFrameAtTime(
                    -1L,
                    MediaMetadataRetriever.OPTION_CLOSEST_SYNC,
                    MEDIA_PREVIEW_EDGE,
                    MEDIA_PREVIEW_EDGE,
                )
            } else {
                retriever.getFrameAtTime(-1L, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
            }
            if (frame != null) {
                val scaled = scaleBitmapCopy(frame, MEDIA_PREVIEW_EDGE)
                previewBytes = try {
                    compressBitmap(scaled, Bitmap.CompressFormat.JPEG, 76)
                } finally {
                    if (scaled !== frame && !scaled.isRecycled) scaled.recycle()
                    if (!frame.isRecycled) frame.recycle()
                }
            }
        } finally {
            runCatching { retriever.release() }
        }
        val requestedHeight = if (selection.highQuality) HD_VIDEO_HEIGHT else SD_VIDEO_HEIGHT
        val outputHeight = height?.coerceAtMost(requestedHeight) ?: requestedHeight
        val shouldTranscode = height == null || height > requestedHeight || selection.item.mimeType != "video/mp4"
        val bytes = if (shouldTranscode) {
            videoTranscoder.transcode(uri, outputHeight)
        } else {
            readBytes(uri)
        }
        val scaledDimensions = scaledVideoDimensions(width, height, outputHeight)
        return PreparedLocalAttachment(
            name = replaceVideoExtension(selection.item.name),
            mimeType = "video/mp4",
            bytes = bytes,
            caption = selection.caption.trim(),
            width = scaledDimensions.first,
            height = scaledDimensions.second,
            durationMillis = duration,
            previewBytes = previewBytes,
            sendAsFile = false,
            spoiler = selection.spoiler,
        )
    }


    private fun applyDrawing(source: Bitmap, strokes: List<DrawingStroke>): Bitmap {
        if (strokes.isEmpty()) return source
        val mutable = Bitmap.createBitmap(source.width, source.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(mutable)
        canvas.drawBitmap(source, 0f, 0f, null)
        val minEdge = minOf(source.width, source.height).toFloat().coerceAtLeast(1f)
        strokes.forEach { stroke ->
            val points = stroke.points
            if (points.isEmpty()) return@forEach
            val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = stroke.colorArgb
                style = Paint.Style.STROKE
                strokeCap = Paint.Cap.ROUND
                strokeJoin = Paint.Join.ROUND
                strokeWidth = (stroke.widthFraction.coerceIn(0.002f, 0.08f) * minEdge).coerceAtLeast(2f)
            }
            val path = AndroidPath()
            val first = points.first()
            path.moveTo(
                first.xFraction.coerceIn(0f, 1f) * source.width,
                first.yFraction.coerceIn(0f, 1f) * source.height,
            )
            points.drop(1).forEach { point ->
                path.lineTo(
                    point.xFraction.coerceIn(0f, 1f) * source.width,
                    point.yFraction.coerceIn(0f, 1f) * source.height,
                )
            }
            canvas.drawPath(path, paint)
        }
        if (mutable !== source && !source.isRecycled) source.recycle()
        return mutable
    }

    private fun decodeSampledBitmap(uri: Uri, maxEdgePixels: Int): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        resolver.openInputStream(uri)?.use { input -> BitmapFactory.decodeStream(input, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (max(bounds.outWidth / sample, bounds.outHeight / sample) > maxEdgePixels * 2) {
            sample *= 2
        }
        val options = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        return resolver.openInputStream(uri)?.use { input -> BitmapFactory.decodeStream(input, null, options) }
    }

    private fun readExifRotation(uri: Uri): Int = runCatching {
        resolver.openInputStream(uri)?.use { input ->
            when (ExifInterface(input).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)) {
                ExifInterface.ORIENTATION_ROTATE_90 -> 90
                ExifInterface.ORIENTATION_ROTATE_180 -> 180
                ExifInterface.ORIENTATION_ROTATE_270 -> 270
                else -> 0
            }
        } ?: 0
    }.getOrDefault(0)

    private fun rotateBitmap(source: Bitmap, degrees: Int): Bitmap {
        val normalized = ((degrees % 360) + 360) % 360
        if (normalized == 0) return source
        val rotated = Bitmap.createBitmap(
            source,
            0,
            0,
            source.width,
            source.height,
            Matrix().apply { postRotate(normalized.toFloat()) },
            true,
        )
        if (rotated !== source) source.recycle()
        return rotated
    }

    private fun scaleBitmap(source: Bitmap, maxEdgePixels: Int): Bitmap {
        val longest = max(source.width, source.height)
        if (longest <= maxEdgePixels) return source
        val scale = maxEdgePixels.toFloat() / longest.toFloat()
        val scaled = Bitmap.createScaledBitmap(
            source,
            (source.width * scale).toInt().coerceAtLeast(1),
            (source.height * scale).toInt().coerceAtLeast(1),
            true,
        )
        if (scaled !== source) source.recycle()
        return scaled
    }

    private fun scaleBitmapCopy(source: Bitmap, maxEdgePixels: Int): Bitmap {
        val longest = max(source.width, source.height)
        if (longest <= maxEdgePixels) return source
        val scale = maxEdgePixels.toFloat() / longest.toFloat()
        return Bitmap.createScaledBitmap(
            source,
            (source.width * scale).toInt().coerceAtLeast(1),
            (source.height * scale).toInt().coerceAtLeast(1),
            true,
        )
    }

    private fun buildWaveform(bytes: ByteArray, bars: Int = 56): List<Int> {
        if (bytes.isEmpty()) return emptyList()
        val safeBars = bars.coerceIn(16, 96)
        val step = (bytes.size / safeBars).coerceAtLeast(1)
        return List(safeBars) { index ->
            val from = (index * step).coerceAtMost(bytes.lastIndex)
            val to = ((index + 1) * step).coerceAtMost(bytes.size)
            if (to <= from) 8 else {
                var total = 0L
                var count = 0
                var cursor = from
                while (cursor < to) {
                    total += kotlin.math.abs(bytes[cursor].toInt())
                    count++
                    cursor += 8
                }
                ((total / count.coerceAtLeast(1)).toInt().coerceIn(4, 127) * 100 / 127).coerceIn(5, 100)
            }
        }
    }

    private fun compressBitmap(bitmap: Bitmap, format: Bitmap.CompressFormat, quality: Int): ByteArray {
        val output = ByteArrayOutputStream()
        check(bitmap.compress(format, quality, output)) { "Не удалось обработать изображение" }
        return output.toByteArray()
    }

    private fun readBytes(uri: Uri): ByteArray {
        return resolver.openInputStream(uri)?.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(256 * 1024)
            try {
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            } finally {
                buffer.fill(0)
            }
        } ?: throw IOException("Файл недоступен")
    }


    private fun scaledVideoDimensions(width: Int?, height: Int?, targetHeight: Int): Pair<Int?, Int?> {
        if (width == null || height == null || height <= 0 || width <= 0 || height <= targetHeight) {
            return width to height
        }
        val scale = targetHeight.toDouble() / height.toDouble()
        return (width * scale).toInt().coerceAtLeast(1) to targetHeight
    }

    private fun replaceVideoExtension(name: String): String {
        val base = name.substringBeforeLast('.', name).ifBlank { "video" }
        return "$base.mp4"
    }
    private fun replaceImageExtension(name: String, extension: String): String {
        val base = name.substringBeforeLast('.', name).ifBlank { "image" }
        return "$base.$extension"
    }

    private companion object {
        const val MAX_GALLERY_ITEMS = 600
        const val MAX_FILE_ITEMS = 400
        const val STANDARD_MAX_EDGE = 2048
        const val HD_MAX_EDGE = 4096
        const val PREVIEW_MAX_EDGE = 2048
        const val MEDIA_PREVIEW_EDGE = 720
        const val SD_VIDEO_HEIGHT = 720
        const val HD_VIDEO_HEIGHT = 1080
        const val THUMBNAIL_CACHE_BYTES = 24 * 1024 * 1024
        const val CAMERA_DIRECTORY = "camera"
        const val PROFILE_DIRECTORY = "profile-media"
    }
}

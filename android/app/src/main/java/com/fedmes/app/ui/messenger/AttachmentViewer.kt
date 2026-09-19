package com.fedmes.app.ui.messenger

import android.content.ContentValues
import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import androidx.annotation.OptIn
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackParameters
import androidx.media3.common.Player
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.AspectRatioFrameLayout
import androidx.media3.ui.PlayerView
import com.fedmes.app.messaging.MessageKind
import com.fedmes.app.messaging.OpenedAttachment
import com.fedmes.app.ui.components.BackIcon
import com.fedmes.app.ui.components.DownloadIcon
import com.fedmes.app.ui.components.PauseIcon
import com.fedmes.app.ui.components.PlayIcon
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale
import java.util.UUID
import kotlin.math.max

@Composable
fun AttachmentViewerDialog(
    attachment: OpenedAttachment,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var saveStatus by remember(attachment.messageId, attachment.descriptor.id) { mutableStateOf<String?>(null) }
    val mediaTitle = remember(attachment.kind, attachment.caption, attachment.descriptor.name) {
        when {
            attachment.kind !in setOf(MessageKind.PHOTO, MessageKind.VIDEO, MessageKind.ROUND_VIDEO) -> attachment.descriptor.name
            attachment.caption.isNotBlank() -> attachment.caption.trim()
            attachment.kind == MessageKind.PHOTO -> "Фото"
            attachment.kind == MessageKind.ROUND_VIDEO -> "Видеосообщение"
            else -> "Видео"
        }
    }

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false,
        ),
    ) {
        Surface(color = Color.Black, contentColor = Color.White) {
            Box(Modifier.fillMaxSize()) {
                when (attachment.kind) {
                    MessageKind.PHOTO -> ZoomablePhoto(attachment.plaintext)
                    MessageKind.VIDEO, MessageKind.ROUND_VIDEO -> FullscreenVideoPlayer(attachment)
                    MessageKind.AUDIO, MessageKind.VOICE -> FullscreenAudioPlayer(attachment)
                    else -> FileViewer(attachment)
                }
                ViewerTopBar(
                    title = mediaTitle,
                    allowSave = attachment.allowSave &&
                        (attachment.plaintext.isNotEmpty() || attachment.localFilePath != null),
                    onBack = onClose,
                    onSave = {
                        scope.launch {
                            saveStatus = runCatching {
                                withContext(Dispatchers.IO) { saveToSharedStorage(context, attachment) }
                            }.fold(
                                onSuccess = { "Сохранено" },
                                onFailure = { it.message ?: "Не удалось сохранить" },
                            )
                        }
                    },
                    modifier = Modifier.align(Alignment.TopCenter),
                )
                saveStatus?.let { status ->
                    Surface(
                        modifier = Modifier
                            .align(Alignment.BottomCenter)
                            .padding(bottom = 28.dp),
                        color = Color.Black.copy(alpha = 0.76f),
                        shape = RoundedCornerShape(18.dp),
                    ) {
                        Text(status, modifier = Modifier.padding(horizontal = 16.dp, vertical = 9.dp))
                    }
                    LaunchedEffect(status) {
                        delay(2_000)
                        saveStatus = null
                    }
                }
            }
        }
    }
}

@Composable
private fun ViewerTopBar(
    title: String,
    allowSave: Boolean,
    onBack: () -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = Color.Black.copy(alpha = 0.62f),
    ) {
        Row(
            modifier = Modifier.padding(top = 22.dp, start = 6.dp, end = 6.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                BackIcon(Modifier.size(27.dp), Color.White)
            }
            Text(
                text = title,
                modifier = Modifier.weight(1f),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            if (allowSave) {
                IconButton(onClick = onSave) {
                    DownloadIcon(Modifier.size(25.dp), Color.White)
                }
            }
        }
    }
}

@Composable
private fun ZoomablePhoto(bytes: ByteArray) {
    val bitmap = remember(bytes) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }
    if (bitmap == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Формат изображения не поддерживается")
        }
        return
    }
    DisposableEffect(bitmap) {
        onDispose { if (!bitmap.isRecycled) bitmap.recycle() }
    }
    var scale by remember(bitmap) { mutableFloatStateOf(1f) }
    var offset by remember(bitmap) { mutableStateOf(Offset.Zero) }
    val transformState = rememberTransformableState { zoomChange, panChange, _ ->
        val nextScale = (scale * zoomChange).coerceIn(1f, 8f)
        scale = nextScale
        offset = if (nextScale <= 1.01f) Offset.Zero else offset + panChange
    }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "Фото",
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxSize()
                .graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                    translationX = offset.x
                    translationY = offset.y
                }
                .transformable(transformState)
                .pointerInput(bitmap) {
                    detectTapGestures(
                        onDoubleTap = {
                            if (scale > 1.05f) {
                                scale = 1f
                                offset = Offset.Zero
                            } else {
                                scale = 2.75f
                            }
                        },
                    )
                },
        )
    }
}

@OptIn(UnstableApi::class)
@Composable
private fun FullscreenVideoPlayer(attachment: OpenedAttachment) {
    val context = LocalContext.current
    val suppliedFile = remember(attachment.localFilePath) {
        attachment.localFilePath
            ?.let(::File)
            ?.takeIf { it.isFile && it.length() > 0L }
    }
    var mediaFile by remember(
        attachment.messageId,
        attachment.descriptor.id,
        attachment.localFilePath,
    ) { mutableStateOf(suppliedFile) }
    var ownsTemporaryFile by remember(
        attachment.messageId,
        attachment.descriptor.id,
        attachment.localFilePath,
    ) { mutableStateOf(false) }
    var controlsVisible by remember { mutableStateOf(true) }
    var speedMenu by remember { mutableStateOf(false) }
    var speed by remember { mutableFloatStateOf(1f) }
    var playing by remember { mutableStateOf(false) }
    var position by remember { mutableLongStateOf(0L) }
    var duration by remember { mutableLongStateOf(max(1L, attachment.descriptor.durationMillis ?: 1L)) }
    var dragging by remember { mutableStateOf(false) }

    LaunchedEffect(
        attachment.messageId,
        attachment.descriptor.id,
        suppliedFile,
        attachment.plaintext.size,
    ) {
        if (mediaFile != null || attachment.plaintext.isEmpty()) return@LaunchedEffect
        val created = withContext(Dispatchers.IO) {
            File(context.cacheDir, "viewer-${UUID.randomUUID()}.mp4").also {
                it.writeBytes(attachment.plaintext)
            }
        }
        ownsTemporaryFile = true
        mediaFile = created
    }
    val player = remember(mediaFile) {
        mediaFile?.let { file ->
            ExoPlayer.Builder(context).build().apply {
                setMediaItem(MediaItem.fromUri(Uri.fromFile(file)))
                repeatMode = Player.REPEAT_MODE_ONE
                prepare()
                playWhenReady = true
            }
        }
    }
    DisposableEffect(player, mediaFile, ownsTemporaryFile) {
        onDispose {
            player?.release()
            if (ownsTemporaryFile) mediaFile?.delete()
        }
    }
    LaunchedEffect(speed, player) {
        player?.playbackParameters = PlaybackParameters(speed)
    }
    LaunchedEffect(player) {
        while (player != null) {
            playing = player.isPlaying
            if (!dragging) position = player.currentPosition.coerceAtLeast(0L)
            duration = player.duration.takeIf { it > 0L } ?: duration
            delay(200)
        }
    }
    LaunchedEffect(controlsVisible, playing, speedMenu) {
        if (controlsVisible && playing && !speedMenu) {
            delay(3_000)
            controlsVisible = false
        }
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black)
            .pointerInput(player) {
                detectTapGestures(
                    onTap = { controlsVisible = !controlsVisible },
                    onDoubleTap = { tap ->
                        val active = player
                        if (active != null) {
                            val delta = if (tap.x < size.width / 2f) -10_000L else 10_000L
                            active.seekTo((active.currentPosition + delta).coerceIn(0L, duration))
                            controlsVisible = true
                        }
                    },
                )
            },
        contentAlignment = Alignment.Center,
    ) {
        if (player == null) {
            CircularProgressIndicator()
        } else {
            AndroidView(
                factory = { ctx ->
                    PlayerView(ctx).apply {
                        this.player = player
                        useController = false
                        resizeMode = AspectRatioFrameLayout.RESIZE_MODE_FIT
                        setShowBuffering(PlayerView.SHOW_BUFFERING_ALWAYS)
                        setShutterBackgroundColor(android.graphics.Color.BLACK)
                    }
                },
                update = { it.player = player },
                modifier = Modifier.fillMaxSize(),
            )
            if (controlsVisible) {
                Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.22f)))
                Row(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalArrangement = Arrangement.spacedBy(24.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    PlayerRoundButton(label = "−10") {
                        player.seekTo((player.currentPosition - 10_000L).coerceAtLeast(0L))
                    }
                    Surface(
                        modifier = Modifier.size(68.dp).clickable {
                            if (player.isPlaying) player.pause() else player.play()
                            controlsVisible = true
                        },
                        color = Color.Black.copy(alpha = 0.72f),
                        shape = CircleShape,
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            if (playing) PauseIcon(Modifier.size(30.dp), Color.White)
                            else PlayIcon(Modifier.size(30.dp), Color.White)
                        }
                    }
                    PlayerRoundButton(label = "+10") {
                        player.seekTo((player.currentPosition + 10_000L).coerceAtMost(duration))
                    }
                }
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .padding(horizontal = 10.dp, vertical = 18.dp),
                    color = Color.Black.copy(alpha = 0.72f),
                    shape = RoundedCornerShape(18.dp),
                ) {
                    Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                        Slider(
                            value = position.coerceIn(0L, duration).toFloat(),
                            onValueChange = {
                                dragging = true
                                position = it.toLong()
                            },
                            onValueChangeFinished = {
                                player.seekTo(position)
                                dragging = false
                            },
                            valueRange = 0f..duration.coerceAtLeast(1L).toFloat(),
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                "${formatPlayerTime(position)} / ${formatPlayerTime(duration)}",
                                style = MaterialTheme.typography.labelMedium,
                                modifier = Modifier.weight(1f),
                            )
                            Box {
                                Surface(
                                    modifier = Modifier.clickable {
                                        speedMenu = true
                                        controlsVisible = true
                                    },
                                    color = Color.White.copy(alpha = 0.12f),
                                    shape = RoundedCornerShape(10.dp),
                                ) {
                                    Text(
                                        "${formatSpeed(speed)}×",
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                }
                                DropdownMenu(expanded = speedMenu, onDismissRequest = { speedMenu = false }) {
                                    listOf(0.25f, 0.5f, 0.75f, 1f, 1.25f, 1.5f, 2f).forEach { value ->
                                        DropdownMenuItem(
                                            text = { Text("${formatSpeed(value)}×") },
                                            onClick = {
                                                speed = value
                                                speedMenu = false
                                                controlsVisible = true
                                            },
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PlayerRoundButton(label: String, onClick: () -> Unit) {
    Surface(
        modifier = Modifier.size(54.dp).clickable(onClick = onClick),
        color = Color.Black.copy(alpha = 0.68f),
        shape = CircleShape,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(label, color = Color.White, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun FullscreenAudioPlayer(attachment: OpenedAttachment) {
    val context = LocalContext.current
    var tempFile by remember(attachment.messageId, attachment.descriptor.id) { mutableStateOf<File?>(null) }
    val player = remember(tempFile) {
        tempFile?.let { file ->
            ExoPlayer.Builder(context).build().apply {
                setMediaItem(MediaItem.fromUri(Uri.fromFile(file)))
                prepare()
            }
        }
    }
    var playing by remember(player) { mutableStateOf(false) }
    var position by remember(player) { mutableFloatStateOf(0f) }
    var duration by remember(player) { mutableFloatStateOf(max(1L, attachment.descriptor.durationMillis ?: 1L).toFloat()) }

    LaunchedEffect(attachment.messageId, attachment.descriptor.id) {
        tempFile = withContext(Dispatchers.IO) {
            File(context.cacheDir, "audio-${UUID.randomUUID()}.bin").also { it.writeBytes(attachment.plaintext) }
        }
    }
    DisposableEffect(player, tempFile) {
        onDispose {
            player?.release()
            tempFile?.delete()
        }
    }
    LaunchedEffect(player) {
        while (player != null) {
            playing = player.isPlaying
            position = player.currentPosition.coerceAtLeast(0L).toFloat()
            duration = player.duration.takeIf { it > 0L }?.toFloat() ?: duration
            delay(200)
        }
    }

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Surface(color = Color(0xFF20242A), shape = RoundedCornerShape(28.dp)) {
            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(0.88f),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(attachment.caption.ifBlank { attachment.descriptor.name }, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(18.dp))
                Slider(
                    value = position.coerceIn(0f, duration.coerceAtLeast(1f)),
                    onValueChange = { position = it },
                    onValueChangeFinished = { player?.seekTo(position.toLong()) },
                    valueRange = 0f..duration.coerceAtLeast(1f),
                )
                Surface(
                    modifier = Modifier.size(58.dp).clickable {
                        player?.let { active -> if (active.isPlaying) active.pause() else active.play() }
                    },
                    color = MaterialTheme.colorScheme.primary,
                    shape = CircleShape,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        if (playing) PauseIcon(Modifier.size(25.dp), MaterialTheme.colorScheme.onPrimary)
                        else PlayIcon(Modifier.size(25.dp), MaterialTheme.colorScheme.onPrimary)
                    }
                }
            }
        }
    }
}

@Composable
private fun FileViewer(attachment: OpenedAttachment) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Surface(color = Color(0xFF20242A), shape = RoundedCornerShape(24.dp)) {
            Column(
                modifier = Modifier.padding(28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(attachment.descriptor.name, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                Text(attachment.descriptor.mimeType, color = Color.White.copy(alpha = 0.65f))
                Text(formatFileSize(attachment.descriptor.originalSize), color = Color.White.copy(alpha = 0.65f))
            }
        }
    }
}

private fun saveToSharedStorage(context: Context, attachment: OpenedAttachment): Uri {
    val resolver = context.contentResolver
    val mime = attachment.descriptor.mimeType
    val collection = when {
        mime.startsWith("image/") -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        mime.startsWith("video/") -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
        mime.startsWith("audio/") -> MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> MediaStore.Downloads.EXTERNAL_CONTENT_URI
        else -> MediaStore.Files.getContentUri("external")
    }
    val values = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, attachment.descriptor.name)
        put(MediaStore.MediaColumns.MIME_TYPE, mime)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val relativePath = when {
                mime.startsWith("image/") -> "Pictures/FedMes"
                mime.startsWith("video/") -> "Movies/FedMes"
                mime.startsWith("audio/") -> "Music/FedMes"
                else -> "Download/FedMes"
            }
            put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
    }
    val uri = resolver.insert(collection, values) ?: error("Не удалось создать файл")
    try {
        resolver.openOutputStream(uri, "w")?.use { output ->
            val localFile = attachment.localFilePath
                ?.let(::File)
                ?.takeIf { it.isFile && it.length() > 0L }
            if (localFile != null) {
                localFile.inputStream().buffered().use { input -> input.copyTo(output) }
            } else {
                output.write(attachment.plaintext)
            }
            output.flush()
        } ?: error("Не удалось открыть файл для записи")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            resolver.update(
                uri,
                ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) },
                null,
                null,
            )
        }
        return uri
    } catch (error: Exception) {
        resolver.delete(uri, null, null)
        throw error
    }
}

private fun formatPlayerTime(milliseconds: Long): String {
    val totalSeconds = (milliseconds.coerceAtLeast(0L) / 1_000L)
    val hours = totalSeconds / 3_600L
    val minutes = (totalSeconds % 3_600L) / 60L
    val seconds = totalSeconds % 60L
    return if (hours > 0L) "%d:%02d:%02d".format(hours, minutes, seconds)
    else "%d:%02d".format(minutes, seconds)
}

private fun formatSpeed(value: Float): String = if (value % 1f == 0f) {
    value.toInt().toString()
} else {
    String.format(Locale.US, "%.2f", value).trimEnd('0').trimEnd('.')
}

private fun formatFileSize(bytes: Long): String = when {
    bytes >= 1024L * 1024L * 1024L -> "%.1f ГБ".format(bytes / (1024.0 * 1024.0 * 1024.0))
    bytes >= 1024L * 1024L -> "%.1f МБ".format(bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> "%.1f КБ".format(bytes / 1024.0)
    else -> "$bytes Б"
}

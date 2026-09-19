package com.fedmes.app.ui.messenger

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaDataSource
import android.media.MediaPlayer
import android.net.Uri
import android.view.LayoutInflater
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.fedmes.app.R
import com.fedmes.app.messaging.DecryptedMessage
import com.fedmes.app.messaging.MediaDescriptor
import com.fedmes.app.messaging.MessageKind
import com.fedmes.app.messaging.RoundVideoShape
import com.fedmes.app.messaging.VideoPlaybackCache
import com.fedmes.app.ui.components.PauseIcon
import com.fedmes.app.ui.components.PlayIcon
import com.fedmes.app.ui.components.SpoilerIcon
import androidx.media3.common.MediaItem
import androidx.media3.common.Player
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.PI
import kotlin.math.min
import kotlin.math.sin

@Composable
fun TextSpoilerMessageBody(message: DecryptedMessage) {
    var revealed by remember(message.id) { mutableStateOf(false) }
    if (!message.content.spoiler || revealed) {
        RichMessageText(message.content.text, message.content.textEntities)
        return
    }
    val spoilerColor = MaterialTheme.colorScheme.onSurface
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f))
            .clickable { revealed = true }
            .padding(horizontal = 10.dp, vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            var index = 0
            val step = 7f
            var y = 0f
            while (y < size.height) {
                var x = 0f
                while (x < size.width) {
                    val phase = ((index * 43 + message.id.hashCode()) and 0xFF) / 255f
                    drawCircle(
                        color = spoilerColor.copy(alpha = 0.12f + phase * 0.42f),
                        radius = 1f + phase * 2.2f,
                        center = Offset(x + phase * 4f, y + (1f - phase) * 4f),
                    )
                    index++
                    x += step
                }
                y += step
            }
        }
        Text(
            "Нажмите, чтобы показать",
            color = MaterialTheme.colorScheme.onSurface,
            style = MaterialTheme.typography.labelMedium,
        )
    }
}

@Composable
fun MediaGroupMessageBody(
    message: DecryptedMessage,
    currentUsername: String,
    onOpen: (MediaDescriptor) -> Unit,
    onLoadPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    onLoadBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
) {
    val items = message.content.mediaItems.ifEmpty { message.content.media?.let(::listOf).orEmpty() }.take(10)
    if (items.isEmpty()) return
    var locallyRevealed by rememberSaveable(message.id) {
        mutableStateOf(LocalSpoilerRevealStore.isRevealed(message.id))
    }
    val hidden = message.content.spoiler &&
        message.senderUsername != currentUsername &&
        !locallyRevealed
    val rows = albumRows(items.size)
    var cursor = 0
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        rows.forEachIndexed { rowIndex, count ->
            val rowItems = items.subList(cursor, cursor + count)
            cursor += count
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                rowItems.forEach { descriptor ->
                    val singleRatio = if (items.size == 1) {
                        val width = descriptor.width?.coerceAtLeast(1) ?: 4
                        val height = descriptor.height?.coerceAtLeast(1) ?: 3
                        (width.toFloat() / height.toFloat()).coerceIn(0.72f, 1.55f)
                    } else {
                        1f
                    }
                    if (!hidden && descriptor.mimeType.startsWith("video/")) {
                        OrdinaryVideoPrefetchEffect(message, descriptor, onLoadBytes)
                    }
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .then(
                                if (items.size == 1) {
                                    Modifier.aspectRatio(singleRatio)
                                } else {
                                    Modifier.height(albumRowHeight(items.size, rowIndex))
                                },
                            )
                            .clip(RoundedCornerShape(8.dp))
                            .clickable {
                                if (hidden) {
                                    LocalSpoilerRevealStore.reveal(message.id)
                                    locallyRevealed = true
                                } else {
                                    onOpen(descriptor)
                                }
                            },
                    ) {
                        if (hidden) {
                            MediaSpoilerCover(
                                seed = message.id.hashCode() xor descriptor.id.hashCode(),
                                onReveal = {
                                    LocalSpoilerRevealStore.reveal(message.id)
                                    locallyRevealed = true
                                },
                            )
                        } else {
                            RemoteMediaPreview(
                                message = message,
                                descriptor = descriptor,
                                onLoadPreview = onLoadPreview,
                                modifier = Modifier.matchParentSize(),
                            )
                            if (descriptor.mimeType.startsWith("video/")) {
                                Surface(
                                    modifier = Modifier.align(Alignment.Center).size(44.dp),
                                    color = Color.Black.copy(alpha = 0.56f),
                                    shape = CircleShape,
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        PlayIcon(Modifier.size(21.dp), Color.White)
                                    }
                                }
                                descriptor.durationMillis?.let { duration ->
                                    Surface(
                                        modifier = Modifier.align(Alignment.BottomStart).padding(6.dp),
                                        color = Color.Black.copy(alpha = 0.62f),
                                        shape = RoundedCornerShape(8.dp),
                                    ) {
                                        Text(
                                            formatMediaDuration(duration),
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                            color = Color.White,
                                            style = MaterialTheme.typography.labelSmall,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (message.content.text.isNotBlank()) {
            RichMessageText(message.content.text, message.content.textEntities, modifier = Modifier.padding(top = 5.dp))
        }
    }
}

@Composable
private fun OrdinaryVideoPrefetchEffect(
    message: DecryptedMessage,
    descriptor: MediaDescriptor,
    onLoadBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
) {
    val context = LocalContext.current
    val cacheKey = remember(message.id, descriptor.id) {
        VideoPlaybackCache.key(message.id, descriptor.id)
    }
    val extension = remember(descriptor.name) {
        VideoPlaybackCache.extension(descriptor.name)
    }
    LaunchedEffect(cacheKey, extension) {
        if (descriptor.originalSize > MAX_AUTOMATIC_VIDEO_PREFETCH_BYTES) return@LaunchedEffect
        if (VideoPlaybackCache.find(context, cacheKey, extension) == null) {
            runCatching {
                VideoPlaybackCache.load(context, cacheKey, extension) {
                    onLoadBytes(message, descriptor)
                }
            }
        }
    }
}

@Composable
fun RemoteMediaPreview(
    message: DecryptedMessage,
    descriptor: MediaDescriptor,
    onLoadPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    modifier: Modifier,
) {
    val previewState by produceState<RemotePreviewState>(
        initialValue = RemotePreviewState.Loading,
        message.id,
        descriptor.id,
    ) {
        value = withContext(Dispatchers.IO) {
            val bytes = runCatching { onLoadPreview(message, descriptor) }.getOrNull()
                ?: return@withContext RemotePreviewState.Failed
            try {
                decodePreviewBitmap(bytes)
                    ?.let(RemotePreviewState::Ready)
                    ?: RemotePreviewState.Failed
            } finally {
                bytes.fill(0)
            }
        }
    }
    val bitmap = (previewState as? RemotePreviewState.Ready)?.bitmap
    DisposableEffect(bitmap) {
        onDispose { bitmap?.let { if (!it.isRecycled) it.recycle() } }
    }
    when (val state = previewState) {
        RemotePreviewState.Loading -> {
            Box(modifier.background(MaterialTheme.colorScheme.surfaceVariant), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
            }
        }
        RemotePreviewState.Failed -> {
            Box(modifier.background(MaterialTheme.colorScheme.surfaceVariant), contentAlignment = Alignment.Center) {
                Text(
                    if (descriptor.mimeType.startsWith("video/")) "Видео" else "Медиа",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
        }
        is RemotePreviewState.Ready -> {
            Image(
                bitmap = state.bitmap.asImageBitmap(),
                contentDescription = descriptor.name,
                modifier = modifier,
                contentScale = ContentScale.Crop,
            )
        }
    }
}

private fun decodePreviewBitmap(bytes: ByteArray): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    var sample = 1
    val largest = maxOf(bounds.outWidth, bounds.outHeight)
    while (largest / sample > MAX_PREVIEW_DECODE_EDGE) sample *= 2
    val options = BitmapFactory.Options().apply {
        inSampleSize = sample.coerceAtLeast(1)
        inPreferredConfig = Bitmap.Config.RGB_565
    }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
}

private const val MAX_PREVIEW_DECODE_EDGE = 960
private const val MAX_AUTOMATIC_VIDEO_PREFETCH_BYTES = 48L * 1024L * 1024L

private sealed interface RemotePreviewState {
    data object Loading : RemotePreviewState
    data object Failed : RemotePreviewState
    data class Ready(val bitmap: Bitmap) : RemotePreviewState
}

@Composable
private fun MediaSpoilerCover(
    seed: Int,
    onReveal: () -> Unit,
) {
    val transition = rememberInfiniteTransition(label = "media-spoiler")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1_700),
            repeatMode = RepeatMode.Restart,
        ),
        label = "media-spoiler-phase",
    )
    val palette = remember(seed) {
        val palettes = listOf(
            listOf(Color(0xFF325F74), Color(0xFF6D5B86), Color(0xFF4D8594), Color(0xFF8A6575)),
            listOf(Color(0xFF3E4F77), Color(0xFF597D72), Color(0xFF765A82), Color(0xFF46718A)),
            listOf(Color(0xFF75536A), Color(0xFF3E7080), Color(0xFF6B7463), Color(0xFF4B557C)),
        )
        palettes[(seed and Int.MAX_VALUE) % palettes.size]
    }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(palette.first())
            .clickable(onClick = onReveal),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            drawRect(palette.first())
            repeat(14) { index ->
                val xUnit = spoilerUnit(seed xor (index * 0x45D9F3B))
                val yUnit = spoilerUnit(seed xor (index * 0x119DE1F3))
                val wave = sin(phase * 2f * PI + index * 0.71f).toFloat()
                val radius = size.minDimension * (0.16f + spoilerUnit(seed + index * 97) * 0.22f)
                drawCircle(
                    color = palette[index % palette.size].copy(alpha = 0.22f),
                    radius = radius,
                    center = Offset(
                        x = (xUnit * size.width + wave * size.width * 0.035f).coerceIn(0f, size.width),
                        y = (yUnit * size.height - wave * size.height * 0.025f).coerceIn(0f, size.height),
                    ),
                )
            }
            val particleCount = ((size.width * size.height) / 1_450f).toInt().coerceIn(80, 360)
            repeat(particleCount) { index ->
                val xUnit = spoilerUnit(seed + index * 1_103)
                val yUnit = spoilerUnit(seed xor (index * 7_919))
                val wave = sin(phase * 2f * PI + index * 0.37f).toFloat()
                val pulse = (wave + 1f) * 0.5f
                drawCircle(
                    color = Color.White.copy(alpha = 0.10f + pulse * 0.28f),
                    radius = 1.1f + spoilerUnit(seed + index * 313) * 3.2f,
                    center = Offset(
                        x = (xUnit * size.width + wave * 7f).coerceIn(0f, size.width),
                        y = (yUnit * size.height + wave * 5f).coerceIn(0f, size.height),
                    ),
                )
            }
        }
        Surface(
            modifier = Modifier.padding(12.dp),
            color = Color.Black.copy(alpha = 0.58f),
            contentColor = Color.White,
            shape = RoundedCornerShape(20.dp),
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SpoilerIcon(Modifier.size(21.dp), Color.White)
                Text(
                    "Нажмите, чтобы показать",
                    color = Color.White,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
        }
    }
}

private object LocalSpoilerRevealStore {
    private val revealedMessageIds = ConcurrentHashMap.newKeySet<String>()

    fun isRevealed(messageId: String): Boolean = messageId in revealedMessageIds

    fun reveal(messageId: String) {
        revealedMessageIds += messageId
    }
}

private fun spoilerUnit(value: Int): Float {
    var mixed = value
    mixed = mixed xor (mixed ushr 16)
    mixed *= 0x45D9F3B
    mixed = mixed xor (mixed ushr 16)
    return ((mixed ushr 8) and 0xFFFF) / 65_535f
}

@Composable
fun AudioWaveformMessageBody(
    message: DecryptedMessage,
    descriptor: MediaDescriptor,
    onLoadBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
) {
    val scope = rememberCoroutineScope()
    var source by remember(message.id, descriptor.id) { mutableStateOf<MemoryMediaDataSource?>(null) }
    var player by remember(message.id, descriptor.id) { mutableStateOf<MediaPlayer?>(null) }
    var loading by remember(message.id, descriptor.id) { mutableStateOf(false) }
    var prepared by remember(message.id, descriptor.id) { mutableStateOf(false) }
    var playing by remember(message.id, descriptor.id) { mutableStateOf(false) }
    var position by remember(message.id, descriptor.id) { mutableFloatStateOf(0f) }
    var duration by remember(message.id, descriptor.id) {
        mutableFloatStateOf((message.content.durationMillis ?: descriptor.durationMillis ?: 1L).toFloat())
    }

    DisposableEffect(message.id, descriptor.id) {
        onDispose {
            runCatching { player?.stop() }
            player?.release()
            source?.close()
        }
    }
    LaunchedEffect(playing, prepared) {
        while (playing && prepared) {
            position = player?.currentPosition?.toFloat() ?: 0f
            delay(100)
        }
    }

    fun togglePlayback() {
        val active = player
        if (active != null && prepared) {
            if (active.isPlaying) {
                active.pause()
                playing = false
            } else {
                active.start()
                playing = true
            }
            return
        }
        if (loading) return
        loading = true
        scope.launch {
            val bytes = runCatching { onLoadBytes(message, descriptor) }.getOrNull()
            if (bytes == null) {
                loading = false
                return@launch
            }
            val nextSource = MemoryMediaDataSource(bytes)
            val nextPlayer = MediaPlayer()
            val configured = runCatching {
                nextPlayer.setDataSource(nextSource)
                nextPlayer.setOnPreparedListener {
                    prepared = true
                    loading = false
                    duration = it.duration.coerceAtLeast(1).toFloat()
                    it.start()
                    playing = true
                }
                nextPlayer.setOnCompletionListener {
                    playing = false
                    position = 0f
                    runCatching { it.seekTo(0) }
                }
                nextPlayer.setOnErrorListener { failedPlayer, _, _ ->
                    playing = false
                    prepared = false
                    loading = false
                    runCatching { failedPlayer.reset() }
                    true
                }
                nextPlayer.prepareAsync()
            }.isSuccess
            if (configured) {
                source = nextSource
                player = nextPlayer
            } else {
                loading = false
                nextPlayer.release()
                nextSource.close()
            }
        }
    }

    Row(verticalAlignment = Alignment.CenterVertically) {
        Surface(
            modifier = Modifier.size(44.dp).clickable(onClick = ::togglePlayback),
            shape = CircleShape,
            color = MaterialTheme.colorScheme.primary,
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (loading) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                } else if (playing) {
                    PauseIcon(Modifier.size(20.dp), MaterialTheme.colorScheme.onPrimary)
                } else {
                    PlayIcon(Modifier.size(20.dp), MaterialTheme.colorScheme.onPrimary)
                }
            }
        }
        Spacer(Modifier.width(9.dp))
        Column(Modifier.weight(1f)) {
            val waveform = message.content.waveform.ifEmpty { defaultWaveform(descriptor.id) }
            WaveformCanvas(waveform, (position / duration).coerceIn(0f, 1f))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    if (message.content.kind == MessageKind.VOICE) formatMediaDuration(position.toLong()) else descriptor.name,
                    style = MaterialTheme.typography.labelSmall,
                    maxLines = 1,
                )
                Text(formatMediaDuration(duration.toLong()), style = MaterialTheme.typography.labelSmall)
            }
        }
    }
    if (message.content.text.isNotBlank()) {
        RichMessageText(message.content.text, message.content.textEntities, modifier = Modifier.padding(top = 5.dp))
    }
}

@Composable
private fun WaveformCanvas(waveform: List<Int>, progress: Float) {
    val activeColor = MaterialTheme.colorScheme.primary
    val inactiveColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.28f)
    Canvas(
        Modifier
            .fillMaxWidth()
            .height(28.dp),
    ) {
        val count = waveform.size.coerceAtLeast(1)
        val barWidth = (size.width / (count * 1.7f)).coerceAtLeast(1f)
        val gap = (size.width - barWidth * count) / count
        waveform.forEachIndexed { index, level ->
            val normalized = level.coerceIn(4, 100) / 100f
            val barHeight = (size.height * normalized).coerceAtLeast(3f)
            val x = index * (barWidth + gap)
            drawRoundRect(
                color = if (index.toFloat() / count <= progress) activeColor else inactiveColor,
                topLeft = Offset(x, (size.height - barHeight) / 2f),
                size = androidx.compose.ui.geometry.Size(barWidth, barHeight),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(barWidth / 2f),
            )
        }
    }
}

@androidx.annotation.OptIn(UnstableApi::class)
@Composable
fun RoundVideoMessageBody(
    message: DecryptedMessage,
    descriptor: MediaDescriptor,
    onLoadPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    onLoadBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val scope = rememberCoroutineScope()
    var expanded by rememberSaveable(message.id) { mutableStateOf(false) }
    val roundShape = when (message.content.roundVideoShape) {
        RoundVideoShape.SQUARE -> RoundVideoShape.SQUARE
        RoundVideoShape.CIRCLE, RoundVideoShape.HEART, null -> RoundVideoShape.CIRCLE
    }
    val shape = roundMessageShape(roundShape)
    val extension = remember(descriptor.name) {
        descriptor.name
            .substringAfterLast('.', "mp4")
            .lowercase()
            .takeIf { it.length in 2..6 && it.all(Char::isLetterOrDigit) }
            ?: "mp4"
    }
    val cacheKey = remember(message.id, descriptor.id, roundShape) {
        "${message.id}-${descriptor.id}-${roundShape.name.lowercase()}"
    }

    var mediaFile by remember(cacheKey) {
        mutableStateOf(RoundVideoPlaybackCache.find(context, cacheKey, extension))
    }
    var loading by remember(cacheKey) { mutableStateOf(false) }
    var startWhenReady by remember(cacheKey) { mutableStateOf(false) }
    var loadFailed by remember(cacheKey) { mutableStateOf(false) }
    var playing by remember(cacheKey) { mutableStateOf(false) }
    var ended by remember(cacheKey) { mutableStateOf(false) }
    var position by remember(cacheKey) { mutableFloatStateOf(0f) }
    var duration by remember(cacheKey) {
        mutableFloatStateOf(
            (message.content.durationMillis ?: descriptor.durationMillis ?: 1L)
                .coerceAtLeast(1L)
                .toFloat(),
        )
    }

    suspend fun ensureLoaded() {
        if (mediaFile != null || loading) return
        loading = true
        loadFailed = false
        runCatching {
            RoundVideoPlaybackCache.load(context, cacheKey, extension) {
                onLoadBytes(message, descriptor)
            }
        }.onSuccess { file ->
            mediaFile = file
        }.onFailure {
            loadFailed = true
        }
        loading = false
    }

    // LazyColumn composes only visible and near-visible rows. Prefetching here makes the first tap
    // start as soon as the device and network can authenticate the complete encrypted blob.
    LaunchedEffect(cacheKey) {
        if (mediaFile == null && descriptor.originalSize <= MAX_AUTOMATIC_VIDEO_PREFETCH_BYTES) {
            delay(80)
            ensureLoaded()
        }
    }

    val player = remember(mediaFile, roundShape) {
        mediaFile?.let { file ->
            ExoPlayer.Builder(context).build().apply {
                setMediaItem(MediaItem.fromUri(Uri.fromFile(file)))
                repeatMode = Player.REPEAT_MODE_OFF
                playWhenReady = false
                prepare()
            }
        }
    }

    DisposableEffect(player) {
        val active = player
        if (active == null) {
            onDispose {}
        } else {
            val listener = object : Player.Listener {
                override fun onIsPlayingChanged(isPlaying: Boolean) {
                    playing = isPlaying
                }

                override fun onPlaybackStateChanged(playbackState: Int) {
                    ended = playbackState == Player.STATE_ENDED
                    if (ended) {
                        playing = false
                        position = duration
                        expanded = false
                    }
                }
            }
            active.addListener(listener)
            onDispose {
                active.removeListener(listener)
                active.release()
            }
        }
    }

    LaunchedEffect(player, startWhenReady) {
        val active = player ?: return@LaunchedEffect
        if (!startWhenReady) return@LaunchedEffect
        if (active.playbackState == Player.STATE_ENDED || ended) {
            active.seekTo(0L)
            active.prepare()
            position = 0f
            ended = false
        }
        active.playWhenReady = true
        active.play()
        startWhenReady = false
    }

    LaunchedEffect(player) {
        val active = player ?: return@LaunchedEffect
        while (kotlinx.coroutines.currentCoroutineContext().isActive) {
            val currentPosition = active.currentPosition.coerceAtLeast(0L).toFloat()
            if (position != currentPosition) position = currentPosition
            active.duration.takeIf { it > 0L }?.toFloat()?.let { currentDuration ->
                if (duration != currentDuration) duration = currentDuration
            }
            val isPlayingNow = active.isPlaying
            if (playing != isPlayingNow) playing = isPlayingNow
            val isEndedNow = active.playbackState == Player.STATE_ENDED
            if (ended != isEndedNow) ended = isEndedNow
            delay(if (isPlayingNow) 80 else 350)
        }
    }

    fun togglePlayback() {
        val active = player
        if (active == null) {
            startWhenReady = true
            if (!loading) {
                scope.launch { ensureLoaded() }
            }
            return
        }

        val nearEnd = active.duration > 0L &&
            active.currentPosition >= (active.duration - REPLAY_END_TOLERANCE_MILLIS).coerceAtLeast(0L)
        when {
            active.playbackState == Player.STATE_ENDED || ended || nearEnd -> {
                active.pause()
                active.seekTo(0L)
                active.prepare()
                position = 0f
                ended = false
                active.playWhenReady = true
                active.play()
            }
            active.isPlaying -> active.pause()
            else -> {
                if (active.playbackState == Player.STATE_IDLE) active.prepare()
                active.playWhenReady = true
                active.play()
            }
        }
    }

    val expandedSize = (configuration.screenWidthDp.dp - 28.dp).coerceAtMost(560.dp)
    val mediaSize by animateDpAsState(
        targetValue = if (expanded) expandedSize else 220.dp,
        animationSpec = spring(dampingRatio = 0.86f, stiffness = 420f),
        label = "round-video-size",
    )
    Box(
        modifier = Modifier
            .size(mediaSize)
            .graphicsLayer {
                this.shape = shape
                clip = true
            }
            .background(Color.Black)
            .clickable {
                if (!expanded) expanded = true
                togglePlayback()
            },
        contentAlignment = Alignment.Center,
    ) {
        if (player == null) {
            RemoteMediaPreview(message, descriptor, onLoadPreview, Modifier.matchParentSize())
        } else {
            AndroidView(
                modifier = Modifier
                    .matchParentSize()
                    .clip(shape),
                factory = { viewContext ->
                    (LayoutInflater.from(viewContext).inflate(
                        R.layout.view_round_video_player,
                        null,
                        false,
                    ) as PlayerView).apply {
                        setShutterBackgroundColor(android.graphics.Color.TRANSPARENT)
                        this.player = player
                    }
                },
                update = { it.player = player },
            )
        }

        if (loading && startWhenReady) {
            Surface(color = Color.Black.copy(alpha = 0.55f), shape = CircleShape) {
                Box(Modifier.size(50.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(25.dp),
                        color = Color.White,
                        strokeWidth = 2.5.dp,
                    )
                }
            }
        } else if (!playing) {
            Surface(color = Color.Black.copy(alpha = 0.48f), shape = CircleShape) {
                Box(Modifier.size(50.dp), contentAlignment = Alignment.Center) {
                    if (loadFailed) {
                        Text("!", color = Color.White, style = MaterialTheme.typography.titleMedium)
                    } else {
                        PlayIcon(Modifier.size(24.dp), Color.White)
                    }
                }
            }
        }

        val progress = (position / duration.coerceAtLeast(1f)).coerceIn(0f, 1f)
        if (roundShape == RoundVideoShape.CIRCLE) {
            Canvas(Modifier.matchParentSize().padding(3.dp)) {
                drawArc(
                    color = Color.White.copy(alpha = 0.92f),
                    startAngle = -90f,
                    sweepAngle = 360f * progress,
                    useCenter = false,
                    style = androidx.compose.ui.graphics.drawscope.Stroke(width = 3.dp.toPx()),
                )
            }
        } else {
            Box(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .height(3.dp)
                    .background(Color.White.copy(alpha = 0.18f)),
            ) {
                Box(
                    Modifier
                        .fillMaxWidth(progress)
                        .height(3.dp)
                        .background(Color.White),
                )
            }
        }
        Surface(
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 10.dp),
            color = Color.Black.copy(alpha = 0.48f),
            shape = RoundedCornerShape(10.dp),
        ) {
            Text(
                formatMediaDuration(
                    if (player == null || position <= 0f) duration.toLong() else position.toLong(),
                ),
                modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
                color = Color.White,
                style = MaterialTheme.typography.labelSmall,
            )
        }
        if (expanded) {
            Surface(
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(10.dp)
                    .size(34.dp)
                    .clickable { expanded = false },
                color = Color.Black.copy(alpha = 0.58f),
                shape = CircleShape,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text("↘", color = Color.White, style = MaterialTheme.typography.titleMedium)
                }
            }
        }
    }
}

@Composable
fun SpoilerRequestMessageBody(
    message: DecryptedMessage,
    currentUsername: String,
    targetMessage: DecryptedMessage?,
    onReveal: (DecryptedMessage, String) -> Unit,
) {
    // Compatibility rendering for messages created by FedMes 0.6.5 and earlier.
    // New clients reveal media locally by tapping the spoiler and never create this message kind.
    Text("Спойлер открывается нажатием на медиа")
}

private fun albumRows(count: Int): List<Int> = when (count.coerceIn(1, 10)) {
    1 -> listOf(1)
    2 -> listOf(2)
    3 -> listOf(1, 2)
    4 -> listOf(2, 2)
    5 -> listOf(2, 3)
    6 -> listOf(3, 3)
    7 -> listOf(1, 3, 3)
    8 -> listOf(2, 3, 3)
    9 -> listOf(3, 3, 3)
    else -> listOf(2, 4, 4)
}

private fun albumRowHeight(total: Int, rowIndex: Int) = when {
    total == 3 && rowIndex == 0 -> 190.dp
    total == 7 && rowIndex == 0 -> 180.dp
    total <= 4 -> 150.dp
    else -> 112.dp
}

private fun roundMessageShape(shape: RoundVideoShape): Shape = when (shape) {
    RoundVideoShape.CIRCLE, RoundVideoShape.HEART -> CircleShape
    RoundVideoShape.SQUARE -> RoundedCornerShape(24.dp)
}

private fun defaultWaveform(seed: String): List<Int> = List(48) { index ->
    val value = (seed.hashCode() * (index + 11) * 31).ushr(3)
    12 + (value % 82)
}

fun formatMediaDuration(durationMillis: Long): String {
    val totalSeconds = durationMillis.coerceAtLeast(0L) / 1000L
    return "%d:%02d".format(totalSeconds / 60L, totalSeconds % 60L)
}

private class MemoryMediaDataSource(private val bytes: ByteArray) : MediaDataSource() {
    @Throws(IOException::class)
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position < 0 || position >= bytes.size) return -1
        val count = min(size, bytes.size - position.toInt())
        bytes.copyInto(buffer, offset, position.toInt(), position.toInt() + count)
        return count
    }

    override fun getSize(): Long = bytes.size.toLong()

    override fun close() {
        bytes.fill(0)
    }
}

private const val REPLAY_END_TOLERANCE_MILLIS = 180L

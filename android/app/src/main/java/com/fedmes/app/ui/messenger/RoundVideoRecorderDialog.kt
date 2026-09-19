package com.fedmes.app.ui.messenger

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.media.MediaMetadataRetriever
import androidx.camera.core.CameraSelector
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.ExperimentalPersistentRecording
import androidx.camera.video.FallbackStrategy
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.camera.view.PreviewView
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
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
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.fedmes.app.messaging.MIN_ROUND_VIDEO_DURATION_MILLIS
import com.fedmes.app.messaging.RecordedMedia
import com.fedmes.app.messaging.RoundVideoShape
import com.fedmes.app.ui.components.CloseIcon
import com.fedmes.app.ui.components.PauseIcon
import com.fedmes.app.ui.components.PlayIcon
import com.fedmes.app.ui.components.SendIcon
import com.fedmes.app.ui.components.SwitchCameraIcon
import kotlinx.coroutines.delay
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID

@SuppressLint("MissingPermission")
@androidx.annotation.OptIn(ExperimentalPersistentRecording::class)
@Composable
fun RoundVideoRecorderDialog(
    initialShape: RoundVideoShape = RoundVideoShape.CIRCLE,
    onDismiss: () -> Unit,
    onRecorded: (RecordedMedia) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val mainExecutor = remember(context) { ContextCompat.getMainExecutor(context) }
    val outputFile = remember { File(context.cacheDir, "round-${UUID.randomUUID()}.mp4") }
    val openedAt = remember { System.currentTimeMillis() }
    val recorder = remember {
        Recorder.Builder()
            .setQualitySelector(
                QualitySelector.from(
                    Quality.SD,
                    FallbackStrategy.higherQualityOrLowerThan(Quality.SD),
                ),
            )
            .build()
    }
    val videoCapture = remember(recorder) { VideoCapture.withOutput(recorder) }
    var previewView by remember { mutableStateOf<PreviewView?>(null) }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    var recording by remember { mutableStateOf<Recording?>(null) }
    var recordingPaused by remember { mutableStateOf(false) }
    var shape by remember {
        mutableStateOf(if (initialShape == RoundVideoShape.HEART) RoundVideoShape.CIRCLE else initialShape)
    }
    var lensFacing by remember { mutableIntStateOf(CameraSelector.LENS_FACING_FRONT) }
    var cameraReady by remember { mutableStateOf(false) }
    var cameraSwitching by remember { mutableStateOf(false) }
    var cameraFailure by remember { mutableStateOf(false) }
    var startedAt by remember { mutableLongStateOf(0L) }
    var elapsed by remember { mutableLongStateOf(0L) }
    var finalAction by remember { mutableStateOf(FinalAction.NONE) }
    var pendingPreviewBytes by remember { mutableStateOf<ByteArray?>(null) }
    var retryToken by remember { mutableIntStateOf(0) }

    fun capturePreviewAndSend() {
        if (finalAction != FinalAction.NONE || recording == null) return
        pendingPreviewBytes = previewView?.bitmap?.let { bitmap ->
            ByteArrayOutputStream().use { output ->
                bitmap.compress(android.graphics.Bitmap.CompressFormat.JPEG, 76, output)
                output.toByteArray()
            }
        }
        finalAction = FinalAction.SEND
        recording?.stop()
    }

    fun cancelRecording() {
        if (finalAction != FinalAction.NONE) return
        if (recording == null) {
            onDismiss()
        } else {
            finalAction = FinalAction.CANCEL
            recording?.stop()
        }
    }

    fun startRecording() {
        if (!cameraReady || recording != null || finalAction != FinalAction.NONE) return
        val capture = videoCapture
        outputFile.delete()
        pendingPreviewBytes?.fill(0)
        pendingPreviewBytes = null
        elapsed = 0L
        recordingPaused = false
        var pending = capture.output.prepareRecording(
            context,
            FileOutputOptions.Builder(outputFile).build(),
        )
        if (
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            pending = pending.withAudioEnabled()
        }
        pending = pending.asPersistentRecording()
        recording = pending.start(mainExecutor) { event ->
            elapsed = (event.recordingStats.recordedDurationNanos / 1_000_000L)
                .coerceAtLeast(0L)
            when (event) {
                is VideoRecordEvent.Start -> {
                    startedAt = System.currentTimeMillis()
                    recordingPaused = false
                }
                is VideoRecordEvent.Pause -> recordingPaused = true
                is VideoRecordEvent.Resume -> recordingPaused = false
                is VideoRecordEvent.Finalize -> {
                    recording = null
                    startedAt = 0L
                    recordingPaused = false
                    val action = finalAction
                    val actualDuration = maxOf(elapsed, readVideoDurationMillis(outputFile))
                    if (
                        action == FinalAction.SEND &&
                        !event.hasError() &&
                        outputFile.isFile &&
                        actualDuration >= MIN_ROUND_VIDEO_DURATION_MILLIS
                    ) {
                        val bytes = runCatching { outputFile.readBytes() }.getOrDefault(ByteArray(0))
                        if (bytes.isNotEmpty()) {
                            val previewBytes = pendingPreviewBytes
                            pendingPreviewBytes = null
                            outputFile.delete()
                            onRecorded(
                                RecordedMedia(
                                    name = "Видеосообщение-${System.currentTimeMillis()}.mp4",
                                    mimeType = "video/mp4",
                                    bytes = bytes,
                                    durationMillis = actualDuration,
                                    roundVideoShape = shape,
                                    previewBytes = previewBytes,
                                ),
                            )
                            return@start
                        }
                    }
                    outputFile.delete()
                    pendingPreviewBytes?.fill(0)
                    pendingPreviewBytes = null
                    elapsed = 0L
                    finalAction = FinalAction.NONE
                    if (action == FinalAction.CANCEL) {
                        onDismiss()
                    } else if (event.hasError()) {
                        cameraFailure = true
                    }
                }
            }
        }
    }

    LaunchedEffect(startedAt) {
        while (startedAt > 0L && finalAction == FinalAction.NONE) {
            if (elapsed >= MAX_ROUND_VIDEO_DURATION_MILLIS) {
                capturePreviewAndSend()
                break
            }
            delay(100)
        }
    }

    LaunchedEffect(cameraFailure) {
        if (cameraFailure) {
            delay(650)
            cameraFailure = false
            retryToken++
        }
    }

    LaunchedEffect(previewView, lensFacing, retryToken) {
        val view = previewView ?: return@LaunchedEffect
        cameraReady = false
        cameraSwitching = true
        val activeRecording = recording
        val resumeAfterRebind = activeRecording != null && startedAt > 0L && !recordingPaused
        if (resumeAfterRebind) {
            activeRecording.pause()
        }
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener(
            {
                runCatching {
                    val cameraProvider = future.get()
                    provider = cameraProvider
                    val selector = CameraSelector.Builder().requireLensFacing(lensFacing).build()
                    val selected = if (cameraProvider.hasCamera(selector)) {
                        selector
                    } else {
                        val fallbackLens = if (lensFacing == CameraSelector.LENS_FACING_FRONT) {
                            CameraSelector.LENS_FACING_BACK
                        } else {
                            CameraSelector.LENS_FACING_FRONT
                        }
                        lensFacing = fallbackLens
                        CameraSelector.Builder().requireLensFacing(fallbackLens).build()
                    }
                    val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(lifecycleOwner, selected, preview, videoCapture)
                    cameraReady = true
                    cameraSwitching = false
                    if (resumeAfterRebind && recording != null) {
                        recording?.resume()
                    }
                }.onFailure {
                    cameraReady = false
                    cameraSwitching = false
                    cameraFailure = true
                    if (resumeAfterRebind && recording != null) {
                        recording?.resume()
                    }
                }
            },
            mainExecutor,
        )
    }

    DisposableEffect(Unit) {
        onDispose {
            if (finalAction == FinalAction.NONE) finalAction = FinalAction.CANCEL
            recording?.stop()
            provider?.unbindAll()
            pendingPreviewBytes?.fill(0)
            pendingPreviewBytes = null
            outputFile.delete()
        }
    }

    Dialog(
        onDismissRequest = {
            if (System.currentTimeMillis() - openedAt > DISMISS_GUARD_MILLIS) cancelRecording()
        },
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnClickOutside = false,
        ),
    ) {
        Surface(color = Color.Transparent) {
            Box(Modifier.fillMaxSize()) {
                AndroidView(
                    factory = {
                        PreviewView(it).apply {
                            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                            scaleType = PreviewView.ScaleType.FILL_CENTER
                            previewView = this
                        }
                    },
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(330.dp)
                        .clip(roundShape(shape)),
                )
                if (!cameraReady) {
                    CircularProgressIndicator(
                        modifier = Modifier.align(Alignment.Center),
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                Row(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 28.dp, start = 16.dp, end = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Surface(
                        modifier = Modifier.size(44.dp).clickable(onClick = ::cancelRecording),
                        shape = CircleShape,
                        color = Color.Black.copy(alpha = 0.48f),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            CloseIcon(Modifier.size(22.dp), Color.White)
                        }
                    }
                    Spacer(Modifier.width(8.dp))
                    Surface(
                        modifier = Modifier.clickable(
                            enabled = recording == null,
                            onClick = {
                                shape = when (shape) {
                                    RoundVideoShape.CIRCLE -> RoundVideoShape.SQUARE
                                    RoundVideoShape.SQUARE, RoundVideoShape.HEART -> RoundVideoShape.CIRCLE
                                }
                            },
                        ),
                        color = Color.Black.copy(alpha = if (recording == null) 0.48f else 0.28f),
                        shape = RoundedCornerShape(22.dp),
                    ) {
                        Text(
                            shapeLabel(shape),
                            color = Color.White.copy(alpha = if (recording == null) 1f else 0.55f),
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 11.dp),
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    if (recording != null) {
                        Text(formatRecordingTime(elapsed), color = Color.White)
                        Spacer(Modifier.width(8.dp))
                    }
                    Surface(
                        modifier = Modifier
                            .size(44.dp)
                            .clickable(
                                enabled = cameraReady && !cameraSwitching && finalAction == FinalAction.NONE,
                                onClick = {
                                    val target = if (lensFacing == CameraSelector.LENS_FACING_FRONT) {
                                        CameraSelector.LENS_FACING_BACK
                                    } else {
                                        CameraSelector.LENS_FACING_FRONT
                                    }
                                    val selector = CameraSelector.Builder().requireLensFacing(target).build()
                                    if (runCatching { provider?.hasCamera(selector) == true }.getOrDefault(false)) {
                                        cameraSwitching = true
                                        lensFacing = target
                                    }
                                },
                            ),
                        shape = CircleShape,
                        color = Color.Black.copy(alpha = if (cameraReady && !cameraSwitching) 0.48f else 0.28f),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            SwitchCameraIcon(
                                Modifier.size(24.dp),
                                Color.White.copy(alpha = if (cameraReady && !cameraSwitching) 1f else 0.55f),
                            )
                        }
                    }
                }
                if (recording != null) {
                    Surface(
                        modifier = Modifier
                            .align(Alignment.BottomStart)
                            .padding(start = 26.dp, bottom = 40.dp)
                            .size(50.dp)
                            .clickable {
                                if (recordingPaused) recording?.resume() else recording?.pause()
                            },
                        shape = CircleShape,
                        color = Color.Black.copy(alpha = 0.56f),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            if (recordingPaused) {
                                PlayIcon(Modifier.size(22.dp), Color.White)
                            } else {
                                PauseIcon(Modifier.size(22.dp), Color.White)
                            }
                        }
                    }
                }
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 34.dp)
                        .size(68.dp)
                        .clickable(
                            enabled = cameraReady && finalAction == FinalAction.NONE,
                            onClick = {
                                if (recording == null) startRecording() else capturePreviewAndSend()
                            },
                        ),
                    shape = CircleShape,
                    color = if (recording == null) Color(0xFFE53935) else MaterialTheme.colorScheme.primary,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        if (recording == null) {
                            Surface(
                                modifier = Modifier.size(28.dp),
                                shape = CircleShape,
                                color = Color.White,
                            ) {}
                        } else {
                            SendIcon(Modifier.size(30.dp), MaterialTheme.colorScheme.onPrimary)
                        }
                    }
                }
            }
        }
    }
}

private fun roundShape(shape: RoundVideoShape): Shape = when (shape) {
    RoundVideoShape.CIRCLE, RoundVideoShape.HEART -> CircleShape
    RoundVideoShape.SQUARE -> RoundedCornerShape(26.dp)
}

private fun shapeLabel(shape: RoundVideoShape): String = when (shape) {
    RoundVideoShape.CIRCLE, RoundVideoShape.HEART -> "Круг"
    RoundVideoShape.SQUARE -> "Квадрат"
}

private fun readVideoDurationMillis(file: File): Long {
    if (!file.isFile || file.length() <= 0L) return 0L
    val retriever = MediaMetadataRetriever()
    return try {
        retriever.setDataSource(file.absolutePath)
        retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)
            ?.toLongOrNull()
            ?.coerceAtLeast(0L)
            ?: 0L
    } catch (_: RuntimeException) {
        0L
    } finally {
        runCatching { retriever.release() }
    }
}

private fun formatRecordingTime(millis: Long): String {
    val totalTenths = millis / 100L
    return "%02d:%02d.%d".format(totalTenths / 600L, (totalTenths / 10L) % 60L, totalTenths % 10L)
}

private const val MAX_ROUND_VIDEO_DURATION_MILLIS = 60_000L
private const val DISMISS_GUARD_MILLIS = 700L

private enum class FinalAction { NONE, SEND, CANCEL }

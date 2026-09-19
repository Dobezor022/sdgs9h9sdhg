package com.fedmes.app.calling

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Rect
import android.graphics.YuvImage
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.fedmes.app.messaging.CallMode
import com.fedmes.app.ui.fedui3.FedMes26CallControlTray
import com.fedmes.app.ui.fedui3.FedMes26CallMode
import com.fedmes.app.ui.fedui3.FedMes26Palette
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

class CallActions(
    val onAccept: () -> Unit,
    val onDecline: () -> Unit,
    val onEnd: () -> Unit,
    val onMute: (Boolean) -> Unit,
    val onSpeaker: (Boolean) -> Unit,
    val onCamera: (Boolean) -> Unit,
    val onPermissionsGranted: () -> Unit,
    val onVideoFrame: (ByteArray) -> Unit,
)

@Composable
fun FedMesCallScreen(
    state: CallUiState,
    actions: CallActions,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val palette = FedMes26Palette.Dark
    val required = remember(state.descriptor.mode) {
        if (state.descriptor.mode == CallMode.AUDIO) arrayOf(Manifest.permission.RECORD_AUDIO)
        else arrayOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA)
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        if (required.all { grants[it] == true || context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }) {
            actions.onPermissionsGranted()
        }
    }
    LaunchedEffect(state.descriptor.callId) {
        val missing = required.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) launcher.launch(missing.toTypedArray()) else actions.onPermissionsGranted()
    }

    Box(modifier.fillMaxSize().background(palette.background)) {
        val remoteBitmap = remember(state.remoteVideoFrame) {
            state.remoteVideoJpeg?.let { bytes -> runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }.getOrNull() }
        }
        if (state.descriptor.mode != CallMode.AUDIO && remoteBitmap != null) {
            Image(
                bitmap = remoteBitmap.asImageBitmap(),
                contentDescription = "Видео собеседника",
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.Crop,
            )
        } else {
            Column(
                Modifier.align(Alignment.Center).padding(bottom = 100.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    Modifier.size(126.dp).clip(CircleShape).background(palette.raised),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(state.peerTitle.take(1).uppercase(), color = palette.text, fontSize = 52.sp)
                }
                Spacer(Modifier.height(20.dp))
                Text(state.peerTitle, color = palette.text, fontSize = 24.sp)
                Spacer(Modifier.height(8.dp))
                Text(callStatus(state), color = palette.muted, fontSize = 14.sp)
                Spacer(Modifier.height(16.dp))
                Text("🔐 🐋 🔑 ✨", color = palette.text, fontSize = 20.sp)
            }
        }

        Column(
            Modifier.align(Alignment.TopCenter).fillMaxWidth().padding(top = 44.dp, start = 18.dp, end = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(state.peerTitle, color = Color.White, fontSize = 17.sp)
            Text(callStatus(state), color = Color(0xFFC7D1D9), fontSize = 12.sp)
        }

        if (state.cameraEnabled && state.descriptor.mode != CallMode.AUDIO &&
            context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        ) {
            Box(
                Modifier.align(Alignment.TopEnd).padding(top = 90.dp, end = 16.dp)
                    .size(width = 112.dp, height = 164.dp).clip(RoundedCornerShape(18.dp))
                    .background(palette.surface),
            ) {
                FedMesCallCameraPreview(
                    modifier = Modifier.fillMaxSize(),
                    onJpeg = actions.onVideoFrame,
                )
            }
        }

        if (state.phase == CallPhase.INCOMING) {
            Row(
                Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(24.dp, 24.dp, 24.dp, 44.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Button(
                    onClick = actions.onDecline,
                    modifier = Modifier.weight(1f).height(58.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE34B4B)),
                ) { Text("Отклонить") }
                Button(
                    onClick = actions.onAccept,
                    modifier = Modifier.weight(1f).height(58.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2FA866)),
                ) { Text("Принять") }
            }
        } else {
            FedMes26CallControlTray(
                mode = when (state.descriptor.mode) {
                    CallMode.AUDIO -> FedMes26CallMode.AUDIO
                    CallMode.VIDEO -> FedMes26CallMode.VIDEO
                    CallMode.GROUP -> FedMes26CallMode.GROUP
                },
                muted = state.muted,
                speaker = state.speakerEnabled,
                camera = state.cameraEnabled,
                modifier = Modifier.align(Alignment.BottomCenter).padding(horizontal = 8.dp, vertical = 24.dp),
                onMute = { actions.onMute(!state.muted) },
                onSpeaker = { actions.onSpeaker(!state.speakerEnabled) },
                onCamera = { actions.onCamera(!state.cameraEnabled) },
                onFlip = { /* Camera selector cycling is handled by the preview controller in the next session. */ },
                onEnd = actions.onEnd,
            )
        }
    }
}

private fun callStatus(state: CallUiState): String = when (state.phase) {
    CallPhase.INCOMING -> if (state.descriptor.mode == CallMode.AUDIO) "Входящий аудиозвонок" else "Входящий видеозвонок"
    CallPhase.OUTGOING -> "Вызов…"
    CallPhase.CONNECTING -> "Соединение…"
    CallPhase.ACTIVE -> "Защищённый звонок"
    CallPhase.RECONNECTING -> "Восстановление соединения…"
    CallPhase.ENDED -> "Звонок завершён"
    CallPhase.FAILED -> state.error ?: "Ошибка звонка"
}

@Composable
private fun FedMesCallCameraPreview(
    onJpeg: (ByteArray) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val previewView = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }
    val lastFrameNanos = remember { AtomicLong(0L) }

    DisposableEffect(lifecycleOwner) {
        val future = ProcessCameraProvider.getInstance(context)
        val listener = Runnable {
            val provider = runCatching { future.get() }.getOrNull() ?: return@Runnable
            val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
            val analysis = ImageAnalysis.Builder()
                .setTargetResolution(Size(640, 480))
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(executor) { image ->
                val now = System.nanoTime()
                val previous = lastFrameNanos.get()
                if (now - previous < 200_000_000L || !lastFrameNanos.compareAndSet(previous, now)) {
                    image.close()
                    return@setAnalyzer
                }
                try {
                    image.toJpeg(45)?.takeIf { it.size <= FedMesCallCoordinator.MAX_VIDEO_JPEG_BYTES }?.let(onJpeg)
                } finally {
                    image.close()
                }
            }
            runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_FRONT_CAMERA, preview, analysis)
            }
        }
        future.addListener(listener, ContextCompat.getMainExecutor(context))
        onDispose {
            runCatching { future.get().unbindAll() }
            executor.shutdownNow()
        }
    }

    androidx.compose.ui.viewinterop.AndroidView(factory = { previewView }, modifier = modifier)
}

private fun ImageProxy.toJpeg(quality: Int): ByteArray? {
    if (format != ImageFormat.YUV_420_888 || planes.size < 3) return null
    val nv21 = yuv420888ToNv21(this)
    return try {
        val out = ByteArrayOutputStream()
        YuvImage(nv21, ImageFormat.NV21, width, height, null)
            .compressToJpeg(Rect(0, 0, width, height), quality.coerceIn(25, 75), out)
        out.toByteArray()
    } finally { nv21.fill(0) }
}

private fun yuv420888ToNv21(image: ImageProxy): ByteArray {
    val width = image.width
    val height = image.height
    val out = ByteArray(width * height * 3 / 2)
    copyPlane(image.planes[0], width, height, out, 0, 1)
    val chromaOffset = width * height
    // NV21 is VU interleaved. Read each chroma pixel using each plane's row/pixel strides.
    var dst = chromaOffset
    val u = image.planes[1]
    val v = image.planes[2]
    val uBuffer = u.buffer.duplicate()
    val vBuffer = v.buffer.duplicate()
    for (row in 0 until height / 2) {
        for (col in 0 until width / 2) {
            val vi = row * v.rowStride + col * v.pixelStride
            val ui = row * u.rowStride + col * u.pixelStride
            out[dst++] = vBuffer.get(vi)
            out[dst++] = uBuffer.get(ui)
        }
    }
    return out
}

private fun copyPlane(
    plane: ImageProxy.PlaneProxy,
    width: Int,
    height: Int,
    output: ByteArray,
    offset: Int,
    outputStride: Int,
) {
    val buffer = plane.buffer.duplicate()
    var dst = offset
    for (row in 0 until height) {
        for (col in 0 until width) {
            output[dst] = buffer.get(row * plane.rowStride + col * plane.pixelStride)
            dst += outputStride
        }
    }
}

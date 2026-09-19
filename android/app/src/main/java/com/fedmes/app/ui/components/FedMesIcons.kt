package com.fedmes.app.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import com.fedmes.app.messaging.MessageDeliveryState

@Composable
fun BackIcon(modifier: Modifier = Modifier, color: Color) {
    LineIcon(modifier) { w, h, stroke ->
        drawLine(color, Offset(w * 0.72f, h * 0.18f), Offset(w * 0.30f, h * 0.50f), stroke, StrokeCap.Round)
        drawLine(color, Offset(w * 0.30f, h * 0.50f), Offset(w * 0.72f, h * 0.82f), stroke, StrokeCap.Round)
    }
}

@Composable
fun CloseIcon(modifier: Modifier = Modifier, color: Color) {
    LineIcon(modifier) { w, h, stroke ->
        drawLine(color, Offset(w * 0.25f, h * 0.25f), Offset(w * 0.75f, h * 0.75f), stroke, StrokeCap.Round)
        drawLine(color, Offset(w * 0.75f, h * 0.25f), Offset(w * 0.25f, h * 0.75f), stroke, StrokeCap.Round)
    }
}

@Composable
fun AttachIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.09f
        val path = Path().apply {
            moveTo(size.width * 0.66f, size.height * 0.26f)
            cubicTo(
                size.width * 0.86f,
                size.height * 0.45f,
                size.width * 0.72f,
                size.height * 0.78f,
                size.width * 0.48f,
                size.height * 0.78f,
            )
            cubicTo(
                size.width * 0.22f,
                size.height * 0.78f,
                size.width * 0.15f,
                size.height * 0.48f,
                size.width * 0.34f,
                size.height * 0.31f,
            )
            lineTo(size.width * 0.58f, size.height * 0.53f)
            cubicTo(
                size.width * 0.68f,
                size.height * 0.62f,
                size.width * 0.55f,
                size.height * 0.74f,
                size.width * 0.46f,
                size.height * 0.65f,
            )
            lineTo(size.width * 0.29f, size.height * 0.50f)
        }
        drawPath(path, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

@Composable
fun SendIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val path = Path().apply {
            moveTo(size.width * 0.12f, size.height * 0.16f)
            lineTo(size.width * 0.90f, size.height * 0.50f)
            lineTo(size.width * 0.12f, size.height * 0.84f)
            lineTo(size.width * 0.31f, size.height * 0.55f)
            lineTo(size.width * 0.62f, size.height * 0.50f)
            lineTo(size.width * 0.31f, size.height * 0.45f)
            close()
        }
        drawPath(path, color)
    }
}

@Composable
fun ReplyIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.09f
        drawLine(color, Offset(size.width * 0.28f, size.height * 0.50f), Offset(size.width * 0.58f, size.height * 0.22f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.28f, size.height * 0.50f), Offset(size.width * 0.58f, size.height * 0.78f), stroke, StrokeCap.Round)
        val path = Path().apply {
            moveTo(size.width * 0.31f, size.height * 0.50f)
            cubicTo(size.width * 0.70f, size.height * 0.47f, size.width * 0.82f, size.height * 0.61f, size.width * 0.84f, size.height * 0.78f)
        }
        drawPath(path, color, style = Stroke(stroke, cap = StrokeCap.Round))
    }
}

@Composable
fun ForwardIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.09f
        drawLine(color, Offset(size.width * 0.72f, size.height * 0.50f), Offset(size.width * 0.42f, size.height * 0.22f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.72f, size.height * 0.50f), Offset(size.width * 0.42f, size.height * 0.78f), stroke, StrokeCap.Round)
        val path = Path().apply {
            moveTo(size.width * 0.69f, size.height * 0.50f)
            cubicTo(size.width * 0.30f, size.height * 0.47f, size.width * 0.18f, size.height * 0.61f, size.width * 0.16f, size.height * 0.78f)
        }
        drawPath(path, color, style = Stroke(stroke, cap = StrokeCap.Round))
    }
}

@Composable
fun CopyIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.32f, size.height * 0.20f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.48f, size.height * 0.55f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.08f),
            style = Stroke(stroke),
        )
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.18f, size.height * 0.34f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.48f, size.height * 0.48f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.08f),
            style = Stroke(stroke),
        )
    }
}

@Composable
fun PinIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.08f
        drawLine(color, Offset(size.width * 0.36f, size.height * 0.22f), Offset(size.width * 0.76f, size.height * 0.62f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.58f, size.height * 0.17f), Offset(size.width * 0.81f, size.height * 0.40f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.27f, size.height * 0.55f), Offset(size.width * 0.58f, size.height * 0.24f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.32f, size.height * 0.60f), Offset(size.width * 0.18f, size.height * 0.84f), stroke, StrokeCap.Round)
    }
}

@Composable
fun DeleteIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.28f, size.height * 0.31f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.44f, size.height * 0.52f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.05f),
            style = Stroke(stroke),
        )
        drawLine(color, Offset(size.width * 0.20f, size.height * 0.26f), Offset(size.width * 0.80f, size.height * 0.26f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.40f, size.height * 0.16f), Offset(size.width * 0.60f, size.height * 0.16f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.43f, size.height * 0.42f), Offset(size.width * 0.43f, size.height * 0.70f), stroke * 0.75f, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.57f, size.height * 0.42f), Offset(size.width * 0.57f, size.height * 0.70f), stroke * 0.75f, StrokeCap.Round)
    }
}

@Composable
fun DeliveryChecksIcon(
    state: MessageDeliveryState,
    modifier: Modifier = Modifier,
    color: Color,
) {
    if (state == MessageDeliveryState.PENDING) {
        val transition = rememberInfiniteTransition(label = "fedmes-pending-clock")
        val handAngle = transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1_000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "pending-clock-hand",
        ).value
        Canvas(modifier) {
            val stroke = size.minDimension * 0.12f
            val center = Offset(size.width * 0.5f, size.height * 0.5f)
            val radius = size.minDimension * 0.39f
            drawCircle(color, radius, center, style = Stroke(stroke, cap = StrokeCap.Round))
            val radians = Math.toRadians((handAngle - 90f).toDouble())
            val handEnd = Offset(
                center.x + kotlin.math.cos(radians).toFloat() * radius * 0.62f,
                center.y + kotlin.math.sin(radians).toFloat() * radius * 0.62f,
            )
            drawLine(color, center, handEnd, stroke, StrokeCap.Round)
            drawLine(
                color,
                center,
                Offset(center.x, center.y - radius * 0.38f),
                stroke * 0.82f,
                StrokeCap.Round,
            )
        }
        return
    }

    Canvas(modifier) {
        val stroke = size.minDimension * 0.12f
        fun check(originX: Float) {
            drawLine(
                color,
                Offset(size.width * originX, size.height * 0.56f),
                Offset(size.width * (originX + 0.16f), size.height * 0.72f),
                stroke,
                StrokeCap.Round,
            )
            drawLine(
                color,
                Offset(size.width * (originX + 0.16f), size.height * 0.72f),
                Offset(size.width * (originX + 0.44f), size.height * 0.31f),
                stroke,
                StrokeCap.Round,
            )
        }
        if (state == MessageDeliveryState.READ) {
            check(0.05f)
            check(0.30f)
        } else {
            check(0.18f)
        }
    }
}

@Composable
private fun LineIcon(
    modifier: Modifier,
    content: androidx.compose.ui.graphics.drawscope.DrawScope.(Float, Float, Float) -> Unit,
) {
    Canvas(modifier) {
        content(size.width, size.height, size.minDimension * 0.09f)
    }
}

@Composable
fun EditIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.085f
        drawLine(
            color,
            Offset(size.width * 0.24f, size.height * 0.74f),
            Offset(size.width * 0.70f, size.height * 0.28f),
            stroke,
            StrokeCap.Round,
        )
        drawLine(
            color,
            Offset(size.width * 0.64f, size.height * 0.22f),
            Offset(size.width * 0.78f, size.height * 0.36f),
            stroke,
            StrokeCap.Round,
        )
        val tip = Path().apply {
            moveTo(size.width * 0.20f, size.height * 0.80f)
            lineTo(size.width * 0.28f, size.height * 0.61f)
            lineTo(size.width * 0.39f, size.height * 0.72f)
            close()
        }
        drawPath(tip, color)
        drawLine(
            color,
            Offset(size.width * 0.18f, size.height * 0.84f),
            Offset(size.width * 0.54f, size.height * 0.84f),
            stroke * 0.75f,
            StrokeCap.Round,
        )
    }
}

@Composable
fun GalleryIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.07f
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.14f, size.height * 0.18f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.72f, size.height * 0.64f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.10f),
            style = Stroke(stroke),
        )
        drawCircle(color, radius = size.minDimension * 0.075f, center = Offset(size.width * 0.66f, size.height * 0.36f))
        val mountain = Path().apply {
            moveTo(size.width * 0.20f, size.height * 0.72f)
            lineTo(size.width * 0.40f, size.height * 0.49f)
            lineTo(size.width * 0.54f, size.height * 0.62f)
            lineTo(size.width * 0.67f, size.height * 0.50f)
            lineTo(size.width * 0.82f, size.height * 0.72f)
        }
        drawPath(mountain, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

@Composable
fun FileIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        val path = Path().apply {
            moveTo(size.width * 0.26f, size.height * 0.13f)
            lineTo(size.width * 0.60f, size.height * 0.13f)
            lineTo(size.width * 0.79f, size.height * 0.32f)
            lineTo(size.width * 0.79f, size.height * 0.86f)
            lineTo(size.width * 0.26f, size.height * 0.86f)
            close()
            moveTo(size.width * 0.60f, size.height * 0.13f)
            lineTo(size.width * 0.60f, size.height * 0.32f)
            lineTo(size.width * 0.79f, size.height * 0.32f)
        }
        drawPath(path, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

@Composable
fun CameraIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.12f, size.height * 0.28f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.76f, size.height * 0.55f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.10f),
            style = Stroke(stroke),
        )
        drawLine(
            color,
            Offset(size.width * 0.32f, size.height * 0.28f),
            Offset(size.width * 0.42f, size.height * 0.16f),
            stroke,
            StrokeCap.Round,
        )
        drawLine(
            color,
            Offset(size.width * 0.42f, size.height * 0.16f),
            Offset(size.width * 0.61f, size.height * 0.16f),
            stroke,
            StrokeCap.Round,
        )
        drawLine(
            color,
            Offset(size.width * 0.61f, size.height * 0.16f),
            Offset(size.width * 0.69f, size.height * 0.28f),
            stroke,
            StrokeCap.Round,
        )
        drawCircle(
            color,
            radius = size.minDimension * 0.16f,
            center = Offset(size.width * 0.51f, size.height * 0.56f),
            style = Stroke(stroke),
        )
    }
}

@Composable
fun CheckIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.10f
        drawLine(
            color,
            Offset(size.width * 0.18f, size.height * 0.52f),
            Offset(size.width * 0.42f, size.height * 0.75f),
            stroke,
            StrokeCap.Round,
        )
        drawLine(
            color,
            Offset(size.width * 0.42f, size.height * 0.75f),
            Offset(size.width * 0.83f, size.height * 0.27f),
            stroke,
            StrokeCap.Round,
        )
    }
}

@Composable
fun RotateIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        val arc = Path().apply {
            moveTo(size.width * 0.24f, size.height * 0.40f)
            cubicTo(
                size.width * 0.36f,
                size.height * 0.14f,
                size.width * 0.76f,
                size.height * 0.16f,
                size.width * 0.81f,
                size.height * 0.49f,
            )
            cubicTo(
                size.width * 0.84f,
                size.height * 0.75f,
                size.width * 0.58f,
                size.height * 0.88f,
                size.width * 0.37f,
                size.height * 0.77f,
            )
        }
        drawPath(arc, color, style = Stroke(stroke, cap = StrokeCap.Round))
        drawLine(color, Offset(size.width * 0.24f, size.height * 0.40f), Offset(size.width * 0.22f, size.height * 0.18f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.24f, size.height * 0.40f), Offset(size.width * 0.44f, size.height * 0.34f), stroke, StrokeCap.Round)
    }
}

@Composable
fun MoreIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val radius = size.minDimension * 0.085f
        drawCircle(color, radius, Offset(size.width * 0.5f, size.height * 0.24f))
        drawCircle(color, radius, Offset(size.width * 0.5f, size.height * 0.5f))
        drawCircle(color, radius, Offset(size.width * 0.5f, size.height * 0.76f))
    }
}

@Composable
fun MicIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        drawRoundRect(
            color = color,
            topLeft = Offset(size.width * 0.34f, size.height * 0.12f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.32f, size.height * 0.50f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.16f),
            style = Stroke(stroke),
        )
        val path = Path().apply {
            moveTo(size.width * 0.22f, size.height * 0.48f)
            cubicTo(size.width * 0.22f, size.height * 0.75f, size.width * 0.78f, size.height * 0.75f, size.width * 0.78f, size.height * 0.48f)
        }
        drawPath(path, color, style = Stroke(stroke, cap = StrokeCap.Round))
        drawLine(color, Offset(size.width * 0.50f, size.height * 0.75f), Offset(size.width * 0.50f, size.height * 0.90f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.34f, size.height * 0.90f), Offset(size.width * 0.66f, size.height * 0.90f), stroke, StrokeCap.Round)
    }
}

@Composable
fun VideoMessageIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        drawRoundRect(
            color = color,
            topLeft = Offset(size.width * 0.16f, size.height * 0.25f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.50f, size.height * 0.50f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.10f),
            style = Stroke(stroke),
        )
        val triangle = Path().apply {
            moveTo(size.width * 0.68f, size.height * 0.40f)
            lineTo(size.width * 0.88f, size.height * 0.30f)
            lineTo(size.width * 0.88f, size.height * 0.70f)
            lineTo(size.width * 0.68f, size.height * 0.60f)
            close()
        }
        drawPath(triangle, color, style = Stroke(stroke, join = StrokeJoin.Round))
    }
}

@Composable
fun PlayIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val path = Path().apply {
            moveTo(size.width * 0.30f, size.height * 0.18f)
            lineTo(size.width * 0.78f, size.height * 0.50f)
            lineTo(size.width * 0.30f, size.height * 0.82f)
            close()
        }
        drawPath(path, color)
    }
}

@Composable
fun PauseIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.25f, size.height * 0.18f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.16f, size.height * 0.64f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.04f),
        )
        drawRoundRect(
            color,
            topLeft = Offset(size.width * 0.59f, size.height * 0.18f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.16f, size.height * 0.64f),
            cornerRadius = androidx.compose.ui.geometry.CornerRadius(size.width * 0.04f),
        )
    }
}

@Composable
fun DownloadIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.08f
        drawLine(color, Offset(size.width * 0.50f, size.height * 0.16f), Offset(size.width * 0.50f, size.height * 0.62f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.30f, size.height * 0.46f), Offset(size.width * 0.50f, size.height * 0.66f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.70f, size.height * 0.46f), Offset(size.width * 0.50f, size.height * 0.66f), stroke, StrokeCap.Round)
        drawLine(color, Offset(size.width * 0.22f, size.height * 0.82f), Offset(size.width * 0.78f, size.height * 0.82f), stroke, StrokeCap.Round)
    }
}

@Composable
fun SpoilerIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        val eye = Path().apply {
            moveTo(size.width * 0.10f, size.height * 0.50f)
            cubicTo(
                size.width * 0.28f,
                size.height * 0.20f,
                size.width * 0.72f,
                size.height * 0.20f,
                size.width * 0.90f,
                size.height * 0.50f,
            )
            cubicTo(
                size.width * 0.72f,
                size.height * 0.80f,
                size.width * 0.28f,
                size.height * 0.80f,
                size.width * 0.10f,
                size.height * 0.50f,
            )
        }
        drawPath(eye, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
        drawCircle(color, radius = size.minDimension * 0.12f, center = Offset(size.width * 0.50f, size.height * 0.50f))
        drawLine(
            color,
            Offset(size.width * 0.18f, size.height * 0.16f),
            Offset(size.width * 0.82f, size.height * 0.84f),
            stroke,
            StrokeCap.Round,
        )
    }
}

@Composable
fun BrushIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.09f
        drawLine(
            color,
            Offset(size.width * 0.30f, size.height * 0.73f),
            Offset(size.width * 0.76f, size.height * 0.27f),
            stroke,
            StrokeCap.Round,
        )
        val tip = Path().apply {
            moveTo(size.width * 0.23f, size.height * 0.80f)
            cubicTo(
                size.width * 0.13f,
                size.height * 0.72f,
                size.width * 0.16f,
                size.height * 0.57f,
                size.width * 0.31f,
                size.height * 0.57f,
            )
            lineTo(size.width * 0.43f, size.height * 0.69f)
            cubicTo(
                size.width * 0.38f,
                size.height * 0.82f,
                size.width * 0.29f,
                size.height * 0.86f,
                size.width * 0.23f,
                size.height * 0.80f,
            )
            close()
        }
        drawPath(tip, color)
    }
}

@Composable
fun SwitchCameraIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.075f
        val center = Offset(size.width * 0.50f, size.height * 0.52f)
        drawCircle(
            color = color,
            radius = size.minDimension * 0.20f,
            center = center,
            style = Stroke(stroke),
        )
        drawArc(
            color = color,
            startAngle = 205f,
            sweepAngle = 115f,
            useCenter = false,
            topLeft = Offset(size.width * 0.12f, size.height * 0.13f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.76f, size.height * 0.76f),
            style = Stroke(stroke, cap = StrokeCap.Round),
        )
        val first = Path().apply {
            moveTo(size.width * 0.16f, size.height * 0.42f)
            lineTo(size.width * 0.13f, size.height * 0.22f)
            lineTo(size.width * 0.33f, size.height * 0.26f)
        }
        drawPath(first, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
        drawArc(
            color = color,
            startAngle = 25f,
            sweepAngle = 115f,
            useCenter = false,
            topLeft = Offset(size.width * 0.12f, size.height * 0.13f),
            size = androidx.compose.ui.geometry.Size(size.width * 0.76f, size.height * 0.76f),
            style = Stroke(stroke, cap = StrokeCap.Round),
        )
        val second = Path().apply {
            moveTo(size.width * 0.84f, size.height * 0.61f)
            lineTo(size.width * 0.87f, size.height * 0.81f)
            lineTo(size.width * 0.67f, size.height * 0.77f)
        }
        drawPath(second, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

@Composable
fun DownArrowIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.10f
        drawLine(
            color,
            Offset(size.width * 0.24f, size.height * 0.38f),
            Offset(size.width * 0.50f, size.height * 0.64f),
            stroke,
            StrokeCap.Round,
        )
        drawLine(
            color,
            Offset(size.width * 0.50f, size.height * 0.64f),
            Offset(size.width * 0.76f, size.height * 0.38f),
            stroke,
            StrokeCap.Round,
        )
    }
}

@Composable
fun ThemeToggleIcon(modifier: Modifier = Modifier, color: Color, dark: Boolean) {
    Canvas(modifier) {
        val center = Offset(size.width * 0.50f, size.height * 0.50f)
        if (dark) {
            val stroke = size.minDimension * 0.11f
            val crescent = Path().apply {
                moveTo(size.width * 0.62f, size.height * 0.18f)
                cubicTo(
                    size.width * 0.30f,
                    size.height * 0.22f,
                    size.width * 0.24f,
                    size.height * 0.70f,
                    size.width * 0.60f,
                    size.height * 0.82f,
                )
                cubicTo(
                    size.width * 0.42f,
                    size.height * 0.62f,
                    size.width * 0.45f,
                    size.height * 0.34f,
                    size.width * 0.62f,
                    size.height * 0.18f,
                )
            }
            drawPath(crescent, color, style = Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round))
        } else {
            val radius = size.minDimension * 0.19f
            drawCircle(color, radius = radius, center = center)
            val stroke = size.minDimension * 0.075f
            repeat(8) { index ->
                val angle = Math.toRadians(index * 45.0)
                val inner = size.minDimension * 0.31f
                val outer = size.minDimension * 0.43f
                val dx = kotlin.math.cos(angle).toFloat()
                val dy = kotlin.math.sin(angle).toFloat()
                drawLine(
                    color,
                    Offset(center.x + dx * inner, center.y + dy * inner),
                    Offset(center.x + dx * outer, center.y + dy * outer),
                    stroke,
                    StrokeCap.Round,
                )
            }
        }
    }
}

@Composable
fun QuoteMarksIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.13f
        fun mark(originX: Float) {
            drawCircle(
                color = color,
                radius = size.minDimension * 0.13f,
                center = Offset(size.width * originX, size.height * 0.37f),
            )
            drawLine(
                color,
                Offset(size.width * originX, size.height * 0.46f),
                Offset(size.width * (originX - 0.12f), size.height * 0.72f),
                stroke,
                StrokeCap.Round,
            )
        }
        mark(0.38f)
        mark(0.70f)
    }
}

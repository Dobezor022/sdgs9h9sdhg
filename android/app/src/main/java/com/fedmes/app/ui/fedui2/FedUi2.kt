package com.fedmes.app.ui.fedui2

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * FedUI 2 primitives. They deliberately avoid Material widgets and visual
 * conventions. Android contributes only the application surface, IME and
 * accessibility bridge; FedMes owns geometry, colors, spacing and states.
 */
@Immutable
data class FedPalette(
    val background: Color = Color(0xFF101316),
    val surface: Color = Color(0xFF171B1F),
    val surfaceRaised: Color = Color(0xFF1D2227),
    val line: Color = Color(0xFF2D343B),
    val text: Color = Color(0xFFE7EBEF),
    val muted: Color = Color(0xFF929DA7),
    val accent: Color = Color(0xFF64A6B8),
    val secure: Color = Color(0xFF74B58B),
    val danger: Color = Color(0xFFD36E6E),
)

object FedMetrics {
    val rail = 46.dp
    val row = 52.dp
    val line = 1.dp
    val corner = 5.dp
    val gap = 8.dp
}

@Composable
fun FedSurface(palette: FedPalette = FedPalette(), content: @Composable BoxScope.() -> Unit) {
    Box(Modifier.fillMaxSize().background(palette.background), content = content)
}

@Composable
fun FedAction(
    text: String,
    modifier: Modifier = Modifier,
    palette: FedPalette = FedPalette(),
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val bg = if (enabled) palette.surfaceRaised else palette.surface
    Box(
        modifier
            .pointerInput(enabled) { detectTapGestures { if (enabled) onClick() } }
            .background(bg)
            .padding(PaddingValues(horizontal = 12.dp, vertical = 8.dp)),
    ) {
        BasicText(text, style = TextStyle(color = if (enabled) palette.text else palette.muted, fontSize = 13.sp))
    }
}

@Composable
fun FedInput(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    palette: FedPalette = FedPalette(),
    singleLine: Boolean = false,
) {
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.background(palette.surface).padding(horizontal = 10.dp, vertical = 8.dp),
        textStyle = TextStyle(color = palette.text, fontSize = 14.sp),
        cursorBrush = SolidColor(palette.accent),
        singleLine = singleLine,
    )
}

@Composable
fun FedSecuritySpine(
    verified: Boolean,
    generation: Long,
    modifier: Modifier = Modifier,
    palette: FedPalette = FedPalette(),
) {
    Canvas(modifier) {
        val c = if (verified) palette.secure else palette.danger
        drawRoundRect(c, cornerRadius = CornerRadius(3.dp.toPx(), 3.dp.toPx()))
        drawCircle(palette.background, radius = 2.dp.toPx(), center = Offset(7.dp.toPx(), size.height / 2f))
        // Text is intentionally rendered by the caller to keep Canvas independent
        // of Android text layout. The scene state remains generation-aware.
        @Suppress("UNUSED_VARIABLE") val state = generation
    }
}

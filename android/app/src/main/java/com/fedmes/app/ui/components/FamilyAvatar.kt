package com.fedmes.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.fedmes.app.domain.family.AvatarTone
import com.fedmes.app.domain.family.FamilyUser

@Composable
fun FamilyAvatar(
    user: FamilyUser,
    modifier: Modifier = Modifier,
    size: Dp = 42.dp,
    displayName: String = user.displayName,
) {
    val colors = when (user.avatarTone) {
        AvatarTone.BLUE -> listOf(Color(0xFF2AABEE), Color(0xFF3867D6))
        AvatarTone.GREEN -> listOf(Color(0xFF39B982), Color(0xFF22A6B3))
        AvatarTone.ORANGE -> listOf(Color(0xFFFF9F43), Color(0xFFEE5253))
        AvatarTone.PURPLE -> listOf(Color(0xFF8854D0), Color(0xFF3867D6))
        AvatarTone.GRAY -> listOf(Color(0xFF778899), Color(0xFF465768))
    }
    val initial = displayName.firstOrNull()?.uppercase() ?: "?"

    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(Brush.linearGradient(colors))
            .semantics { contentDescription = displayName },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = initial,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
fun SavedMessagesAvatar(
    modifier: Modifier = Modifier,
    size: Dp = 42.dp,
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(
                Brush.linearGradient(
                    listOf(Color(0xFF5AB7F4), Color(0xFF2A87D9)),
                ),
            )
            .semantics { contentDescription = "Избранное" },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(size * 0.48f)) {
            val width = this.size.width
            val height = this.size.height
            val stroke = this.size.minDimension * 0.11f
            val path = Path().apply {
                moveTo(width * 0.25f, height * 0.15f)
                lineTo(width * 0.75f, height * 0.15f)
                lineTo(width * 0.75f, height * 0.84f)
                lineTo(width * 0.50f, height * 0.67f)
                lineTo(width * 0.25f, height * 0.84f)
                close()
            }
            drawPath(
                path = path,
                color = Color.White,
                style = Stroke(width = stroke, cap = StrokeCap.Round),
            )
        }
    }
}

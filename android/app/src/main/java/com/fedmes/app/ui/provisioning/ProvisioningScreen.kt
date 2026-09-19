package com.fedmes.app.ui.provisioning

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fedmes.app.R
import com.fedmes.app.domain.family.FamilyUser
import com.fedmes.app.ui.components.FamilyAvatar
import com.fedmes.app.ui.theme.FedMesThemeValues

@Composable
fun ProvisioningScreen(
    familyMembers: List<FamilyUser>,
    onSignInWithQr: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val signInWithQrDescription = stringResource(R.string.sign_in_with_qr_description)
    val colors = MaterialTheme.colorScheme
    val extended = FedMesThemeValues.extendedColors
    val background = Brush.linearGradient(
        colors = listOf(colors.primary.copy(alpha = 0.18f), colors.background),
        start = Offset.Zero,
        end = Offset.Infinite,
    )

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(background)
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(horizontal = 20.dp, vertical = 24.dp),
        contentAlignment = Alignment.Center,
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 480.dp),
            shape = RoundedCornerShape(22.dp),
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 12.dp),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                BrandMark()
                Spacer(Modifier.height(18.dp))
                Text(
                    text = stringResource(R.string.provisioning_title),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.ExtraBold,
                    color = colors.onSurface,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.provisioning_subtitle),
                    style = MaterialTheme.typography.titleMedium,
                    color = extended.mutedText,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(22.dp))
                FamilyRow(familyMembers)
                Spacer(Modifier.height(22.dp))
                Text(
                    text = stringResource(R.string.provisioning_description),
                    style = MaterialTheme.typography.bodyMedium,
                    color = extended.mutedText,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(26.dp))
                Button(
                    onClick = onSignInWithQr,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp)
                        .semantics {
                            contentDescription = signInWithQrDescription
                        },
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = colors.primary,
                        contentColor = Color.White,
                    ),
                ) {
                    QrGlyph(Modifier.size(24.dp))
                    Spacer(Modifier.size(10.dp))
                    Text(
                        text = stringResource(R.string.sign_in_with_qr),
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun BrandMark() {
    Box(
        modifier = Modifier
            .size(62.dp)
            .background(
                brush = Brush.linearGradient(
                    listOf(Color(0xFF2AABEE), Color(0xFF3867D6)),
                ),
                shape = RoundedCornerShape(18.dp),
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = stringResource(R.string.brand_mark),
            color = Color.White,
            fontWeight = FontWeight.ExtraBold,
            fontSize = 20.sp,
        )
    }
}

@Composable
private fun FamilyRow(familyMembers: List<FamilyUser>) {
    val familyMembersDescription = stringResource(R.string.family_members_description)
    Row(
        horizontalArrangement = Arrangement.spacedBy((-8).dp),
        modifier = Modifier.semantics(mergeDescendants = true) {
            contentDescription = familyMembersDescription
        },
    ) {
        familyMembers.forEach { user ->
            FamilyAvatar(user = user)
        }
    }
}

@Composable
private fun QrGlyph(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val stroke = size.minDimension / 7f
        fun finder(origin: Offset) {
            drawRect(
                color = Color.White,
                topLeft = origin,
                size = androidx.compose.ui.geometry.Size(stroke * 3f, stroke * 3f),
                style = androidx.compose.ui.graphics.drawscope.Stroke(width = stroke),
            )
        }
        finder(Offset(stroke / 2f, stroke / 2f))
        finder(Offset(size.width - stroke * 3.5f, stroke / 2f))
        finder(Offset(stroke / 2f, size.height - stroke * 3.5f))
        val path = Path().apply {
            moveTo(size.width * 0.58f, size.height * 0.58f)
            lineTo(size.width * 0.9f, size.height * 0.58f)
            lineTo(size.width * 0.9f, size.height * 0.9f)
            lineTo(size.width * 0.72f, size.height * 0.9f)
            lineTo(size.width * 0.72f, size.height * 0.75f)
            lineTo(size.width * 0.58f, size.height * 0.75f)
            close()
        }
        drawPath(path, Color.White)
    }
}

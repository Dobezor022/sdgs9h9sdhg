package com.fedmes.app.ui.fedui3

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * FedMes 3 production UI contract.
 * Geometry and semantic colors are frozen against the Bridge 1.9 inventory
 * (freeze19-inventory, sheet sequence 682). Runtime data is intentionally
 * separate from Figma's structural state variants.
 */
@Immutable
data class FedMes26Palette(
    val background: Color,
    val surface: Color,
    val raised: Color,
    val border: Color,
    val text: Color,
    val muted: Color,
    val accent: Color,
    val incoming: Color,
    val outgoing: Color,
    val danger: Color = Color(0xFFD94B4B),
    val secure: Color = Color(0xFF2FBA72),
) {
    companion object {
        val Dark = FedMes26Palette(
            background = Color(0xFF0E1621),
            surface = Color(0xFF17212B),
            raised = Color(0xFF202B36),
            border = Color(0xFF2B3A48),
            text = Color(0xFFF4F7FA),
            muted = Color(0xFF8E9DAA),
            accent = Color(0xFF3390EC),
            incoming = Color(0xFF182533),
            outgoing = Color(0xFF2B5278),
        )
        val Light = FedMes26Palette(
            background = Color(0xFFF4F7FA),
            surface = Color.White,
            raised = Color(0xFFEDF2F6),
            border = Color(0xFFDCE5EC),
            text = Color(0xFF17212B),
            muted = Color(0xFF70808D),
            accent = Color(0xFF3390EC),
            incoming = Color.White,
            outgoing = Color(0xFFE1FFC7),
        )
    }
}

object FedMes26Geometry {
    val screenWidth = 390.dp
    val screenHeight = 844.dp
    val topBarHeight = 58.dp
    val bottomBarHeight = 72.dp
    val chatRowHeight = 68.dp
    val chatAvatar = 54.dp
    val composerHeight = 54.dp
    val componentRadius = 14.dp
    val activeNavigationRadius = 20.dp
    val callTrayRadius = 26.dp
}

enum class FedMes26Destination { CHATS, SEARCH, PROFILE, SETTINGS }

enum class FedMes26PlaybackState { PAUSED, PLAYING, BUFFERING }

enum class FedMes26CallMode { AUDIO, VIDEO, GROUP }

@Composable
fun FedMes26Screen(
    dark: Boolean,
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.(FedMes26Palette) -> Unit,
) {
    val palette = if (dark) FedMes26Palette.Dark else FedMes26Palette.Light
    Box(modifier.fillMaxSize().background(palette.background)) { content(palette) }
}

@Composable
fun FedMes26ChatRow(
    title: String,
    preview: String,
    time: String,
    unreadCount: Int,
    selected: Boolean,
    online: Boolean,
    dark: Boolean,
    modifier: Modifier = Modifier,
    avatar: @Composable BoxScope.() -> Unit,
    onClick: () -> Unit,
) {
    val p = if (dark) FedMes26Palette.Dark else FedMes26Palette.Light
    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(FedMes26Geometry.chatRowHeight)
            .clip(if (selected) RoundedCornerShape(14.dp) else RoundedCornerShape(0.dp))
            .background(if (selected) p.raised else p.surface)
            .clickable(onClick = onClick)
            .padding(start = 8.dp, end = 8.dp, top = 7.dp, bottom = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(FedMes26Geometry.chatAvatar)) {
            avatar()
            if (online) {
                Box(
                    Modifier.align(Alignment.BottomEnd).size(13.dp).clip(CircleShape)
                        .background(p.secure),
                )
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    modifier = Modifier.weight(1f),
                    color = p.text,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(time, color = p.muted, fontSize = 9.sp, maxLines = 1)
            }
            Spacer(Modifier.height(5.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    preview,
                    modifier = Modifier.weight(1f),
                    color = p.muted,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (unreadCount > 0) {
                    Box(
                        Modifier.size(22.dp).clip(CircleShape).background(p.accent),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(if (unreadCount > 99) "99+" else unreadCount.toString(), color = Color.White, fontSize = 9.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
            Spacer(Modifier.height(6.dp))
            Box(Modifier.fillMaxWidth().height(1.dp).background(p.border))
        }
    }
}

@Composable
fun FedMes26BottomBar(
    active: FedMes26Destination,
    dark: Boolean,
    onDestination: (FedMes26Destination) -> Unit,
    modifier: Modifier = Modifier,
) {
    val p = if (dark) FedMes26Palette.Dark else FedMes26Palette.Light
    Row(
        modifier = modifier.fillMaxWidth().height(72.dp).clip(RoundedCornerShape(24.dp)).background(p.surface).padding(horizontal = 10.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val items = listOf(
            FedMes26Destination.CHATS to "Чаты",
            FedMes26Destination.SEARCH to "Поиск",
            FedMes26Destination.PROFILE to "Профиль",
            FedMes26Destination.SETTINGS to "Настройки",
        )
        items.forEach { (destination, label) ->
            val selected = destination == active
            Box(
                Modifier
                    .width(if (destination == FedMes26Destination.SETTINGS) 88.dp else 82.dp)
                    .height(56.dp)
                    .clip(RoundedCornerShape(20.dp))
                    .background(if (selected) p.raised else Color.Transparent)
                    .clickable { onDestination(destination) },
                contentAlignment = Alignment.Center,
            ) {
                Text(label, color = if (selected) p.accent else p.muted, fontSize = 10.sp, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
            }
        }
    }
}

@Composable
fun FedMes26MessageBubble(
    outgoing: Boolean,
    dark: Boolean,
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit,
) {
    val p = if (dark) FedMes26Palette.Dark else FedMes26Palette.Light
    Box(
        modifier.clip(RoundedCornerShape(10.dp)).background(if (outgoing) p.outgoing else p.incoming).padding(horizontal = 10.dp, vertical = 8.dp),
        content = content,
    )
}

@Composable
fun FedMes26VideoPlayerChrome(
    state: FedMes26PlaybackState,
    progress: Float,
    currentTime: String,
    duration: String,
    dark: Boolean,
    chromeVisible: Boolean,
    modifier: Modifier = Modifier,
) {
    val p = if (dark) FedMes26Palette.Dark else FedMes26Palette.Light
    Box(modifier.background(p.background)) {
        if (!chromeVisible) return@Box
        val clamped = progress.coerceIn(0f, 1f)
        if (state == FedMes26PlaybackState.BUFFERING) {
            Text("…", modifier = Modifier.align(Alignment.Center), color = p.text, fontSize = 28.sp)
        } else {
            Box(Modifier.align(Alignment.Center).size(64.dp).clip(CircleShape).background(p.raised), contentAlignment = Alignment.Center) {
                Text(if (state == FedMes26PlaybackState.PLAYING) "Ⅱ" else "▶", color = p.text, fontSize = 24.sp)
            }
        }
        Canvas(Modifier.align(Alignment.BottomCenter).fillMaxWidth().height(62.dp).padding(horizontal = 18.dp, vertical = 26.dp)) {
            val y = size.height / 2f
            drawLine(p.border, Offset(0f, y), Offset(size.width, y), strokeWidth = 4.dp.toPx())
            drawLine(p.accent, Offset(0f, y), Offset(size.width * clamped, y), strokeWidth = 4.dp.toPx())
            drawCircle(p.accent, radius = 8.dp.toPx(), center = Offset(size.width * clamped, y))
        }
        Row(Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(horizontal = 18.dp, vertical = 8.dp)) {
            Text(currentTime, color = p.text, fontSize = 9.sp)
            Spacer(Modifier.weight(1f))
            Text("1×   ⛶   $duration", color = p.text, fontSize = 9.sp)
        }
    }
}

@Composable
fun FedMes26CallControlTray(
    mode: FedMes26CallMode,
    muted: Boolean,
    speaker: Boolean,
    camera: Boolean,
    modifier: Modifier = Modifier,
    onMute: () -> Unit,
    onSpeaker: () -> Unit,
    onCamera: () -> Unit,
    onFlip: () -> Unit,
    onEnd: () -> Unit,
) {
    val p = FedMes26Palette.Dark
    val actions = buildList {
        add(Triple(if (muted) "Микр. выкл." else "Микрофон", muted, onMute))
        add(Triple(if (speaker) "Динамик" else "Аудио", speaker, onSpeaker))
        add(Triple(if (camera) "Камера" else "Видео", camera, onCamera))
        if (mode != FedMes26CallMode.AUDIO) add(Triple("Сменить", false, onFlip))
        add(Triple("Завершить", true, onEnd))
    }
    Row(
        modifier.fillMaxWidth().height(104.dp).clip(RoundedCornerShape(26.dp)).background(p.surface).padding(8.dp, 4.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        actions.forEachIndexed { index, (label, active, action) ->
            Column(
                Modifier.width(72.dp).height(88.dp).clickable(onClick = action),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Box(
                    Modifier.size(46.dp).clip(CircleShape).background(
                        when {
                            index == actions.lastIndex -> p.danger
                            active -> p.accent
                            else -> p.raised
                        },
                    ),
                )
                Spacer(Modifier.height(5.dp))
                Text(label, color = p.text, fontSize = 9.sp, maxLines = 1)
            }
        }
    }
}

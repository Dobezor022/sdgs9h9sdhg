package com.fedmes.app.ui.theme

import androidx.compose.ui.graphics.Color

internal object FedMesColorTokens {
    val LightBackground = Color(0xFFF4F7FA)
    val LightSurface = Color(0xFFFFFFFF)
    val LightSecondarySurface = Color(0xFFEDF2F6)
    val LightBorder = Color(0xFFDCE5EC)
    val LightText = Color(0xFF17212B)
    val LightMuted = Color(0xFF70808D)
    val LightIncoming = Color(0xFFFFFFFF)
    val LightOutgoing = Color(0xFFE1FFC7)

    val DarkBackground = Color(0xFF0E1621)
    val DarkSurface = Color(0xFF17212B)
    val DarkSecondarySurface = Color(0xFF202B36)
    val DarkBorder = Color(0xFF2B3A48)
    val DarkText = Color(0xFFF4F7FA)
    val DarkMuted = Color(0xFF8E9DAA)
    val DarkIncoming = Color(0xFF182533)
    val DarkOutgoing = Color(0xFF2B5278)

    val LightMessageText = Color(0xFF17212B)
    val DarkMessageText = Color(0xFFF4F7FA)
    val LightNameText = Color(0xFF111111)
    val DarkNameText = Color(0xFFFFFFFF)
    val SelectedMessage = Color(0xFF202B36)

    val LightQuoteBackground = Color(0xFFD9DDE1)
    val DarkQuoteBackground = Color(0xFFE2E5E8)
    val LightQuoteBar = Color(0xFFF7F8F9)
    val DarkQuoteBar = Color(0xFFF8F9FA)
    val QuoteMarks = Color(0xFF66727C)

    val LightFormattingSurface = Color(0xFFFFFFFF)
    val DarkFormattingSurface = Color(0xFF17212B)
    val LightFormattingBorder = Color(0xFF79C8F2)
    val DarkFormattingBorder = Color(0xFF14527A)

    val Accent = Color(0xFF3390EC)
    val AccentPressed = Color(0xFF2B7FC6)
    val Danger = Color(0xFFD94B4B)
    val Online = Color(0xFF2FBA72)
    val Warning = Color(0xFFF0A429)
}

data class FedMesExtendedColors(
    val secondarySurface: Color,
    val border: Color,
    val mutedText: Color,
    val incomingBubble: Color,
    val outgoingBubble: Color,
    val messageText: Color,
    val nameText: Color,
    val selectedMessage: Color,
    val quoteBackground: Color,
    val quoteBar: Color,
    val quoteMarks: Color,
    val formattingSurface: Color,
    val formattingBorder: Color,
    val formattingText: Color,
    val isDark: Boolean,
    val online: Color = FedMesColorTokens.Online,
    val warning: Color = FedMesColorTokens.Warning,
)

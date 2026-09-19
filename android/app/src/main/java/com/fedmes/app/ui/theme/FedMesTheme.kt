package com.fedmes.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf

private val LightColorScheme = lightColorScheme(
    primary = FedMesColorTokens.Accent,
    onPrimary = FedMesColorTokens.LightSurface,
    primaryContainer = FedMesColorTokens.LightOutgoing,
    onPrimaryContainer = FedMesColorTokens.LightMessageText,
    background = FedMesColorTokens.LightBackground,
    onBackground = FedMesColorTokens.LightText,
    surface = FedMesColorTokens.LightSurface,
    onSurface = FedMesColorTokens.LightText,
    surfaceVariant = FedMesColorTokens.LightSecondarySurface,
    onSurfaceVariant = FedMesColorTokens.LightMuted,
    outline = FedMesColorTokens.LightBorder,
    error = FedMesColorTokens.Danger,
)

private val DarkColorScheme = darkColorScheme(
    primary = FedMesColorTokens.Accent,
    onPrimary = FedMesColorTokens.DarkText,
    primaryContainer = FedMesColorTokens.DarkOutgoing,
    onPrimaryContainer = FedMesColorTokens.DarkMessageText,
    background = FedMesColorTokens.DarkBackground,
    onBackground = FedMesColorTokens.DarkText,
    surface = FedMesColorTokens.DarkSurface,
    onSurface = FedMesColorTokens.DarkText,
    surfaceVariant = FedMesColorTokens.DarkSecondarySurface,
    onSurfaceVariant = FedMesColorTokens.DarkMuted,
    outline = FedMesColorTokens.DarkBorder,
    error = FedMesColorTokens.Danger,
)

@Immutable
private data class StableExtendedColors(val value: FedMesExtendedColors)

private val LocalExtendedColors = staticCompositionLocalOf {
    StableExtendedColors(
        FedMesExtendedColors(
            secondarySurface = FedMesColorTokens.LightSecondarySurface,
            border = FedMesColorTokens.LightBorder,
            mutedText = FedMesColorTokens.LightMuted,
            incomingBubble = FedMesColorTokens.LightIncoming,
            outgoingBubble = FedMesColorTokens.LightOutgoing,
            messageText = FedMesColorTokens.LightMessageText,
            nameText = FedMesColorTokens.LightNameText,
            selectedMessage = FedMesColorTokens.SelectedMessage,
            quoteBackground = FedMesColorTokens.LightQuoteBackground,
            quoteBar = FedMesColorTokens.LightQuoteBar,
            quoteMarks = FedMesColorTokens.QuoteMarks,
            formattingSurface = FedMesColorTokens.LightFormattingSurface,
            formattingBorder = FedMesColorTokens.LightFormattingBorder,
            formattingText = FedMesColorTokens.LightNameText,
            isDark = false,
        ),
    )
}

object FedMesThemeValues {
    val extendedColors: FedMesExtendedColors
        @Composable get() = LocalExtendedColors.current.value
}

@Composable
fun FedMesTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    content: @Composable () -> Unit,
) {
    val isDark = themeMode.isDark(isSystemInDarkTheme())
    val extendedColors = if (isDark) {
        FedMesExtendedColors(
            secondarySurface = FedMesColorTokens.DarkSecondarySurface,
            border = FedMesColorTokens.DarkBorder,
            mutedText = FedMesColorTokens.DarkMuted,
            incomingBubble = FedMesColorTokens.DarkIncoming,
            outgoingBubble = FedMesColorTokens.DarkOutgoing,
            messageText = FedMesColorTokens.DarkMessageText,
            nameText = FedMesColorTokens.DarkNameText,
            selectedMessage = FedMesColorTokens.SelectedMessage,
            quoteBackground = FedMesColorTokens.DarkQuoteBackground,
            quoteBar = FedMesColorTokens.DarkQuoteBar,
            quoteMarks = FedMesColorTokens.QuoteMarks,
            formattingSurface = FedMesColorTokens.DarkFormattingSurface,
            formattingBorder = FedMesColorTokens.DarkFormattingBorder,
            formattingText = FedMesColorTokens.DarkNameText,
            isDark = true,
        )
    } else {
        FedMesExtendedColors(
            secondarySurface = FedMesColorTokens.LightSecondarySurface,
            border = FedMesColorTokens.LightBorder,
            mutedText = FedMesColorTokens.LightMuted,
            incomingBubble = FedMesColorTokens.LightIncoming,
            outgoingBubble = FedMesColorTokens.LightOutgoing,
            messageText = FedMesColorTokens.LightMessageText,
            nameText = FedMesColorTokens.LightNameText,
            selectedMessage = FedMesColorTokens.SelectedMessage,
            quoteBackground = FedMesColorTokens.LightQuoteBackground,
            quoteBar = FedMesColorTokens.LightQuoteBar,
            quoteMarks = FedMesColorTokens.QuoteMarks,
            formattingSurface = FedMesColorTokens.LightFormattingSurface,
            formattingBorder = FedMesColorTokens.LightFormattingBorder,
            formattingText = FedMesColorTokens.LightNameText,
            isDark = false,
        )
    }

    CompositionLocalProvider(LocalExtendedColors provides StableExtendedColors(extendedColors)) {
        MaterialTheme(
            colorScheme = if (isDark) DarkColorScheme else LightColorScheme,
            typography = Typography(),
            content = content,
        )
    }
}

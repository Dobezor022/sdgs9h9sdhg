package com.fedmes.app.ui.messenger

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.ParagraphStyle
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextIndent
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fedmes.app.messaging.TextEntity
import com.fedmes.app.messaging.TextEntityType
import com.fedmes.app.messaging.sanitizeTextEntities
import com.fedmes.app.ui.components.QuoteMarksIcon
import com.fedmes.app.ui.theme.FedMesThemeValues

private data class RichTextBlock(
    val text: String,
    val entities: List<TextEntity>,
    val quoted: Boolean,
)

@Composable
fun RichMessageText(
    text: String,
    entities: List<TextEntity>,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyLarge,
) {
    val colors = FedMesThemeValues.extendedColors
    val safeEntities = remember(text, entities) { sanitizeTextEntities(text, entities) }
    val blocks = remember(text, safeEntities) { splitRichTextBlocks(text, safeEntities) }
    Column(modifier = modifier.fillMaxWidth()) {
        blocks.forEachIndexed { index, block ->
            if (block.quoted) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    color = colors.quoteBackground,
                    contentColor = colors.messageText,
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(IntrinsicSize.Min),
                    ) {
                        Box(
                            Modifier
                                .width(4.dp)
                                .fillMaxHeight()
                                .background(colors.quoteBar),
                        )
                        RichInlineText(
                            text = block.text,
                            entities = block.entities.filterNot { it.type == TextEntityType.QUOTE },
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 9.dp, vertical = 7.dp),
                            style = style.copy(color = colors.messageText),
                            quoteBackground = colors.quoteBackground,
                        )
                        QuoteMarksIcon(
                            modifier = Modifier
                                .padding(top = 7.dp, end = 8.dp)
                                .size(23.dp),
                            color = colors.quoteMarks,
                        )
                    }
                }
            } else if (block.text.isNotEmpty()) {
                RichInlineText(
                    text = block.text,
                    entities = block.entities,
                    style = style.copy(color = colors.messageText),
                    quoteBackground = colors.quoteBackground,
                )
            } else {
                Spacer(Modifier.height(8.dp))
            }
            if (index != blocks.lastIndex && block.quoted) Spacer(Modifier.height(3.dp))
        }
    }
}

@Composable
private fun RichInlineText(
    text: String,
    entities: List<TextEntity>,
    modifier: Modifier = Modifier,
    style: TextStyle,
    quoteBackground: Color,
) {
    var revealedSpoilers by remember(text, entities) { mutableStateOf<Set<String>>(emptySet()) }
    var layoutResult by remember { mutableStateOf<TextLayoutResult?>(null) }
    val annotated = remember(text, entities, quoteBackground, revealedSpoilers) {
        buildRichAnnotatedString(
            text = text,
            entities = entities,
            quoteBackground = quoteBackground,
            revealedSpoilers = revealedSpoilers,
        )
    }
    Text(
        text = annotated,
        modifier = modifier.pointerInput(annotated) {
            detectTapGestures { position ->
                val offset = layoutResult?.getOffsetForPosition(position) ?: return@detectTapGestures
                val annotation = annotated
                    .getStringAnnotations(SPOILER_ANNOTATION, offset, (offset + 1).coerceAtMost(annotated.length))
                    .firstOrNull()
                    ?: return@detectTapGestures
                revealedSpoilers = revealedSpoilers + annotation.item
            }
        },
        style = style,
        onTextLayout = { layoutResult = it },
    )
}

fun buildRichAnnotatedString(
    text: String,
    entities: List<TextEntity>,
    quoteBackground: Color,
    revealedSpoilers: Set<String> = emptySet(),
): AnnotatedString = buildAnnotatedString {
    append(text)
    sanitizeTextEntities(text, entities).forEach { entity ->
        val start = entity.offset
        val end = entity.endExclusive
        when (entity.type) {
            TextEntityType.BOLD -> addStyle(SpanStyle(fontWeight = FontWeight.Bold), start, end)
            TextEntityType.ITALIC -> addStyle(SpanStyle(fontStyle = FontStyle.Italic), start, end)
            TextEntityType.MONOSPACE -> addStyle(SpanStyle(fontFamily = FontFamily.Monospace), start, end)
            TextEntityType.STRIKETHROUGH -> addStyle(SpanStyle(textDecoration = TextDecoration.LineThrough), start, end)
            TextEntityType.UNDERLINE -> addStyle(SpanStyle(textDecoration = TextDecoration.Underline), start, end)
            TextEntityType.QUOTE -> {
                addStyle(
                    ParagraphStyle(textIndent = TextIndent(firstLine = 12.sp, restLine = 12.sp)),
                    start,
                    end,
                )
                addStyle(SpanStyle(background = quoteBackground), start, end)
            }
            TextEntityType.SPOILER -> {
                val key = "$start:$end"
                if (key !in revealedSpoilers) {
                    addStyle(
                        SpanStyle(
                            color = Color.Transparent,
                            background = Color(0xFF7F8A94),
                        ),
                        start,
                        end,
                    )
                    addStringAnnotation(SPOILER_ANNOTATION, key, start, end)
                }
            }
        }
    }
}

private fun splitRichTextBlocks(text: String, entities: List<TextEntity>): List<RichTextBlock> {
    if (text.isEmpty()) return listOf(RichTextBlock("", emptyList(), false))
    val safe = sanitizeTextEntities(text, entities)
    val lines = mutableListOf<Triple<Int, Int, Boolean>>()
    var start = 0
    while (start <= text.length) {
        val newline = text.indexOf('\n', start)
        val end = if (newline < 0) text.length else newline
        val inclusiveEnd = if (newline < 0) end else end + 1
        val quoted = safe.any { entity ->
            entity.type == TextEntityType.QUOTE && entity.offset < inclusiveEnd && entity.endExclusive > start
        }
        lines += Triple(start, inclusiveEnd, quoted)
        if (newline < 0) break
        start = newline + 1
        if (start == text.length) {
            lines += Triple(start, start, false)
            break
        }
    }

    val result = mutableListOf<RichTextBlock>()
    var groupStart = lines.first().first
    var groupEnd = lines.first().second
    var groupQuoted = lines.first().third
    fun appendGroup() {
        val blockText = text.substring(groupStart, groupEnd)
        val blockEntities = safe.mapNotNull { entity ->
            val entityStart = maxOf(entity.offset, groupStart)
            val entityEnd = minOf(entity.endExclusive, groupEnd)
            if (entityEnd <= entityStart) null else TextEntity(
                type = entity.type,
                offset = entityStart - groupStart,
                length = entityEnd - entityStart,
            )
        }
        result += RichTextBlock(blockText.trimEnd('\n'), blockEntities, groupQuoted)
    }
    for (index in 1 until lines.size) {
        val line = lines[index]
        if (line.third == groupQuoted) {
            groupEnd = line.second
        } else {
            appendGroup()
            groupStart = line.first
            groupEnd = line.second
            groupQuoted = line.third
        }
    }
    appendGroup()
    return result
}

private const val SPOILER_ANNOTATION = "fedmes-spoiler"

package com.fedmes.app.messaging

data class NormalizedFormattedText(
    val text: String,
    val entities: List<TextEntity>,
)

fun sanitizeTextEntities(text: String, entities: List<TextEntity>): List<TextEntity> =
    mergeTextEntities(
        entities.mapNotNull { entity ->
            if (entity.length <= 0 || entity.offset >= text.length) return@mapNotNull null
            val start = entity.offset.coerceAtLeast(0)
            val rawEnd = entity.offset.toLong() + entity.length.toLong()
            val end = rawEnd.coerceIn(start.toLong(), text.length.toLong()).toInt()
            if (end <= start) null else TextEntity(entity.type, start, end - start)
        },
    )

fun normalizeFormattedText(text: String, entities: List<TextEntity>): NormalizedFormattedText {
    val start = text.indexOfFirst { !it.isWhitespace() }.let { if (it < 0) text.length else it }
    val end = text.indexOfLast { !it.isWhitespace() }.let { if (it < 0) start else it + 1 }
    if (end <= start) return NormalizedFormattedText("", emptyList())
    val normalized = text.substring(start, end)
    val normalizedEntities = entities.mapNotNull { entity ->
        val entityStart = maxOf(entity.offset, start)
        val entityEnd = minOf(entity.endExclusive, end)
        if (entityEnd <= entityStart) null else TextEntity(
            type = entity.type,
            offset = entityStart - start,
            length = entityEnd - entityStart,
        )
    }
    return NormalizedFormattedText(normalized, sanitizeTextEntities(normalized, normalizedEntities))
}

fun toggleTextEntity(
    text: String,
    entities: List<TextEntity>,
    type: TextEntityType,
    rawStart: Int,
    rawEnd: Int,
): List<TextEntity> {
    val start = minOf(rawStart, rawEnd).coerceIn(0, text.length)
    val end = maxOf(rawStart, rawEnd).coerceIn(0, text.length)
    if (end <= start) return sanitizeTextEntities(text, entities)
    val current = sanitizeTextEntities(text, entities)
    val alreadyApplied = current
        .filter { it.type == type }
        .any { it.offset <= start && it.endExclusive >= end }
    val result = mutableListOf<TextEntity>()
    current.forEach { entity ->
        if (entity.type != type || entity.endExclusive <= start || entity.offset >= end) {
            result += entity
        } else {
            if (entity.offset < start) {
                result += TextEntity(type, entity.offset, start - entity.offset)
            }
            if (entity.endExclusive > end) {
                result += TextEntity(type, end, entity.endExclusive - end)
            }
        }
    }
    if (!alreadyApplied) result += TextEntity(type, start, end - start)
    return sanitizeTextEntities(text, result)
}

fun clearTextEntities(
    text: String,
    entities: List<TextEntity>,
    rawStart: Int,
    rawEnd: Int,
): List<TextEntity> {
    val start = minOf(rawStart, rawEnd).coerceIn(0, text.length)
    val end = maxOf(rawStart, rawEnd).coerceIn(0, text.length)
    if (end <= start) return sanitizeTextEntities(text, entities)
    val result = mutableListOf<TextEntity>()
    sanitizeTextEntities(text, entities).forEach { entity ->
        if (entity.endExclusive <= start || entity.offset >= end) {
            result += entity
        } else {
            if (entity.offset < start) result += TextEntity(entity.type, entity.offset, start - entity.offset)
            if (entity.endExclusive > end) result += TextEntity(entity.type, end, entity.endExclusive - end)
        }
    }
    return sanitizeTextEntities(text, result)
}

fun remapTextEntitiesAfterEdit(
    oldText: String,
    newText: String,
    entities: List<TextEntity>,
): List<TextEntity> {
    if (oldText == newText) return sanitizeTextEntities(newText, entities)
    val maxPrefix = minOf(oldText.length, newText.length)
    var prefix = 0
    while (prefix < maxPrefix && oldText[prefix] == newText[prefix]) prefix++

    var suffix = 0
    val oldRemaining = oldText.length - prefix
    val newRemaining = newText.length - prefix
    while (
        suffix < oldRemaining &&
        suffix < newRemaining &&
        oldText[oldText.lastIndex - suffix] == newText[newText.lastIndex - suffix]
    ) suffix++

    val oldChangedEnd = oldText.length - suffix
    val newChangedEnd = newText.length - suffix
    val delta = newText.length - oldText.length

    fun mapStart(position: Int): Int = when {
        position <= prefix -> position
        position >= oldChangedEnd -> position + delta
        else -> prefix
    }

    fun mapEnd(position: Int): Int = when {
        position <= prefix -> position
        position >= oldChangedEnd -> position + delta
        else -> newChangedEnd
    }

    val mapped = sanitizeTextEntities(oldText, entities).mapNotNull { entity ->
        val start = mapStart(entity.offset).coerceIn(0, newText.length)
        val end = mapEnd(entity.endExclusive).coerceIn(start, newText.length)
        if (end <= start) null else TextEntity(entity.type, start, end - start)
    }
    return sanitizeTextEntities(newText, mapped)
}

fun expandToLineRange(text: String, rawStart: Int, rawEnd: Int): IntRange {
    if (text.isEmpty()) return 0..0
    val start = minOf(rawStart, rawEnd).coerceIn(0, text.length)
    val end = maxOf(rawStart, rawEnd).coerceIn(0, text.length)
    val lineStart = if (start == 0) 0 else text.lastIndexOf('\n', start - 1).let { if (it < 0) 0 else it + 1 }
    val lineEnd = text.indexOf('\n', end).let { if (it < 0) text.length else it }
    return lineStart..lineEnd
}

private fun mergeTextEntities(entities: List<TextEntity>): List<TextEntity> {
    val sorted = entities
        .filter { it.length > 0 }
        .sortedWith(compareBy<TextEntity>({ it.type.ordinal }, { it.offset }, { it.endExclusive }))
    val merged = mutableListOf<TextEntity>()
    sorted.forEach { entity ->
        val last = merged.lastOrNull()
        if (last != null && last.type == entity.type && entity.offset <= last.endExclusive) {
            val end = maxOf(last.endExclusive, entity.endExclusive)
            merged[merged.lastIndex] = TextEntity(last.type, last.offset, end - last.offset)
        } else {
            merged += entity
        }
    }
    return merged.sortedWith(compareBy<TextEntity>({ it.offset }, { it.endExclusive }, { it.type.ordinal }))
}

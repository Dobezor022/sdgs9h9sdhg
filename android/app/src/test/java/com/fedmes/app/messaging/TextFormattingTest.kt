package com.fedmes.app.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TextFormattingTest {
    @Test
    fun toggleAddsAndRemovesSelectedFormat() {
        val text = "alpha beta"
        val added = toggleTextEntity(text, emptyList(), TextEntityType.BOLD, 0, 5)
        assertEquals(listOf(TextEntity(TextEntityType.BOLD, 0, 5)), added)
        assertTrue(toggleTextEntity(text, added, TextEntityType.BOLD, 0, 5).isEmpty())
    }

    @Test
    fun insertionInsideEntityExtendsEntity() {
        val updated = remapTextEntitiesAfterEdit(
            "bold",
            "boXld",
            listOf(TextEntity(TextEntityType.BOLD, 0, 4)),
        )
        assertEquals(listOf(TextEntity(TextEntityType.BOLD, 0, 5)), updated)
    }

    @Test
    fun normalizationTrimsTextAndEntityOffsets() {
        val normalized = normalizeFormattedText(
            "  text  ",
            listOf(TextEntity(TextEntityType.ITALIC, 2, 4)),
        )
        assertEquals("text", normalized.text)
        assertEquals(listOf(TextEntity(TextEntityType.ITALIC, 0, 4)), normalized.entities)
    }

    @Test
    fun spoilerFormatCanBeToggled() {
        val text = "secret"
        val added = toggleTextEntity(text, emptyList(), TextEntityType.SPOILER, 0, text.length)
        assertEquals(listOf(TextEntity(TextEntityType.SPOILER, 0, text.length)), added)
        assertTrue(toggleTextEntity(text, added, TextEntityType.SPOILER, 0, text.length).isEmpty())
    }

    @Test
    fun quoteExpandsToWholeLines() {
        val range = expandToLineRange("one\ntwo\nthree", 5, 6)
        assertEquals(4, range.first)
        assertEquals(7, range.last)
    }
}

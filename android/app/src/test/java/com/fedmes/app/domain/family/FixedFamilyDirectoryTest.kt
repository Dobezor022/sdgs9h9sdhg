package com.fedmes.app.domain.family

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FixedFamilyDirectoryTest {
    @Test
    fun `contains exactly the five fixed users in stable order`() {
        val members = FixedFamilyDirectory.members()

        assertEquals(listOf("grisha", "papa", "mama", "yura", "vasya"), members.map { it.id })
        assertEquals(members.size, members.map { it.id }.toSet().size)
    }

    @Test
    fun `matches the approved avatar palette`() {
        val tones = FixedFamilyDirectory.members().associate { it.id to it.avatarTone }

        assertEquals(AvatarTone.BLUE, tones["grisha"])
        assertEquals(AvatarTone.GREEN, tones["papa"])
        assertEquals(AvatarTone.ORANGE, tones["mama"])
        assertEquals(AvatarTone.PURPLE, tones["yura"])
        assertEquals(AvatarTone.BLUE, tones["vasya"])
        assertTrue(tones.values.none { it == AvatarTone.GRAY })
    }
}

package com.fedmes.app.domain.family

enum class AvatarTone {
    BLUE,
    GREEN,
    ORANGE,
    PURPLE,
    GRAY,
}

data class FamilyUser(
    val id: String,
    val displayName: String,
    val avatarTone: AvatarTone,
) {
    init {
        require(id.isNotBlank()) { "User ID must not be blank" }
        require(displayName.isNotBlank()) { "Display name must not be blank" }
    }

    val initial: String
        get() = displayName.first().uppercase()
}

fun interface FamilyDirectory {
    fun members(): List<FamilyUser>
}

object FixedFamilyDirectory : FamilyDirectory {
    private val fixedMembers = listOf(
        FamilyUser("grisha", "Гриша", AvatarTone.BLUE),
        FamilyUser("papa", "Папа", AvatarTone.GREEN),
        FamilyUser("mama", "Мама", AvatarTone.ORANGE),
        FamilyUser("yura", "Юра", AvatarTone.PURPLE),
        FamilyUser("vasya", "Вася", AvatarTone.BLUE),
    )

    override fun members(): List<FamilyUser> = fixedMembers
}

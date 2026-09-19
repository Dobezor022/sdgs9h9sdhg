buildscript {
    dependencies {
        // AGP 9 uses built-in Kotlin. Pin the newer supported KGP on its classpath.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.21")
    }
}

plugins {
    id("com.android.application") version "9.2.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.21" apply false
}

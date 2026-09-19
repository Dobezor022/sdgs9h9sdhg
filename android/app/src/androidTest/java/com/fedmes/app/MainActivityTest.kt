package com.fedmes.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import org.junit.Rule
import org.junit.Test

class MainActivityTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun provisioningShowsOnlyQrPrimaryAction() {
        composeRule.onNodeWithText("Войти по QR").assertIsDisplayed()
        composeRule.onNodeWithText("FedMes").assertIsDisplayed()
    }
}

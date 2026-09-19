package com.fedmes.app.ui.model

import com.fedmes.app.provisioning.AccountSummary
import com.fedmes.app.provisioning.ProvisioningFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class FedMesUiReducerTest {
    @Test
    fun `scanner transitions through processing error and retry`() {
        val signedOut = FedMesUiReducer.reduce(FedMesUiState(), FedMesUiAction.RestoreWithoutAccount)
        val scanning = FedMesUiReducer.reduce(signedOut, FedMesUiAction.OpenQrScanner)
        val processing = FedMesUiReducer.reduce(scanning, FedMesUiAction.QrDecoded("secret payload"))
        val closeIgnored = FedMesUiReducer.reduce(processing, FedMesUiAction.CloseQrScanner)
        val failed = FedMesUiReducer.reduce(
            processing,
            FedMesUiAction.ProvisioningFailed(ProvisioningFailure.INVITATION_USED),
        )
        val retried = FedMesUiReducer.reduce(failed, FedMesUiAction.RetryScanner)

        assertEquals(FedMesScreen.QR_SIGN_IN, signedOut.screen)
        assertEquals(ScannerPhase.SCANNING, scanning.scannerPhase)
        assertEquals(ScannerPhase.PROCESSING, processing.scannerPhase)
        assertEquals(processing, closeIgnored)
        assertEquals(ProvisioningFailure.INVITATION_USED, failed.failure)
        assertEquals(ScannerPhase.SCANNING, retried.scannerPhase)
        assertEquals(null, retried.failure)
    }

    @Test
    fun `successful provisioning opens signed in screen`() {
        val account = AccountSummary(
            serverUrl = "https://family.example",
            username = "mama",
            deviceId = "128d9a52-5b9a-4f4f-b441-ae2bfd68b174",
            sessionExpiresAtEpochMillis = 1_900_000_000_000,
        )
        val state = FedMesUiReducer.reduce(
            FedMesUiState(screen = FedMesScreen.QR_SCANNER),
            FedMesUiAction.ProvisioningSucceeded(account),
        )

        assertEquals(FedMesScreen.SIGNED_IN, state.screen)
        assertEquals(account, state.account)
    }

    @Test
    fun `restore failure exposes retry without an infinite loading state`() {
        val failed = FedMesUiReducer.reduce(
            FedMesUiState(),
            FedMesUiAction.SessionRestoreFailed(ProvisioningFailure.NETWORK),
        )
        val retrying = FedMesUiReducer.reduce(failed, FedMesUiAction.RetrySessionRestore)

        assertEquals(FedMesScreen.RESTORE_ERROR, failed.screen)
        assertEquals(ProvisioningFailure.NETWORK, failed.failure)
        assertEquals(FedMesScreen.RESTORING, retrying.screen)
        assertEquals(null, retrying.failure)
    }
}

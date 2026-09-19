package com.fedmes.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.fedmes.app.BuildConfig
import java.security.MessageDigest

object AppIntegrityVerifier {
    fun verifyOrThrow(context: Context) {
        val expected = BuildConfig.EXPECTED_SIGNING_CERT_SHA256.trim().lowercase()
        if (expected.isEmpty()) return
        require(expected.matches(Regex("[a-f0-9]{64}"))) {
            "Некорректная конфигурация подписи FedMes."
        }

        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        val signingInfo = packageInfo.signingInfo
            ?: throw SecurityException("Android не вернул сведения о подписи FedMes.")
        val signers = if (signingInfo.hasMultipleSigners()) {
            signingInfo.apkContentsSigners
        } else {
            signingInfo.signingCertificateHistory
        }
        val trusted = signers.any { signature ->
            val actual = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
            val expectedBytes = expected.hexBytes()
            try {
                MessageDigest.isEqual(actual, expectedBytes)
            } finally {
                actual.fill(0)
                expectedBytes.fill(0)
            }
        }
        if (!trusted) throw SecurityException("Подпись установленного FedMes не прошла проверку.")
    }

    private fun String.hexBytes(): ByteArray = chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

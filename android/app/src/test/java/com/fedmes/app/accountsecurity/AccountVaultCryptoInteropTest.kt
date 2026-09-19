package com.fedmes.app.accountsecurity

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class AccountVaultCryptoInteropTest {
    @Test
    fun recoveryInteropVectorRestoresExpectedAccountRootKey() {
        val recoveryPackage = EncryptedRecoveryPackage(
            id = "00000000-0000-4000-8000-000000000014",
            vaultRevision = 7,
            packageVersion = 1,
            cryptoVersion = 2,
            aadVersion = 1,
            kdfName = "PBKDF2-HMAC-SHA256",
            kdfParameters = """{"iterations":310000,"key_bits":256,"password_encoding":"base64url-canonical"}""",
            salt = Base64.getDecoder().decode("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
            nonce = Base64.getDecoder().decode("YGFiY2RlZmdoaWpr"),
            ciphertext = Base64.getDecoder().decode(
                "vpN1OM8iNs68w0Q6KCJXsB7lhUHDgvknuq/lg163PrWlYKgn6MDal2HLOe8JnzzC",
            ),
            ciphertextSha256Hex = "b6dcdb83a6d8c9e29700f1b4ad6e33d1270d7dc60879a4e719a80798850f4449",
        )
        val restored = AccountVaultCrypto().recoverAccountRootKey(
            serverUrl = "https://fedmes.example",
            username = "grisha",
            recoveryKeyText = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            recoveryPackage = recoveryPackage,
        )
        try {
            assertArrayEquals(
                ByteArray(32) { it.toByte() },
                restored,
            )
        } finally {
            restored.fill(0)
            recoveryPackage.salt.fill(0)
            recoveryPackage.nonce.fill(0)
            recoveryPackage.ciphertext.fill(0)
        }
    }
}

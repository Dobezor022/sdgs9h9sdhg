package com.fedmes.app.accountsecurity

import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal data class OpaqueRecoveryEnvelope(
    val vaultRevision: Long,
    val packageVersion: Int,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val ciphertextHash: ByteArray,
)

internal class OpaqueRecoveryCrypto(private val random: SecureRandom = SecureRandom()) {
    fun encrypt(serverUrl: String, username: String, exportKey: ByteArray, accountRootKey: ByteArray, vaultRevision: Long): OpaqueRecoveryEnvelope {
        require(accountRootKey.size == 32 && vaultRevision > 0 && exportKey.size >= 32)
        val key = derive(exportKey, serverUrl, username)
        val plaintext = JSONObject().put("version", 1).put("username", username).put("vault_revision", vaultRevision)
            .put("account_root_key", Base64.encodeToString(accountRootKey, Base64.NO_WRAP)).toString().toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(12).also(random::nextBytes)
        val aad = aad(serverUrl, username, vaultRevision)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            OpaqueRecoveryEnvelope(vaultRevision, 1, nonce, ciphertext, MessageDigest.getInstance("SHA-256").digest(ciphertext))
        } finally { key.fill(0); plaintext.fill(0); aad.fill(0) }
    }
    fun decrypt(serverUrl: String, username: String, exportKey: ByteArray, envelope: OpaqueRecoveryEnvelope): ByteArray {
        val hash = MessageDigest.getInstance("SHA-256").digest(envelope.ciphertext)
        if (!MessageDigest.isEqual(hash, envelope.ciphertextHash)) { hash.fill(0); throw AccountSecurityException("opaque_recovery_corrupt") }
        hash.fill(0)
        require(exportKey.size >= 32)
        val key = derive(exportKey, serverUrl, username)
        val aad = aad(serverUrl, username, envelope.vaultRevision)
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, envelope.nonce))
            cipher.updateAAD(aad); cipher.doFinal(envelope.ciphertext)
        } catch (error: Exception) { throw AccountSecurityException("opaque_recovery_failed", error) }
        finally { key.fill(0); aad.fill(0) }
        return try {
            val root = JSONObject(plaintext.toString(Charsets.UTF_8))
            if (root.getInt("version") != 1 || root.getString("username") != username || root.getLong("vault_revision") != envelope.vaultRevision) throw AccountSecurityException("opaque_recovery_scope")
            Base64.decode(root.getString("account_root_key"), Base64.NO_WRAP).also { if (it.size != 32) { it.fill(0); throw AccountSecurityException("opaque_recovery_key") } }
        } finally { plaintext.fill(0) }
    }
    private fun derive(exportKey: ByteArray, serverUrl: String, username: String): ByteArray {
        val salt = MessageDigest.getInstance("SHA-256").digest("fedmes-opaque-recovery-salt-v1\n$serverUrl\n$username".toByteArray())
        val extract = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(salt, "HmacSHA256")); doFinal(exportKey) }
        salt.fill(0)
        return try { Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(extract, "HmacSHA256")); doFinal("fedmes-opaque-recovery-key-v1\u0001".toByteArray()).copyOf(32) } }
        finally { extract.fill(0) }
    }
    private fun aad(serverUrl: String, username: String, revision: Long) = "fedmes-opaque-recovery-v1\n$serverUrl\n$username\n$revision".toByteArray()
}

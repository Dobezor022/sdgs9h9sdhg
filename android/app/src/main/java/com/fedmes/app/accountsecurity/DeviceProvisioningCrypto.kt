package com.fedmes.app.accountsecurity

import android.util.Base64
import com.fedmes.app.security.AndroidProvisioningKeyStore
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class DeviceProvisioningCrypto(
    private val keyStore: AndroidProvisioningKeyStore,
    private val random: SecureRandom = SecureRandom(),
) {
    data class Encrypted(val blob: ByteArray, val nonce: ByteArray)
    data class Decrypted(val accountRootKey: ByteArray, val vaultRevision: Long)

    fun encryptFor(request: PendingDeviceRequest, issuerDeviceId: String, accountRootKey: ByteArray, vaultRevision: Long): Encrypted {
        require(request.keyAgreementAlgorithm == AndroidProvisioningKeyStore.ALGORITHM && accountRootKey.size == 32 && vaultRevision > 0)
        val payload = JSONObject()
            .put("version", 1).put("username", request.username).put("target_device_id", request.targetDeviceId)
            .put("issuer_device_id", issuerDeviceId).put("vault_revision", vaultRevision)
            .put("account_root_key", Base64.encodeToString(accountRootKey, Base64.NO_WRAP))
            .toString().toByteArray(Charsets.UTF_8)
        val aesKey = ByteArray(32).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        val aad = aad(request.id, request.targetDeviceId, vaultRevision)
        val ciphertext = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, nonce)); updateAAD(aad); doFinal(payload)
            }
        } finally { payload.fill(0); aad.fill(0) }
        val publicKey = parseRsa(request.keyAgreementPublicKeySpkiBase64)
        val wrapped = try {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").run { init(Cipher.ENCRYPT_MODE, publicKey); doFinal(aesKey) }
        } finally { aesKey.fill(0) }
        val blob = ByteBuffer.allocate(4 + wrapped.size + ciphertext.size).putInt(wrapped.size).put(wrapped).put(ciphertext).array()
        wrapped.fill(0); ciphertext.fill(0)
        return Encrypted(blob, nonce)
    }

    fun decrypt(
        serverUrl: String,
        username: String,
        requestId: String,
        targetDeviceId: String,
        encrypted: ByteArray,
        nonce: ByteArray,
        expectedVaultRevision: Long,
    ): Decrypted {
        if (encrypted.size < 420 || nonce.size != 12) throw AccountSecurityException("provisioning_package_invalid")
        val buffer = ByteBuffer.wrap(encrypted)
        val wrappedSize = buffer.int
        if (wrappedSize !in 256..512 || wrappedSize >= buffer.remaining()) throw AccountSecurityException("provisioning_package_invalid")
        val wrapped = ByteArray(wrappedSize).also(buffer::get)
        val ciphertext = ByteArray(buffer.remaining()).also(buffer::get)
        val aesKey = try { keyStore.decrypt(serverUrl, username, wrapped) } finally { wrapped.fill(0) }
        if (expectedVaultRevision <= 0) throw AccountSecurityException("provisioning_package_invalid")
        try {
            val revision = expectedVaultRevision
            run {
                val aad = aad(requestId, targetDeviceId, revision)
                val plaintext = try {
                    Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, nonce)); updateAAD(aad); doFinal(ciphertext)
                    }
                } catch (error: Exception) {
                    throw AccountSecurityException("provisioning_package_decryption_failed", error)
                } finally { aad.fill(0) }
                try {
                    val root = JSONObject(plaintext.toString(Charsets.UTF_8))
                    if (root.getInt("version") != 1 || root.getString("username") != username ||
                        root.getString("target_device_id") != targetDeviceId || root.getLong("vault_revision") != revision
                    ) throw AccountSecurityException("provisioning_package_scope")
                    val ark = Base64.decode(root.getString("account_root_key"), Base64.NO_WRAP)
                    if (ark.size != 32) { ark.fill(0); throw AccountSecurityException("provisioning_package_key") }
                    return Decrypted(ark, revision)
                } finally { plaintext.fill(0) }
            }
        } catch (error: AccountSecurityException) {
            throw error
        } catch (error: Exception) {
            throw AccountSecurityException("provisioning_package_decryption_failed", error)
        } finally { aesKey.fill(0); ciphertext.fill(0) }
    }

    fun verifyCertificate(payload: ByteArray, signature: ByteArray, algorithm: String): JSONObject {
        val root = try { JSONObject(payload.toString(Charsets.UTF_8)) } catch (error: Exception) {
            throw AccountSecurityException("device_certificate_invalid", error)
        }
        val key = parseSigning(root.getString("issuer_signing_public_key_spki"), algorithm)
        val verifier = when (algorithm) {
            "ecdsa-p256-sha256" -> Signature.getInstance("SHA256withECDSA")
            "ed25519" -> Signature.getInstance("Ed25519")
            else -> throw AccountSecurityException("device_certificate_algorithm")
        }
        verifier.initVerify(key); verifier.update(payload)
        if (!verifier.verify(signature)) throw AccountSecurityException("device_certificate_signature_invalid")
        return root
    }

    private fun parseRsa(base64: String): PublicKey = try {
        val der = Base64.decode(base64, Base64.NO_WRAP)
        try { KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der)) } finally { der.fill(0) }
    } catch (error: Exception) { throw AccountSecurityException("provisioning_public_key_invalid", error) }

    private fun parseSigning(base64: String, algorithm: String): PublicKey = try {
        val der = Base64.decode(base64, Base64.NO_WRAP)
        try {
            val name = if (algorithm == "ed25519") "Ed25519" else "EC"
            KeyFactory.getInstance(name).generatePublic(X509EncodedKeySpec(der))
        } finally { der.fill(0) }
    } catch (error: Exception) { throw AccountSecurityException("device_certificate_key_invalid", error) }

    private fun aad(requestId: String, targetDeviceId: String, vaultRevision: Long): ByteArray =
        "fedmes-provisioning-package-v1\n$requestId\n$targetDeviceId\n$vaultRevision".toByteArray(Charsets.UTF_8)
}

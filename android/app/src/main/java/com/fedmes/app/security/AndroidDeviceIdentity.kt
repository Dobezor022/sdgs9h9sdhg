package com.fedmes.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.fedmes.app.provisioning.DeviceIdentity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

interface DeviceIdentityStore {
    fun getOrCreate(serverUrl: String, username: String): DeviceIdentity
    fun getExisting(serverUrl: String, username: String): DeviceIdentity?
    fun signSha256EcdsaBase64(serverUrl: String, username: String, payload: ByteArray): String
}

/**
 * Stores a separate authentication key for every server/account pair.
 *
 * Builds through 10011 used one global alias for the whole installation. Build 10011 remembers
 * which account owns that legacy alias and uses a scoped alias for every other account. This keeps
 * an existing session recoverable while allowing grisha, papa, and the other accounts to sign in
 * on the same phone without sending a globally duplicated public-key fingerprint to the server.
 */
class AndroidDeviceIdentity(context: Context) : DeviceIdentityStore {
    private val preferences = context.applicationContext.getSharedPreferences(
        KEY_OWNERSHIP_PREFERENCES,
        Context.MODE_PRIVATE,
    )

    override fun getOrCreate(serverUrl: String, username: String): DeviceIdentity = synchronized(lock) {
        val keyStore = loadKeyStore()
        val alias = provisioningAlias(keyStore, serverUrl, username)
        val publicKey = keyStore.getCertificate(alias)?.publicKey?.let {
            it as? ECPublicKey
                ?: throw IllegalStateException("Stored device identity has an unexpected algorithm")
        } ?: generate(alias)
        publicKey.toIdentity()
    }

    override fun getExisting(serverUrl: String, username: String): DeviceIdentity? = synchronized(lock) {
        val keyStore = loadKeyStore()
        val alias = existingAlias(keyStore, serverUrl, username, claimLegacyOwner = true)
            ?: return@synchronized null
        val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
            ?: return@synchronized null
        publicKey.toIdentity()
    }

    override fun signSha256EcdsaBase64(
        serverUrl: String,
        username: String,
        payload: ByteArray,
    ): String {
        val signature = signSha256Ecdsa(serverUrl, username, payload)
        return try {
            Base64.encodeToString(signature, Base64.NO_WRAP)
        } finally {
            signature.fill(0)
        }
    }

    private fun signSha256Ecdsa(serverUrl: String, username: String, payload: ByteArray): ByteArray =
        synchronized(lock) {
            require(payload.isNotEmpty() && payload.size <= MAX_SIGNED_PAYLOAD_BYTES) {
                "Device authentication payload has an invalid size"
            }
            val keyStore = loadKeyStore()
            val alias = existingAlias(keyStore, serverUrl, username, claimLegacyOwner = true)
                ?: throw IllegalStateException("Device identity is not available")
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: throw IllegalStateException("Device identity is not available")
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initSign(privateKey)
                update(payload)
                sign()
            }
        }

    private fun provisioningAlias(keyStore: KeyStore, serverUrl: String, username: String): String {
        val scoped = scopedAlias(serverUrl, username)
        if (keyStore.containsAlias(scoped)) return scoped
        val owner = preferences.getString(LEGACY_IDENTITY_OWNER, null)
        val requestedOwner = AccountKeyScope.hashHex(serverUrl, username)
        if (owner == requestedOwner && keyStore.containsAlias(LEGACY_IDENTITY_ALIAS)) {
            return LEGACY_IDENTITY_ALIAS
        }
        return scoped
    }

    private fun existingAlias(
        keyStore: KeyStore,
        serverUrl: String,
        username: String,
        claimLegacyOwner: Boolean,
    ): String? {
        val scoped = scopedAlias(serverUrl, username)
        if (keyStore.containsAlias(scoped)) return scoped
        if (!keyStore.containsAlias(LEGACY_IDENTITY_ALIAS)) return null

        val requestedOwner = AccountKeyScope.hashHex(serverUrl, username)
        val owner = preferences.getString(LEGACY_IDENTITY_OWNER, null)
        if (owner == requestedOwner) return LEGACY_IDENTITY_ALIAS
        if (owner == null && claimLegacyOwner) {
            preferences.edit().putString(LEGACY_IDENTITY_OWNER, requestedOwner).commit()
            return LEGACY_IDENTITY_ALIAS
        }
        return null
    }

    private fun generate(alias: String): ECPublicKey {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE,
        )
        val parameters = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        generator.initialize(parameters)
        return generator.generateKeyPair().public as ECPublicKey
    }

    private fun ECPublicKey.toIdentity() = DeviceIdentity(
        algorithm = DEVICE_KEY_ALGORITHM,
        publicKeySpkiBase64 = Base64.encodeToString(encoded, Base64.NO_WRAP),
    )

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun scopedAlias(serverUrl: String, username: String): String =
        "$SCOPED_ALIAS_PREFIX.${AccountKeyScope.aliasSuffix(serverUrl, username)}"

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val LEGACY_IDENTITY_ALIAS = "fedmes.device.identity.p256.v1"
        const val SCOPED_ALIAS_PREFIX = "fedmes.device.identity.p256.v2"
        const val KEY_OWNERSHIP_PREFERENCES = "fedmes.keystore.ownership.v1"
        const val LEGACY_IDENTITY_OWNER = "legacy_identity_owner"
        const val P256_CURVE = "secp256r1"
        const val DEVICE_KEY_ALGORITHM = "ecdsa-p256-sha256"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val MAX_SIGNED_PAYLOAD_BYTES = 4_096
        val lock = Any()
    }
}

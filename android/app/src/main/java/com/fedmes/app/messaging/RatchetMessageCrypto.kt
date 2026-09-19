package com.fedmes.app.messaging

import android.util.Base64
import com.fedmes.app.accountsecurity.AndroidAccountVaultStore
import com.fedmes.app.cryptocore.FedMesCryptoCore
import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.security.AndroidDeviceIdentity
import org.json.JSONObject
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto version 2 message engine.
 *
 * Direct/favorites messages use a fresh AES-256-GCM content key per message;
 * that key is delivered to every READY device through independent Olm sessions.
 * The family room uses a rotated Megolm sender session whose session key is
 * distributed to every READY device through Olm. Ratchet state is atomically
 * encrypted at rest with a key derived from Account Root Key.
 */
class RatchetMessageCrypto(
    private val core: FedMesCryptoCore,
    private val api: RatchetHttpApi,
    private val store: AndroidRatchetStore,
    private val vaultStore: AndroidAccountVaultStore,
    private val deviceIdentity: AndroidDeviceIdentity,
    private val messageCrypto: MessageCrypto,
    private val random: SecureRandom = SecureRandom(),
) {
    @Synchronized
    fun initialize(account: ProvisionedAccount) = withRootKey(account) { rootKey ->
        val key = pickleKey(rootKey, account)
        try {
            val state = loadOrCreateState(account, rootKey, key)
            ensurePublishableKeys(account, rootKey, key, state)
        } finally { key.fill(0) }
    }

    @Synchronized
    fun prepare(
        account: ProvisionedAccount,
        chat: ChatSummary,
        content: MessageContent,
        devices: List<ChatDevice>,
        messageId: String,
        cryptoSequence: Long,
        sequenceRequestId: String,
    ): PreparedMessage = withRootKey(account) { rootKey ->
        val key = pickleKey(rootKey, account)
        try {
            val state = loadOrCreateState(account, rootKey, key)
            ensurePublishableKeys(account, rootKey, key, state)
            when (chat.kind) {
                "family" -> prepareGroup(account, chat, content, devices, messageId, cryptoSequence, sequenceRequestId, rootKey, key, state)
                "direct", "favorites" -> prepareDirect(account, chat, content, devices, messageId, cryptoSequence, sequenceRequestId, rootKey, key, state)
                else -> error("Unsupported encrypted chat kind")
            }
        } finally { key.fill(0) }
    }

    @Synchronized
    fun decrypt(account: ProvisionedAccount, message: WireMessage): DecryptedMessage = withRootKey(account) { rootKey ->
        require(message.cryptoVersion == 2 && message.aadVersion == 2 && message.cryptoSequence > 0)
        require(message.aad == canonicalAad(message.chatId, message.senderUsername, message.senderDeviceId, message.id, message.messageType, message.cryptoSequence, message.roomKeyVersion))
        val key = pickleKey(rootKey, account)
        try {
            val state = loadOrCreateState(account, rootKey, key)
            when (message.encryptionAlgorithm) {
                ALGORITHM_OLM -> decryptDirect(account, message, rootKey, key, state)
                ALGORITHM_MEGOLM -> decryptGroup(account, message, rootKey, key, state)
                else -> error("Unsupported message encryption algorithm")
            }
        } finally { key.fill(0) }
    }

    private fun prepareDirect(
        account: ProvisionedAccount,
        chat: ChatSummary,
        content: MessageContent,
        devices: List<ChatDevice>,
        messageId: String,
        cryptoSequence: Long,
        sequenceRequestId: String,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): PreparedMessage {
        require(devices.isNotEmpty() && devices.any { it.id == account.deviceId })
        val messageType = content.kind.name.lowercase()
        val aad = canonicalAad(chat.id, account.username, account.deviceId, messageId, messageType, cryptoSequence, 1)
        val contentKey = randomBytes(32)
        val nonce = randomBytes(12)
        val plaintext = messageCrypto.encodeContent(content)
        val padded = messageCrypto.pad(plaintext)
        plaintext.fill(0)
        val ciphertext = try {
            messageCrypto.aesGcm(Cipher.ENCRYPT_MODE, contentKey, nonce, aad.toByteArray(Charsets.UTF_8), padded)
        } finally { padded.fill(0) }
        val envelopes = mutableListOf<RatchetMessageEnvelope>()
        try {
            devices.sortedBy(ChatDevice::id).forEach { device ->
                envelopes += if (device.id == account.deviceId) {
                    state.ownMessageKeys[messageId] = rawUrl(contentKey)
                    // The server requires an envelope for every READY device. A
                    // self envelope is a real Olm pre-key message; local reloads
                    // use the ARK-encrypted ownMessageKeys cache to avoid replaying
                    // the same pre-key message through the inbound ratchet twice.
                    createSelfEnvelope(account, device, contentKey, rootKey, pickleKey, state)
                } else {
                    encryptForPeer(account, device, contentKey, pickleKey, state)
                }
            }
            trimOwnKeys(state)
            store.save(account.serverUrl, account.username, rootKey, state)
            return PreparedMessage(
                id = messageId,
                ciphertextBase64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
                nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP),
                aad = aad,
                protocolVersion = 2,
                cryptoVersion = 2,
                roomKeyVersion = 1,
                aadVersion = 2,
                cryptoSequence = cryptoSequence,
                encryptionAlgorithm = ALGORITHM_OLM,
                messageType = messageType,
                sequenceRequestId = sequenceRequestId,
                ratchetEnvelopes = envelopes,
            )
        } finally {
            contentKey.fill(0); nonce.fill(0); ciphertext.fill(0)
        }
    }

    private fun prepareGroup(
        account: ProvisionedAccount,
        chat: ChatSummary,
        content: MessageContent,
        devices: List<ChatDevice>,
        messageId: String,
        cryptoSequence: Long,
        sequenceRequestId: String,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): PreparedMessage {
        val group = state.outboundGroups[chat.id] ?: createAndPublishGroup(account, chat, devices, rootKey, pickleKey, state)
        val messageType = content.kind.name.lowercase()
        val aad = canonicalAad(chat.id, account.username, account.deviceId, messageId, messageType, cryptoSequence, group.roomKeyVersion)
        val contentBytes = messageCrypto.encodeContent(content)
        val payload = JSONObject().put("version", 1).put("aad", aad).put("content", rawUrl(contentBytes))
            .toString().toByteArray(Charsets.UTF_8)
        contentBytes.fill(0)
        val encrypted = try { core.megolmEncrypt(group.pickle, rawUrl(pickleKey), rawUrl(payload)) } finally { payload.fill(0) }
        group.pickle = encrypted.getString("pickle")
        val sessionId = encrypted.getString("session_id")
        require(sessionId == group.sessionId)
        val ciphertextAscii = encrypted.getString("ciphertext").toByteArray(Charsets.US_ASCII)
        val nonce = randomBytes(12) // routing metadata; integrity is provided by Megolm and AAD in plaintext.
        try {
            store.save(account.serverUrl, account.username, rootKey, state)
            return PreparedMessage(
                id = messageId,
                ciphertextBase64 = Base64.encodeToString(ciphertextAscii, Base64.NO_WRAP),
                nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP),
                aad = aad,
                protocolVersion = 2,
                cryptoVersion = 2,
                roomKeyVersion = group.roomKeyVersion,
                aadVersion = 2,
                cryptoSequence = cryptoSequence,
                encryptionAlgorithm = ALGORITHM_MEGOLM,
                messageType = messageType,
                sequenceRequestId = sequenceRequestId,
            )
        } finally { ciphertextAscii.fill(0); nonce.fill(0) }
    }

    private fun decryptDirect(
        account: ProvisionedAccount,
        message: WireMessage,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): DecryptedMessage {
        val contentKey = state.ownMessageKeys[message.id]?.let(::decodeRawUrl) ?: run {
            val envelope = requireNotNull(message.ratchetEnvelope)
            require(envelope.recipientDeviceId == account.deviceId)
            decryptOlmEnvelope(account, message.senderDeviceId, envelope, pickleKey, state)
        }
        try {
            require(contentKey.size == 32)
            val nonce = Base64.decode(message.nonceBase64, Base64.NO_WRAP)
            val ciphertext = Base64.decode(message.ciphertextBase64, Base64.NO_WRAP)
            val padded = try {
                messageCrypto.aesGcm(Cipher.DECRYPT_MODE, contentKey, nonce, message.aad.toByteArray(Charsets.UTF_8), ciphertext)
            } finally { nonce.fill(0); ciphertext.fill(0) }
            val plaintext = try { messageCrypto.unpad(padded) } finally { padded.fill(0) }
            return try { messageCrypto.toDecryptedMessage(message, messageCrypto.decodeContent(plaintext), true) }
            finally { plaintext.fill(0) }
        } finally {
            contentKey.fill(0)
            store.save(account.serverUrl, account.username, rootKey, state)
        }
    }

    private fun decryptGroup(
        account: ProvisionedAccount,
        message: WireMessage,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): DecryptedMessage {
        importPendingGroups(account, rootKey, pickleKey, state)
        val groupKey = groupKey(message.chatId, message.roomKeyVersion)
        var groupPickle = state.inboundGroups[groupKey]
        if (groupPickle == null && message.senderDeviceId == account.deviceId) {
            val outbound = state.outboundGroups[message.chatId]
            if (outbound != null && outbound.roomKeyVersion == message.roomKeyVersion) {
                groupPickle = core.megolmCreateInbound(outbound.sessionKey, rawUrl(pickleKey))
                state.inboundGroups[groupKey] = groupPickle
            }
        }
        requireNotNull(groupPickle) { "Group key is not available" }
        val ciphertextAscii = Base64.decode(message.ciphertextBase64, Base64.NO_WRAP).toString(Charsets.US_ASCII)
        val result = core.megolmDecrypt(groupPickle, rawUrl(pickleKey), ciphertextAscii)
        val sessionId = result.getString("session_id")
        val messageIndex = result.getLong("message_index")
        val replayKey = "$sessionId:$messageIndex"
        val ciphertextHash = sha256Hex(ciphertextAscii.toByteArray(Charsets.US_ASCII))
        val previousHash = state.seenGroupIndexes[replayKey]
        require(previousHash == null || constantTimeHexEquals(previousHash, ciphertextHash)) { "Megolm replay conflict" }
        state.seenGroupIndexes[replayKey] = ciphertextHash
        trimSeenGroupIndexes(state)
        state.inboundGroups[groupKey] = result.getString("pickle")
        val plaintext = decodeRawUrl(result.getString("plaintext"))
        try {
            val root = JSONObject(plaintext.toString(Charsets.UTF_8))
            require(root.optInt("version") == 1 && root.getString("aad") == message.aad)
            val content = decodeRawUrl(root.getString("content"))
            return try { messageCrypto.toDecryptedMessage(message, messageCrypto.decodeContent(content), true) }
            finally { content.fill(0) }
        } finally {
            plaintext.fill(0)
            store.save(account.serverUrl, account.username, rootKey, state)
        }
    }

    private fun createAndPublishGroup(
        account: ProvisionedAccount,
        chat: ChatSummary,
        devices: List<ChatDevice>,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): LocalMegolmOutbound {
        require(devices.isNotEmpty())
        val rotationId = UUID.randomUUID().toString()
        val reservation = api.reserveGroupVersion(account, chat.id, rotationId)
        val created = core.megolmCreateOutbound(rawUrl(pickleKey))
        val roomVersion = reservation.roomKeyVersion
        val group = LocalMegolmOutbound(
            roomKeyVersion = roomVersion,
            sessionId = created.getString("session_id"),
            sessionKey = created.getString("session_key"),
            pickle = created.getString("pickle"),
        )
        val packages = mutableListOf<RatchetHttpApi.GroupKeyUpload>()
        val keyBytes = group.sessionKey.toByteArray(Charsets.US_ASCII)
        try {
            devices.sortedBy(ChatDevice::id).forEach { device ->
                val envelope = if (device.id == account.deviceId) {
                    createSelfEnvelope(account, device, keyBytes, rootKey, pickleKey, state)
                } else {
                    encryptForPeer(account, device, keyBytes, pickleKey, state)
                }
                val encrypted = decodeRawUrl(envelope.ciphertextBase64Url)
                packages += RatchetHttpApi.GroupKeyUpload(device.id, envelope.sessionId, envelope.messageType, encrypted)
            }
            api.putGroupSession(account, chat.id, roomVersion, group.sessionId, rotationId, packages)
            state.outboundGroups[chat.id] = group
            state.inboundGroups[groupKey(chat.id, roomVersion)] = core.megolmCreateInbound(group.sessionKey, rawUrl(pickleKey))
            store.save(account.serverUrl, account.username, rootKey, state)
            return group
        } finally {
            keyBytes.fill(0)
            packages.forEach { it.encryptedSessionKey.fill(0) }
        }
    }

    private fun importPendingGroups(account: ProvisionedAccount, rootKey: ByteArray, pickleKey: ByteArray, state: LocalOlmState) {
        api.listGroupPackages(account).forEach { pkg ->
            try {
                val envelope = RatchetMessageEnvelope(
                    recipientDeviceId = account.deviceId,
                    senderCurve25519Key = pkg.senderCurve25519Key,
                    sessionId = pkg.olmSessionId,
                    messageType = pkg.messageType,
                    ciphertextBase64Url = rawUrl(pkg.encryptedSessionKey),
                    ciphertextSha256Hex = sha256Hex(pkg.encryptedSessionKey),
                )
                val sessionKey = decryptOlmEnvelope(account, pkg.senderDeviceId, envelope, pickleKey, state)
                try {
                    val text = sessionKey.toString(Charsets.US_ASCII)
                    val incoming = core.megolmCreateInbound(text, rawUrl(pickleKey))
                    state.inboundGroups[groupKey(pkg.chatId, pkg.roomKeyVersion)] = incoming
                    api.consumeGroupPackage(account, pkg.chatId, pkg.roomKeyVersion)
                } finally { sessionKey.fill(0) }
            } finally { pkg.encryptedSessionKey.fill(0) }
        }
        store.save(account.serverUrl, account.username, rootKey, state)
    }

    private fun encryptForPeer(
        account: ProvisionedAccount,
        device: ChatDevice,
        plaintext: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): RatchetMessageEnvelope {
        val peerKey = "peer:${device.id}"
        var sessionPickle = state.sessions[peerKey]
        var senderCurve = state.curve25519IdentityKey
        if (sessionPickle == null) {
            val claimed = api.claim(account, device.id)
            verifyClaim(device, claimed)
            val outbound = core.olmCreateOutbound(state.accountPickle, rawUrl(pickleKey), claimed.curve25519IdentityKey, claimed.oneTimeKey.publicKey)
            sessionPickle = outbound.getString("pickle")
            state.sessions["curve:${device.id}"] = claimed.curve25519IdentityKey
        }
        val encrypted = core.olmEncrypt(sessionPickle, rawUrl(pickleKey), rawUrl(plaintext))
        val updated = encrypted.getString("pickle")
        val sessionId = encrypted.getString("session_id")
        state.sessions[peerKey] = updated
        state.sessions["session:$sessionId"] = updated
        val ciphertextAscii = encrypted.getString("ciphertext").toByteArray(Charsets.US_ASCII)
        return try {
            RatchetMessageEnvelope(device.id, senderCurve, sessionId, encrypted.getInt("message_type"), rawUrl(ciphertextAscii), sha256Hex(ciphertextAscii))
        } finally { ciphertextAscii.fill(0) }
    }

    private fun createSelfEnvelope(
        account: ProvisionedAccount,
        device: ChatDevice,
        plaintext: ByteArray,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): RatchetMessageEnvelope {
        if (state.selfOneTimeKey.isNullOrBlank()) ensurePublishableKeys(account, rootKey, pickleKey, state)
        val oneTimeKey = requireNotNull(state.selfOneTimeKey)
        val outbound = core.olmCreateOutbound(state.accountPickle, rawUrl(pickleKey), state.curve25519IdentityKey, oneTimeKey)
        val encrypted = core.olmEncrypt(outbound.getString("pickle"), rawUrl(pickleKey), rawUrl(plaintext))
        val ciphertext = encrypted.getString("ciphertext")
        val messageType = encrypted.getInt("message_type")
        val inbound = core.olmCreateInbound(state.accountPickle, rawUrl(pickleKey), state.curve25519IdentityKey, ciphertext, messageType)
        state.accountPickle = inbound.getString("account_pickle")
        val sessionId = inbound.getString("session_id")
        state.sessions["session:$sessionId"] = inbound.getString("session_pickle")
        state.selfOneTimeKey = null
        state.selfOneTimeKeyId = null
        val ascii = ciphertext.toByteArray(Charsets.US_ASCII)
        return try {
            RatchetMessageEnvelope(device.id, state.curve25519IdentityKey, sessionId, messageType, rawUrl(ascii), sha256Hex(ascii))
        } finally { ascii.fill(0) }
    }

    private fun decryptOlmEnvelope(
        account: ProvisionedAccount,
        senderDeviceId: String,
        envelope: RatchetMessageEnvelope,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ): ByteArray {
        val asciiBytes = decodeRawUrl(envelope.ciphertextBase64Url)
        if (!constantTimeHexEquals(envelope.ciphertextSha256Hex, sha256Hex(asciiBytes))) {
            asciiBytes.fill(0); error("Ratchet envelope hash mismatch")
        }
        val ciphertext = try { asciiBytes.toString(Charsets.US_ASCII) } finally { asciiBytes.fill(0) }
        var sessionPickle = state.sessions["session:${envelope.sessionId}"]
        val result = if (sessionPickle == null && envelope.messageType == 0) {
            core.olmCreateInbound(state.accountPickle, rawUrl(pickleKey), envelope.senderCurve25519Key, ciphertext, envelope.messageType)
                .also {
                    state.accountPickle = it.getString("account_pickle")
                    sessionPickle = it.getString("session_pickle")
                }
        } else {
            core.olmDecrypt(requireNotNull(sessionPickle), rawUrl(pickleKey), ciphertext, envelope.messageType)
        }
        val updated = result.getString("session_pickle")
        state.sessions["session:${envelope.sessionId}"] = updated
        state.sessions["peer:$senderDeviceId"] = updated
        state.sessions["curve:$senderDeviceId"] = envelope.senderCurve25519Key
        return decodeRawUrl(result.getString("plaintext"))
    }

    private fun ensurePublishableKeys(
        account: ProvisionedAccount,
        rootKey: ByteArray,
        pickleKey: ByteArray,
        state: LocalOlmState,
    ) {
        if (!state.selfOneTimeKey.isNullOrBlank() && state.bundleVersion > 0) return
        val generated = core.olmRefillOneTimeKeys(state.accountPickle, rawUrl(pickleKey), 33)
        state.accountPickle = generated.getString("pickle")
        val identity = JSONObject(generated.getString("identity_keys"))
        state.curve25519IdentityKey = identity.getString("curve25519")
        state.ed25519IdentityKey = identity.getString("ed25519")
        val oneTimeRoot = JSONObject(generated.getString("one_time_keys")).getJSONObject("curve25519")
        val entries = oneTimeRoot.keys().asSequence().map { it to oneTimeRoot.getString(it) }.sortedBy { it.first }.toList()
        require(entries.size >= 2) { "Crypto core did not generate enough one-time keys" }
        val self = entries.first()
        state.selfOneTimeKeyId = self.first
        state.selfOneTimeKey = self.second
        state.bundleVersion += 1
        val bundlePayload = canonicalBundle(account.deviceId, state.bundleVersion, state.curve25519IdentityKey, state.ed25519IdentityKey)
        val bundleSignature = sign(account, bundlePayload)
        val uploads = entries.drop(1).take(32).map { (id, value) ->
            val payload = canonicalOtk(account.deviceId, id, value)
            val signature = sign(account, payload)
            payload.fill(0)
            RatchetHttpApi.OneTimeKey(id, value, signature)
        }
        try {
            api.putBundle(account, state.bundleVersion, state.curve25519IdentityKey, state.ed25519IdentityKey, bundlePayload, bundleSignature, uploads)
            state.accountPickle = core.olmMarkKeysPublished(state.accountPickle, rawUrl(pickleKey))
            store.save(account.serverUrl, account.username, rootKey, state)
        } finally {
            bundlePayload.fill(0); bundleSignature.fill(0); uploads.forEach { it.signature.fill(0) }
        }
    }

    private fun loadOrCreateState(account: ProvisionedAccount, rootKey: ByteArray, pickleKey: ByteArray): LocalOlmState {
        store.load(account.serverUrl, account.username, rootKey)?.let { return it }
        val created = core.olmCreateAccount(rawUrl(pickleKey), 1)
        val identity = JSONObject(created.getString("identity_keys"))
        val state = LocalOlmState(
            accountPickle = created.getString("pickle"),
            curve25519IdentityKey = identity.getString("curve25519"),
            ed25519IdentityKey = identity.getString("ed25519"),
            selfOneTimeKeyId = null,
            selfOneTimeKey = null,
            bundleVersion = 0,
            sessions = mutableMapOf(),
            outboundGroups = mutableMapOf(),
            inboundGroups = mutableMapOf(),
            ownMessageKeys = mutableMapOf(),
            seenGroupIndexes = mutableMapOf(),
        )
        store.save(account.serverUrl, account.username, rootKey, state)
        return state
    }

    private fun verifyClaim(device: ChatDevice, claimed: RatchetHttpApi.ClaimedKey) {
        require(claimed.deviceId == device.id)
        val bundle = canonicalBundle(claimed.deviceId, claimed.bundleVersion, claimed.curve25519IdentityKey, claimed.ed25519IdentityKey)
        val otk = canonicalOtk(claimed.deviceId, claimed.oneTimeKey.keyId, claimed.oneTimeKey.publicKey)
        try {
            require(MessageDigest.isEqual(bundle, claimed.signedPayload))
            require(verifyDeviceSignature(device, bundle, claimed.bundleSignature))
            require(verifyDeviceSignature(device, otk, claimed.oneTimeKey.signature))
        } finally {
            bundle.fill(0); otk.fill(0); claimed.signedPayload.fill(0); claimed.bundleSignature.fill(0); claimed.oneTimeKey.signature.fill(0)
        }
    }

    private fun verifyDeviceSignature(device: ChatDevice, payload: ByteArray, signature: ByteArray): Boolean = try {
        val spki = Base64.decode(device.identityPublicKeySpkiBase64, Base64.NO_WRAP)
        val publicKey = try {
            KeyFactory.getInstance(if (device.identityAlgorithm == "ed25519") "Ed25519" else "EC")
                .generatePublic(X509EncodedKeySpec(spki))
        } finally { spki.fill(0) }
        Signature.getInstance(if (device.identityAlgorithm == "ed25519") "Ed25519" else "SHA256withECDSA").run {
            initVerify(publicKey); update(payload); verify(signature)
        }
    } catch (_: Exception) { false }

    private fun sign(account: ProvisionedAccount, payload: ByteArray): ByteArray =
        Base64.decode(deviceIdentity.signSha256EcdsaBase64(account.serverUrl, account.username, payload), Base64.NO_WRAP)

    private inline fun <T> withRootKey(account: ProvisionedAccount, block: (ByteArray) -> T): T {
        val local = vaultStore.load(account.serverUrl, account.username) ?: error("Account Root Key is not available")
        return try { block(local.accountRootKey) } finally { local.accountRootKey.fill(0) }
    }

    private fun pickleKey(rootKey: ByteArray, account: ProvisionedAccount): ByteArray {
        val context = "fedmes-olm-pickle-key-v1\n${account.serverUrl}\n${account.username}\n${account.deviceId}".toByteArray(Charsets.UTF_8)
        return try { Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(rootKey, "HmacSHA256")); doFinal(context) } }
        finally { context.fill(0) }
    }

    private fun canonicalBundle(deviceId: String, version: Int, curve: String, ed: String): ByteArray =
        "fedmes-ratchet-bundle-v1\n$deviceId\n$version\n$curve\n$ed".toByteArray(Charsets.UTF_8)
    private fun canonicalOtk(deviceId: String, keyId: String, key: String): ByteArray =
        "fedmes-olm-otk-v1\n$deviceId\n$keyId\n$key".toByteArray(Charsets.UTF_8)
    private fun canonicalAad(chatId: String, username: String, deviceId: String, messageId: String, messageType: String, sequence: Long, roomKeyVersion: Long): String =
        listOf("fedmes-message-v2", chatId, messageId, username, deviceId, messageType, sequence.toString(), roomKeyVersion.toString(), "aad-v2").joinToString("\n")
    private fun groupKey(chatId: String, version: Long) = "$chatId:$version"
    private fun randomBytes(size: Int) = ByteArray(size).also(random::nextBytes)
    private fun rawUrl(value: ByteArray): String = Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun decodeRawUrl(value: String): ByteArray = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun sha256Hex(value: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun constantTimeHexEquals(left: String, right: String): Boolean {
        val a = left.lowercase().toByteArray(Charsets.US_ASCII)
        val b = right.lowercase().toByteArray(Charsets.US_ASCII)
        return try { MessageDigest.isEqual(a, b) } finally { a.fill(0); b.fill(0) }
    }
    private fun trimOwnKeys(state: LocalOlmState) {
        while (state.ownMessageKeys.size > 50_000) state.ownMessageKeys.remove(state.ownMessageKeys.keys.first())
    }
    private fun trimSeenGroupIndexes(state: LocalOlmState) {
        while (state.seenGroupIndexes.size > 100_000) state.seenGroupIndexes.remove(state.seenGroupIndexes.keys.first())
    }

    companion object {
        const val ALGORITHM_OLM = "fedmes-olm-v1"
        const val ALGORITHM_MEGOLM = "fedmes-megolm-v1"
    }
}

package com.fedmes.app.cryptocore

import org.json.JSONObject
import java.lang.reflect.InvocationTargetException

/**
 * Thin reflection boundary around the gomobile-generated crypto AAR. Reflection
 * keeps Kotlin source independent of gomobile's generated Java package suffix;
 * the release builder verifies and packages the AAR before Gradle starts.
 */
class FedMesCryptoCore {
    data class OpaqueStart(val handle: String, val message: String, val suite: String)
    data class OpaqueFinish(val message: String, val sessionKey: String?, val exportKey: String, val suite: String)

    fun version(): String = invokeString("version")
    fun opaqueRegistrationStart(password: CharArray): OpaqueStart = passwordString(password) {
        parseStart(invokeString("opaqueRegistrationStart", it))
    }
    fun opaqueRegistrationFinish(handle: String, response: String, username: String, serverIdentity: String): OpaqueFinish =
        parseFinish(invokeString("opaqueRegistrationFinish", handle, response, username, serverIdentity))
    fun opaqueLoginStart(password: CharArray): OpaqueStart = passwordString(password) {
        parseStart(invokeString("opaqueLoginStart", it))
    }
    fun opaqueLoginFinish(handle: String, response: String, username: String, serverIdentity: String): OpaqueFinish =
        parseFinish(invokeString("opaqueLoginFinish", handle, response, username, serverIdentity))
    fun opaqueCancel(handle: String) { invokeVoid("opaqueCancel", handle) }

    fun olmCreateAccount(pickleKeyBase64: String, count: Int): JSONObject =
        JSONObject(invokeString("olmCreateAccount", pickleKeyBase64, count.toLong()))
    fun olmRefillOneTimeKeys(accountPickle: String, pickleKeyBase64: String, count: Int): JSONObject =
        JSONObject(invokeString("olmRefillOneTimeKeys", accountPickle, pickleKeyBase64, count.toLong()))
    fun olmMarkKeysPublished(accountPickle: String, pickleKeyBase64: String): String =
        invokeString("olmMarkKeysPublished", accountPickle, pickleKeyBase64)
    fun olmCreateOutbound(accountPickle: String, pickleKeyBase64: String, identityKey: String, oneTimeKey: String): JSONObject =
        JSONObject(invokeString("olmCreateOutbound", accountPickle, pickleKeyBase64, identityKey, oneTimeKey))
    fun olmEncrypt(sessionPickle: String, pickleKeyBase64: String, plaintextBase64: String): JSONObject =
        JSONObject(invokeString("olmEncrypt", sessionPickle, pickleKeyBase64, plaintextBase64))
    fun olmCreateInbound(accountPickle: String, pickleKeyBase64: String, identityKey: String, ciphertext: String, messageType: Int): JSONObject =
        JSONObject(invokeString("olmCreateInbound", accountPickle, pickleKeyBase64, identityKey, ciphertext, messageType.toLong()))
    fun olmDecrypt(sessionPickle: String, pickleKeyBase64: String, ciphertext: String, messageType: Int): JSONObject =
        JSONObject(invokeString("olmDecrypt", sessionPickle, pickleKeyBase64, ciphertext, messageType.toLong()))
    fun megolmCreateOutbound(pickleKeyBase64: String): JSONObject = JSONObject(invokeString("megolmCreateOutbound", pickleKeyBase64))
    fun megolmEncrypt(sessionPickle: String, pickleKeyBase64: String, plaintextBase64: String): JSONObject =
        JSONObject(invokeString("megolmEncrypt", sessionPickle, pickleKeyBase64, plaintextBase64))
    fun megolmCreateInbound(sessionKey: String, pickleKeyBase64: String): String =
        invokeString("megolmCreateInbound", sessionKey, pickleKeyBase64)
    fun megolmDecrypt(sessionPickle: String, pickleKeyBase64: String, ciphertext: String): JSONObject =
        JSONObject(invokeString("megolmDecrypt", sessionPickle, pickleKeyBase64, ciphertext))


    // FedMes 2.0 FSA2 shared security core. All methods delegate to the same
    // gomobile library used by Windows through fedmes-crypto-worker.
    fun security2Version(): String = invokeString("security2Version")
    fun security2GenerateUserRoot(): JSONObject = JSONObject(invokeString("security2GenerateUserRoot"))
    fun security2GenerateDeviceIdentity(): JSONObject = JSONObject(invokeString("security2GenerateDeviceIdentity"))
    fun security2SharedSecret(localPrivate: String, peerPublic: String): String =
        invokeString("security2SharedSecret", localPrivate, peerPublic)
    fun security2NewRatchet(seed: String, domain: String, generation: Long): JSONObject =
        JSONObject(invokeString("security2NewRatchet", seed, domain, generation))
    fun security2EncryptCapsule(state: JSONObject, route: String, transportEpoch: Long, plaintext: String, padTo: Int): JSONObject =
        JSONObject(invokeString("security2EncryptCapsule", state.toString(), route, transportEpoch, plaintext, padTo.toLong()))
    fun security2DecryptCapsule(state: JSONObject, capsule: JSONObject, route: String, transportEpoch: Long): JSONObject =
        JSONObject(invokeString("security2DecryptCapsule", state.toString(), capsule.toString(), route, transportEpoch))
    fun security2HealRatchet(state: JSONObject, shared: String, transcript: String): JSONObject =
        JSONObject(invokeString("security2HealRatchet", state.toString(), shared, transcript))
    fun security2NewCallRoot(shared: String, transcript: String): String =
        invokeString("security2NewCallRoot", shared, transcript)
    fun security2MediaEpochKey(callRoot: String, domain: Int, direction: Int, epoch: Long, fresh: String = ""): String =
        invokeString("security2MediaEpochKey", callRoot, domain.toLong(), direction.toLong(), epoch, fresh)
    fun security2EncryptMedia(epochKey: String, route: String, epoch: Long, sequence: Long, plaintext: String): JSONObject =
        JSONObject(invokeString("security2EncryptMedia", epochKey, route, epoch, sequence, plaintext))
    fun security2DecryptMedia(epochKey: String, route: String, packet: JSONObject): String =
        invokeString("security2DecryptMedia", epochKey, route, packet.toString())
    fun security2DeriveFileRoot(seed: String, fileId: String): String =
        invokeString("security2DeriveFileRoot", seed, fileId)
    fun security2EncryptChunk(root: String, fileId: String, index: Long, data: String): String =
        invokeString("security2EncryptChunk", root, fileId, index, data)
    fun security2DecryptChunk(root: String, fileId: String, index: Long, data: String): String =
        invokeString("security2DecryptChunk", root, fileId, index, data)
    fun security2NewAdmissionRequest(userRootId: String, generation: Long, securityEpoch: Long, device: JSONObject): JSONObject =
        JSONObject(invokeString("security2NewAdmissionRequest", userRootId, generation, securityEpoch, device.toString()))
    fun security2AdmissionCode(request: JSONObject): String =
        invokeString("security2AdmissionCode", request.toString())
    fun security2ApproveAdmission(request: JSONObject, approverDeviceId: String, signPrivate: String): JSONObject =
        JSONObject(invokeString("security2ApproveAdmission", request.toString(), approverDeviceId, signPrivate))

    private fun parseStart(json: String): OpaqueStart = JSONObject(json).let {
        OpaqueStart(it.getString("handle"), it.getString("message"), it.getString("suite"))
    }
    private fun parseFinish(json: String): OpaqueFinish = JSONObject(json).let {
        OpaqueFinish(it.getString("message"), it.optString("session_key").takeIf(String::isNotEmpty), it.getString("export_key"), it.getString("suite"))
    }
    private inline fun <T> passwordString(password: CharArray, block: (String) -> T): T {
        require(password.size in 12..1024 && password.any { !it.isWhitespace() })
        // Managed strings cannot be guaranteed to be wiped. Keep this conversion
        // inside the smallest possible call boundary and clear the caller's array.
        val value = String(password)
        return try { block(value) } finally { password.fill('\u0000') }
    }
    private fun invokeString(name: String, vararg arguments: Any): String = invoke(name, *arguments) as? String
        ?: error("FedMes crypto core returned an invalid value")
    private fun invokeVoid(name: String, vararg arguments: Any) { invoke(name, *arguments) }
    private fun invoke(name: String, vararg arguments: Any): Any? {
        val clazz = CORE_CLASSES.firstNotNullOfOrNull { runCatching { Class.forName(it) }.getOrNull() }
            ?: error("FedMes crypto core AAR is not packaged")
        val method = clazz.methods.firstOrNull { candidate ->
            candidate.name.equals(name, ignoreCase = true) && candidate.parameterCount == arguments.size
        } ?: error("FedMes crypto core method is unavailable: $name")
        return try { method.invoke(null, *arguments) } catch (error: InvocationTargetException) {
            throw IllegalStateException(error.targetException.message ?: "FedMes crypto core failed", error.targetException)
        }
    }
    private companion object {
        val CORE_CLASSES = listOf("com.fedmes.crypto.mobile.Mobile", "com.fedmes.crypto.Mobile", "go.mobile.Mobile", "mobile.Mobile")
    }
}

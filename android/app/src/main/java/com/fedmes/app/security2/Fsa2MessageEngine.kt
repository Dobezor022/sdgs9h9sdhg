package com.fedmes.app.security2

import com.fedmes.app.cryptocore.FedMesCryptoCore
import com.fedmes.app.transport2.BlindObjectClient
import org.json.JSONObject
import java.util.Base64

/** Actual FedMes 2.0 message/event path. Legacy message crypto is migration-only. */
class Fsa2MessageEngine(private val core: FedMesCryptoCore) {
    data class SendResult(val state: JSONObject, val objectId: String)
    data class ReceiveResult(val state: JSONObject, val plaintext: ByteArray, val objectId: String)

    fun send(
        serverUrl: String,
        state: JSONObject,
        routeCapability: ByteArray,
        transportEpoch: Long,
        eventBytes: ByteArray,
    ): SendResult {
        require(routeCapability.size == 32 && eventBytes.isNotEmpty())
        val capability = raw(routeCapability)
        val padTo = paddingTarget(eventBytes.size + 4)
        val encrypted = core.security2EncryptCapsule(state, capability, transportEpoch, raw(eventBytes), padTo)
        val next = encrypted.getJSONObject("state")
        val capsule = encrypted.getJSONObject("capsule")
        val objectId = BlindObjectClient.randomObjectId()
        BlindObjectClient(serverUrl).put(capability, objectId, capsule.getInt("length_class"), raw(capsule.toString().toByteArray(Charsets.UTF_8)))
        return SendResult(next, objectId)
    }

    fun receiveOne(
        serverUrl: String,
        state: JSONObject,
        routeCapability: ByteArray,
        transportEpoch: Long,
    ): ReceiveResult? {
        require(routeCapability.size == 32)
        val capability = raw(routeCapability)
        val client = BlindObjectClient(serverUrl)
        val cell = client.pull(capability, 1).firstOrNull() ?: return null
        val encodedCapsule = Base64.getUrlDecoder().decode(cell.ciphertext)
        val capsule = try { JSONObject(encodedCapsule.toString(Charsets.UTF_8)) } finally { encodedCapsule.fill(0) }
        val result = core.security2DecryptCapsule(state, capsule, capability, transportEpoch)
        val plaintext = Base64.getUrlDecoder().decode(result.getString("plaintext"))
        // ACK only after successful authentication/decryption.
        client.ack(capability, cell.id)
        return ReceiveResult(result.getJSONObject("state"), plaintext, cell.id)
    }

    private fun paddingTarget(n: Int): Int = when {
        n <= 256 -> 256
        n <= 1024 -> 1024
        n <= 4096 -> 4096
        n <= 16384 -> 16384
        n <= 65536 -> 65536
        else -> ((n + 65535) / 65536) * 65536
    }
    private fun raw(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

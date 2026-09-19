package com.fedmes.app.transport2

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Base64

/** FedMes 2.0 opaque object transport. No chat/message semantics are sent. */
class BlindObjectClient(private val baseUrl: String) {
    data class ObjectCell(val id: String, val lengthClass: Int, val ciphertext: String)

    fun routeDigest(capability: ByteArray): String {
        require(capability.size == 32)
        val digest = MessageDigest.getInstance("SHA-256").digest(capability)
        return try { rawUrl(digest) } finally { digest.fill(0) }
    }

    fun registerRoute(sessionToken: String, routeDigest: String, generation: Long, lifetimeSeconds: Long = 86400) {
        val body = JSONObject()
            .put("version", 1)
            .put("route_digest", routeDigest)
            .put("generation", generation)
            .put("lifetime_seconds", lifetimeSeconds)
            .put("max_object_bytes", 2 * 1024 * 1024)
            .put("max_pending_objects", 512)
        val connection = request("PUT", "/api/v4/object/route", sessionToken, null, body.toString().toByteArray())
        try { if (connection.responseCode !in 200..299) error("FedMes route registration failed") } finally { connection.disconnect() }
    }

    fun put(capability: String, objectId: String, lengthClass: Int, ciphertext: String, lifetimeSeconds: Long = 259200) {
        val body = JSONObject()
            .put("version", 1).put("object_id", objectId).put("length_class", lengthClass)
            .put("ciphertext", ciphertext).put("lifetime_seconds", lifetimeSeconds)
        val connection = request("POST", "/api/v4/object", null, capability, body.toString().toByteArray())
        try { if (connection.responseCode !in 200..299) error("FedMes object transport rejected upload") } finally { connection.disconnect() }
    }

    fun pull(capability: String, limit: Int = 64): List<ObjectCell> {
        require(limit in 1..256)
        val connection = request("GET", "/api/v4/object?limit=$limit", null, capability, null)
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) error("FedMes object transport unavailable")
            val text = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val array = JSONObject(text).getJSONArray("objects")
            return buildList(array.length()) {
                for (i in 0 until array.length()) {
                    val item = array.getJSONObject(i)
                    add(ObjectCell(item.getString("object_id"), item.getInt("length_class"), item.getString("ciphertext")))
                }
            }
        } finally { connection.disconnect() }
    }

    fun ack(capability: String, objectId: String) {
        require(objectId.matches(Regex("[A-Za-z0-9_-]{20,64}")))
        val connection = request("DELETE", "/api/v4/object/$objectId", null, capability, null)
        try {
            if (connection.responseCode !in 200..299 && connection.responseCode != HttpURLConnection.HTTP_NOT_FOUND) {
                error("FedMes object acknowledgement failed")
            }
        } finally { connection.disconnect() }
    }

    private fun request(method: String, path: String, session: String?, capability: String?, body: ByteArray?): HttpURLConnection {
        require(baseUrl.startsWith("https://") || baseUrl.startsWith("http://127.0.0.1") || baseUrl.startsWith("http://localhost"))
        val c = URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = 10_000
        c.readTimeout = 30_000
        c.useCaches = false
        c.setRequestProperty("Accept", "application/json")
        c.setRequestProperty("Cache-Control", "no-store")
        if (session != null) c.setRequestProperty("Authorization", "Bearer $session")
        if (capability != null) c.setRequestProperty("X-Object-Capability", capability)
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.setFixedLengthStreamingMode(body.size)
            c.outputStream.use { it.write(body) }
            body.fill(0)
        }
        return c
    }

    companion object {
        fun rawUrl(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        fun randomObjectId(): String { val b = ByteArray(16); java.security.SecureRandom().nextBytes(b); return try { rawUrl(b) } finally { b.fill(0) } }
        fun parseObjects(json: JSONArray): List<ObjectCell> = buildList(json.length()) {
            for (i in 0 until json.length()) { val o=json.getJSONObject(i); add(ObjectCell(o.getString("object_id"),o.getInt("length_class"),o.getString("ciphertext"))) }
        }
    }
}

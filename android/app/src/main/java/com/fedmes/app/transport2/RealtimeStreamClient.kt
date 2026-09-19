package com.fedmes.app.transport2

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Full-duplex FedMes realtime transport using two independent HTTPS streams.
 * Payloads are already FSA2-encrypted media packets; this class never sees codec
 * metadata or plaintext. Queues are deliberately bounded by the server.
 */
class RealtimeStreamClient(private val baseUrl: String) {
    private fun endpoint(): URL {
        require(baseUrl.startsWith("https://") || baseUrl.startsWith("http://127.0.0.1") || baseUrl.startsWith("http://localhost"))
        return URL(baseUrl.trimEnd('/') + "/api/v4/stream")
    }

    class Uplink internal constructor(
        private val connection: HttpURLConnection,
        private val output: DataOutputStream,
    ) : Closeable {
        @Synchronized fun send(frame: ByteArray) {
            require(frame.isNotEmpty() && frame.size <= 256 * 1024)
            output.writeInt(frame.size)
            output.write(frame)
            output.flush()
        }
        override fun close() {
            runCatching { output.close() }
            runCatching { connection.inputStream.close() }
            connection.disconnect()
        }
    }

    fun openUplink(capability: String): Uplink {
        val c = endpoint().openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.doOutput = true
        c.useCaches = false
        c.connectTimeout = 10_000
        c.readTimeout = 0
        c.setChunkedStreamingMode(16 * 1024)
        c.setRequestProperty("Content-Type", "application/octet-stream")
        c.setRequestProperty("Cache-Control", "no-store")
        c.setRequestProperty("X-Object-Capability", capability)
        val out = DataOutputStream(BufferedOutputStream(c.outputStream, 32 * 1024))
        return Uplink(c, out)
    }

    suspend fun receiveLoop(capability: String, onFrame: suspend (ByteArray) -> Unit) = withContext(Dispatchers.IO) {
        val c = endpoint().openConnection() as HttpURLConnection
        c.requestMethod = "GET"
        c.useCaches = false
        c.connectTimeout = 10_000
        c.readTimeout = 0
        c.setRequestProperty("Accept", "application/octet-stream")
        c.setRequestProperty("Cache-Control", "no-store")
        c.setRequestProperty("X-Object-Capability", capability)
        try {
            if (c.responseCode != HttpURLConnection.HTTP_OK) error("FedMes realtime route unavailable")
            DataInputStream(BufferedInputStream(c.inputStream, 64 * 1024)).use { input ->
                while (currentCoroutineContext().isActive) {
                    val n = input.readInt()
                    require(n in 1..256 * 1024)
                    val frame = ByteArray(n)
                    input.readFully(frame)
                    try { onFrame(frame) } finally { frame.fill(0) }
                }
            }
        } finally { c.disconnect() }
    }
}

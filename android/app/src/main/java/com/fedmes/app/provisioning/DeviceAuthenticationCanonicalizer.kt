package com.fedmes.app.provisioning

object DeviceAuthenticationCanonicalizer {
    const val SESSION_REFRESH_PURPOSE = "session.refresh"

    fun bootstrapCommit(
        serverUrl: String,
        username: String,
        deviceId: String,
        sessionId: String,
    ): ByteArray {
        val values = listOf(serverUrl, username, deviceId, sessionId)
        require(values.all { it.isNotEmpty() && '\n' !in it && '\r' !in it }) {
            "Bootstrap commit context is invalid"
        }
        return buildString {
            append(BOOTSTRAP_CONTEXT_HEADER)
            append('\n')
            append(serverUrl.trimEnd('/'))
            append('\n')
            append(username)
            append('\n')
            append(deviceId)
            append('\n')
            append(sessionId)
        }.toByteArray(Charsets.UTF_8)
    }

    fun sessionRefresh(
        audience: String,
        username: String,
        deviceId: String,
        challengeId: String,
        nonce: String,
    ): ByteArray {
        val values = listOf(audience, username, deviceId, challengeId, nonce)
        require(values.all { it.isNotEmpty() && '\n' !in it && '\r' !in it }) {
            "Device authentication context is invalid"
        }
        return buildString {
            append(CONTEXT_HEADER)
            append('\n')
            append(audience)
            append('\n')
            append(username)
            append('\n')
            append(deviceId)
            append('\n')
            append(challengeId)
            append('\n')
            append(SESSION_REFRESH_PURPOSE)
            append('\n')
            append(nonce)
        }.toByteArray(Charsets.UTF_8)
    }

    private const val CONTEXT_HEADER = "fedmes-device-auth-v1"
    private const val BOOTSTRAP_CONTEXT_HEADER = "fedmes-bootstrap-commit-v1"
}

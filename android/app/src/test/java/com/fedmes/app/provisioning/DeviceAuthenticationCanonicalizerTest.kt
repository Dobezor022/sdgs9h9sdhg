package com.fedmes.app.provisioning

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DeviceAuthenticationCanonicalizerTest {
    @Test
    fun `session refresh payload is byte exact without trailing newline`() {
        val payload = DeviceAuthenticationCanonicalizer.sessionRefresh(
            audience = "family.example:8443",
            username = "grisha",
            deviceId = "128d9a52-5b9a-4f4f-b441-ae2bfd68b174",
            challengeId = "31c5b50c-8d4c-4a16-8731-42ccac4a2360",
            nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        val text = payload.toString(Charsets.UTF_8)

        assertEquals(
            "fedmes-device-auth-v1\n" +
                "family.example:8443\n" +
                "grisha\n" +
                "128d9a52-5b9a-4f4f-b441-ae2bfd68b174\n" +
                "31c5b50c-8d4c-4a16-8731-42ccac4a2360\n" +
                "session.refresh\n" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            text,
        )
        assertFalse(text.endsWith('\n'))
    }
}

package com.fedmes.app.provisioning

import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

object ProtocolTime {
    private val rfc3339Pattern = Regex(
        pattern = """^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$""",
    )

    fun parseRfc3339(value: String): Long? {
        val match = rfc3339Pattern.matchEntire(value) ?: return null
        val base = match.groupValues[1]
        val fraction = match.groupValues[2].padEnd(length = 3, padChar = '0').take(3)
        val offset = match.groupValues[3]
        val normalized = "$base.${fraction.ifEmpty { "000" }}$offset"
        val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US).apply {
            isLenient = false
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val position = ParsePosition(0)
        val parsed = formatter.parse(normalized, position) ?: return null
        return parsed.time.takeIf { position.index == normalized.length }
    }
}

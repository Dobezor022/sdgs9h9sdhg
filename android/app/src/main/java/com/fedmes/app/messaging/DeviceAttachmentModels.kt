package com.fedmes.app.messaging

enum class DeviceAttachmentKind {
    PHOTO,
    VIDEO,
    FILE,
}

enum class AttachmentQuality {
    SD,
    HD,
    ORIGINAL,
}

data class DeviceAttachmentItem(
    val stableId: String,
    val uri: String,
    val name: String,
    val mimeType: String,
    val size: Long,
    val modifiedAtSeconds: Long,
    val durationMillis: Long?,
    val kind: DeviceAttachmentKind,
    val temporary: Boolean = false,
)

data class DrawingPoint(
    val xFraction: Float,
    val yFraction: Float,
)

data class DrawingStroke(
    val points: List<DrawingPoint>,
    val colorArgb: Int,
    val widthFraction: Float = 0.012f,
)

data class AttachmentSelection(
    val item: DeviceAttachmentItem,
    val caption: String,
    val rotationDegrees: Int = 0,
    val quality: AttachmentQuality = AttachmentQuality.SD,
    val spoiler: Boolean = false,
    val drawingStrokes: List<DrawingStroke> = emptyList(),
) {
    val sendAsFile: Boolean get() = quality == AttachmentQuality.ORIGINAL
    val highQuality: Boolean get() = quality == AttachmentQuality.HD
}

data class PreparedLocalAttachment(
    val name: String,
    val mimeType: String,
    val bytes: ByteArray,
    val caption: String,
    val width: Int? = null,
    val height: Int? = null,
    val durationMillis: Long? = null,
    val previewBytes: ByteArray? = null,
    val waveform: List<Int> = emptyList(),
    val sendAsFile: Boolean = false,
    val spoiler: Boolean = false,
)

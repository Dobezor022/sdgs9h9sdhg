package com.fedmes.app.calling

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Process
import android.util.Base64
import com.fedmes.app.cryptocore.FedMesCryptoCore
import com.fedmes.app.messaging.CallDescriptor
import com.fedmes.app.messaging.CallEvent
import com.fedmes.app.messaging.CallMode
import com.fedmes.app.messaging.DecryptedMessage
import com.fedmes.app.messaging.MessageKind
import com.fedmes.app.messaging.MessagingRepository
import com.fedmes.app.security.SessionStore
import com.fedmes.app.transport2.BlindObjectClient
import com.fedmes.app.transport2.RealtimeStreamClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * FedMes native call state. The VPS sees only a random capability and FSA2 ciphertext frames.
 * Signalling is carried inside the normal E2EE message ratchet, so the call secret never exists
 * as plaintext server metadata.
 */
enum class CallPhase { INCOMING, OUTGOING, CONNECTING, ACTIVE, RECONNECTING, ENDED, FAILED }

data class CallUiState(
    val chatId: String,
    val peerTitle: String,
    val descriptor: CallDescriptor,
    val phase: CallPhase,
    val muted: Boolean = false,
    val cameraEnabled: Boolean = false,
    val speakerEnabled: Boolean = true,
    val remoteVideoJpeg: ByteArray? = null,
    val remoteVideoFrame: Long = 0L,
    val startedAtEpochMillis: Long? = null,
    val error: String? = null,
)

class FedMesCallCoordinator(
    context: Context,
    private val sessionStore: SessionStore,
    private val messagingRepository: MessagingRepository,
    private val crypto: FedMesCryptoCore,
) {
    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutableState = MutableStateFlow<CallUiState?>(null)
    val state: StateFlow<CallUiState?> = mutableState.asStateFlow()
    private var session: FedMesRealtimeCallSession? = null
    private var activeChatId: String? = null

    suspend fun startOutgoing(chatId: String, peerTitle: String, mode: CallMode) = withContext(Dispatchers.IO) {
        check(session == null) { "Звонок уже активен" }
        val account = sessionStore.loadAccount() ?: error("Аккаунт не найден")
        val descriptor = CallDescriptorFactory.create(account.username, mode)
        val capabilityBytes = rawUrlDecode(descriptor.capabilityBase64Url)
        val blind = BlindObjectClient(account.serverUrl)
        try {
            blind.registerRoute(
                sessionToken = account.sessionToken,
                routeDigest = blind.routeDigest(capabilityBytes),
                generation = descriptor.generation,
                lifetimeSeconds = CALL_ROUTE_LIFETIME_SECONDS,
            )
        } finally {
            capabilityBytes.fill(0)
        }
        runCatching { messagingRepository.prewarmChat(chatId) }
        val sent = messagingRepository.sendCallSignal(chatId, descriptor)
        activeChatId = chatId
        mutableState.value = CallUiState(chatId, peerTitle, descriptor, CallPhase.OUTGOING, cameraEnabled = mode != CallMode.AUDIO)
        startSession(account.serverUrl, account.deviceId, descriptor, outgoing = true)
        sent
    }

    suspend fun acceptIncoming() = withContext(Dispatchers.IO) {
        val incoming = mutableState.value ?: return@withContext
        if (incoming.phase != CallPhase.INCOMING) return@withContext
        if (incoming.descriptor.expiresAtEpochMillis <= System.currentTimeMillis()) {
            mutableState.value = incoming.copy(phase = CallPhase.FAILED, error = "Приглашение на звонок истекло")
            return@withContext
        }
        val account = sessionStore.loadAccount() ?: error("Аккаунт не найден")
        activeChatId = incoming.chatId
        mutableState.value = incoming.copy(
            phase = CallPhase.CONNECTING,
            cameraEnabled = incoming.descriptor.mode != CallMode.AUDIO,
        )
        startSession(account.serverUrl, account.deviceId, incoming.descriptor, outgoing = false)
        session?.sendControl("join")
        mutableState.value = mutableState.value?.copy(phase = CallPhase.ACTIVE, startedAtEpochMillis = System.currentTimeMillis())
    }

    suspend fun declineIncoming() = withContext(Dispatchers.IO) {
        val incoming = mutableState.value ?: return@withContext
        if (incoming.phase != CallPhase.INCOMING) return@withContext
        val declined = incoming.descriptor.copy(event = CallEvent.DECLINED)
        runCatching { messagingRepository.sendCallSignal(incoming.chatId, declined) }
        mutableState.value = null
        activeChatId = null
    }

    suspend fun endCall() = withContext(Dispatchers.IO) {
        val current = mutableState.value ?: return@withContext
        runCatching { session?.sendControl("leave") }
        runCatching { messagingRepository.sendCallSignal(current.chatId, current.descriptor.copy(event = CallEvent.ENDED)) }
        closeSession()
        mutableState.value = current.copy(phase = CallPhase.ENDED)
        delay(250)
        mutableState.value = null
        activeChatId = null
    }

    fun setMuted(muted: Boolean) {
        session?.muted = muted
        mutableState.value = mutableState.value?.copy(muted = muted)
        scope.launch { runCatching { session?.sendControl(if (muted) "mute" else "unmute") } }
    }

    fun setSpeaker(enabled: Boolean) {
        session?.setSpeaker(enabled)
        mutableState.value = mutableState.value?.copy(speakerEnabled = enabled)
    }

    fun setCameraEnabled(enabled: Boolean) {
        session?.cameraEnabled = enabled
        mutableState.value = mutableState.value?.copy(cameraEnabled = enabled)
        scope.launch { runCatching { session?.sendControl(if (enabled) "camera_on" else "camera_off") } }
    }

    fun onMediaPermissionsGranted() {
        session?.ensureAudio()
    }

    fun sendVideoFrame(jpeg: ByteArray) {
        if (jpeg.isEmpty() || jpeg.size > MAX_VIDEO_JPEG_BYTES) return
        session?.sendVideoFrame(jpeg)
    }

    /** Called whenever an E2EE message page changes. Handles invite/end without extra server signalling. */
    fun observeMessages(chatId: String, peerTitle: String, currentUsername: String, messages: List<DecryptedMessage>) {
        val calls = messages.asSequence()
            .filter { it.content.kind == MessageKind.CALL && it.content.call != null }
            .map { it to requireNotNull(it.content.call) }
            .toList()
        if (calls.isEmpty()) return
        val latestById = calls.groupBy { it.second.callId }.mapValues { (_, values) -> values.maxBy { it.first.sequence } }

        val active = mutableState.value
        if (active != null) {
            val latest = latestById[active.descriptor.callId]?.second
            if (latest != null && latest.event in setOf(CallEvent.ENDED, CallEvent.DECLINED, CallEvent.NO_ANSWER, CallEvent.FAILED)) {
                scope.launch {
                    closeSession()
                    mutableState.value = active.copy(
                        phase = if (latest.event == CallEvent.FAILED) CallPhase.FAILED else CallPhase.ENDED,
                        error = if (latest.event == CallEvent.FAILED) "Звонок завершён с ошибкой" else null,
                    )
                    delay(400)
                    mutableState.value = null
                    activeChatId = null
                }
            }
            return
        }

        val incoming = latestById.values
            .filter { (message, descriptor) ->
                descriptor.event == CallEvent.INVITE &&
                    descriptor.initiatorUsername != currentUsername &&
                    message.senderUsername != currentUsername &&
                    descriptor.expiresAtEpochMillis > System.currentTimeMillis()
            }
            .maxByOrNull { it.first.sequence }
            ?: return
        mutableState.value = CallUiState(
            chatId = chatId,
            peerTitle = peerTitle,
            descriptor = incoming.second,
            phase = CallPhase.INCOMING,
            cameraEnabled = false,
        )
    }

    private suspend fun startSession(serverUrl: String, deviceId: String, descriptor: CallDescriptor, outgoing: Boolean) {
        closeSession()
        val created = FedMesRealtimeCallSession(
            context = appContext,
            serverUrl = serverUrl,
            deviceId = deviceId,
            descriptor = descriptor,
            crypto = crypto,
            onPeerJoined = {
                mutableState.value = mutableState.value?.copy(
                    phase = CallPhase.ACTIVE,
                    startedAtEpochMillis = mutableState.value?.startedAtEpochMillis ?: System.currentTimeMillis(),
                )
            },
            onPeerLeft = {
                scope.launch {
                    mutableState.value = mutableState.value?.copy(phase = CallPhase.ENDED)
                    closeSession()
                    delay(400)
                    mutableState.value = null
                    activeChatId = null
                }
            },
            onRemoteVideo = { jpeg ->
                val current = mutableState.value
                if (current != null) {
                    mutableState.value = current.copy(
                        remoteVideoJpeg = jpeg,
                        remoteVideoFrame = current.remoteVideoFrame + 1,
                    )
                } else {
                    jpeg.fill(0)
                }
            },
            onFailure = { error ->
                mutableState.value = mutableState.value?.copy(phase = CallPhase.RECONNECTING, error = error.message)
            },
        )
        session = created
        created.start()
        if (outgoing) created.sendControl("hello")
    }

    private suspend fun closeSession() {
        val previous = session
        session = null
        previous?.close()
    }

    fun close() {
        scope.launch { closeSession() }
        scope.cancel()
    }

    companion object {
        const val MAX_VIDEO_JPEG_BYTES = 150 * 1024
        private const val CALL_ROUTE_LIFETIME_SECONDS = 6 * 60 * 60L

        private fun rawUrlDecode(value: String): ByteArray = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}

private object CallDescriptorFactory {
    private val random = SecureRandom()
    fun create(username: String, mode: CallMode): CallDescriptor {
        val now = System.currentTimeMillis()
        val capability = ByteArray(32).also(random::nextBytes)
        val shared = ByteArray(32).also(random::nextBytes)
        val route = ByteArray(32).also(random::nextBytes)
        return try {
            CallDescriptor(
                callId = UUID.randomUUID().toString(),
                mode = mode,
                event = CallEvent.INVITE,
                capabilityBase64Url = rawUrl(capability),
                sharedSecretBase64Url = rawUrl(shared),
                routeBase64Url = rawUrl(route),
                generation = now.coerceAtLeast(1L),
                createdAtEpochMillis = now,
                expiresAtEpochMillis = now + 2 * 60 * 1000L,
                initiatorUsername = username,
            )
        } finally {
            capability.fill(0); shared.fill(0); route.fill(0)
        }
    }
    private fun rawUrl(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}

private class FedMesRealtimeCallSession(
    private val context: Context,
    serverUrl: String,
    private val deviceId: String,
    private val descriptor: CallDescriptor,
    private val crypto: FedMesCryptoCore,
    private val onPeerJoined: () -> Unit,
    private val onPeerLeft: () -> Unit,
    private val onRemoteVideo: (ByteArray) -> Unit,
    private val onFailure: (Throwable) -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stream = RealtimeStreamClient(serverUrl)
    private var uplink: RealtimeStreamClient.Uplink? = null
    private var receiveJob: Job? = null
    private var audioJob: Job? = null
    private var recorder: AudioRecord? = null
    private var player: AudioTrack? = null
    private val sequence = ConcurrentHashMap<Int, AtomicLong>()
    private val replayHighWater = ConcurrentHashMap<String, Long>()
    private val callRoot: String
    private val route = descriptor.routeBase64Url
    private val keys: Map<Int, String>
    @Volatile var muted: Boolean = false
    @Volatile var cameraEnabled: Boolean = descriptor.mode != CallMode.AUDIO

    init {
        val transcript = MessageDigest.getInstance("SHA-256")
            .digest("${descriptor.callId}|${descriptor.generation}|${descriptor.initiatorUsername}".toByteArray(Charsets.UTF_8))
        val transcriptB64 = Base64.encodeToString(transcript, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        transcript.fill(0)
        callRoot = crypto.security2NewCallRoot(descriptor.sharedSecretBase64Url, transcriptB64)
        keys = mapOf(
            DOMAIN_AUDIO to crypto.security2MediaEpochKey(callRoot, DOMAIN_AUDIO, 0, EPOCH),
            DOMAIN_VIDEO to crypto.security2MediaEpochKey(callRoot, DOMAIN_VIDEO, 0, EPOCH),
            DOMAIN_CONTROL to crypto.security2MediaEpochKey(callRoot, DOMAIN_CONTROL, 0, EPOCH),
        )
    }

    @SuppressLint("MissingPermission")
    suspend fun start() = withContext(Dispatchers.IO) {
        uplink = stream.openUplink(descriptor.capabilityBase64Url)
        receiveJob = scope.launch {
            reconnectingReceiveLoop()
        }
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            startAudio()
        }
    }

    private suspend fun reconnectingReceiveLoop() {
        var backoff = 250L
        while (scope.isActive) {
            try {
                stream.receiveLoop(descriptor.capabilityBase64Url, ::handleFrame)
                if (scope.isActive) throw IllegalStateException("Realtime stream closed")
            } catch (error: CancellationException) {
                throw error
            } catch (error: Throwable) {
                onFailure(error)
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(4_000L)
            }
        }
    }

    suspend fun sendControl(kind: String) {
        val json = JSONObject().put("sender", deviceId).put("kind", kind).put("ts", System.currentTimeMillis())
        sendEncrypted(DOMAIN_CONTROL, json.toString().toByteArray(Charsets.UTF_8))
    }

    fun sendVideoFrame(jpeg: ByteArray) {
        if (!cameraEnabled || jpeg.isEmpty() || jpeg.size > FedMesCallCoordinator.MAX_VIDEO_JPEG_BYTES) return
        val copy = jpeg.copyOf()
        scope.launch {
            try {
                val body = JSONObject()
                    .put("sender", deviceId)
                    .put("ts", System.currentTimeMillis())
                    .put("jpeg", rawUrl(copy))
                    .toString().toByteArray(Charsets.UTF_8)
                sendEncrypted(DOMAIN_VIDEO, body)
                body.fill(0)
            } finally { copy.fill(0) }
        }
    }

    private suspend fun sendEncrypted(domain: Int, plaintext: ByteArray) = withContext(Dispatchers.IO) {
        val key = keys.getValue(domain)
        val seq = sequence.computeIfAbsent(domain) { AtomicLong(0) }.incrementAndGet()
        val plainB64 = rawUrl(plaintext)
        val packet = crypto.security2EncryptMedia(key, route, EPOCH, seq, plainB64)
        val frame = JSONObject().put("domain", domain).put("packet", packet).toString().toByteArray(Charsets.UTF_8)
        try { uplink?.send(frame) ?: error("Call uplink is closed") } finally { frame.fill(0) }
    }

    private suspend fun handleFrame(frame: ByteArray) {
        val root = JSONObject(frame.toString(Charsets.UTF_8))
        val domain = root.getInt("domain")
        val packet = root.getJSONObject("packet")
        val key = keys[domain] ?: return
        val plainB64 = runCatching { crypto.security2DecryptMedia(key, route, packet) }.getOrNull() ?: return
        val plain = rawUrlDecode(plainB64)
        try {
            val body = JSONObject(plain.toString(Charsets.UTF_8))
            val sender = body.optString("sender")
            if (sender.isBlank() || sender == deviceId) return
            val seq = packet.optLong("sequence", -1L)
            val replayKey = "$sender:$domain"
            val previous = replayHighWater[replayKey] ?: -1L
            if (seq <= previous) return
            replayHighWater[replayKey] = seq
            when (domain) {
                DOMAIN_CONTROL -> when (body.optString("kind")) {
                    "hello", "join" -> onPeerJoined()
                    "leave" -> onPeerLeft()
                }
                DOMAIN_AUDIO -> {
                    val pcm = rawUrlDecode(body.getString("pcm"))
                    try { player?.write(pcm, 0, pcm.size, AudioTrack.WRITE_BLOCKING) } finally { pcm.fill(0) }
                }
                DOMAIN_VIDEO -> {
                    val jpeg = rawUrlDecode(body.getString("jpeg"))
                    if (jpeg.size <= FedMesCallCoordinator.MAX_VIDEO_JPEG_BYTES) onRemoteVideo(jpeg) else jpeg.fill(0)
                }
            }
        } finally { plain.fill(0) }
    }

    @SuppressLint("MissingPermission")
    fun ensureAudio() {
        if (recorder != null || context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) return
        startAudio()
    }

    @SuppressLint("MissingPermission")
    private fun startAudio() {
        val format = AudioFormat.Builder()
            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
            .setSampleRate(AUDIO_SAMPLE_RATE)
            .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
            .build()
        val outputFormat = AudioFormat.Builder()
            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
            .setSampleRate(AUDIO_SAMPLE_RATE)
            .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
            .build()
        val recordBuffer = maxOf(AudioRecord.getMinBufferSize(AUDIO_SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT), AUDIO_FRAME_BYTES * 8)
        val trackBuffer = maxOf(AudioTrack.getMinBufferSize(AUDIO_SAMPLE_RATE, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT), AUDIO_FRAME_BYTES * 16)
        recorder = AudioRecord.Builder()
            .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            .setAudioFormat(format)
            .setBufferSizeInBytes(recordBuffer)
            .build()
        player = AudioTrack.Builder()
            .setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
            .setAudioFormat(outputFormat)
            .setBufferSizeInBytes(trackBuffer)
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build().also { it.play() }
        setSpeaker(true)
        recorder?.startRecording()
        audioJob = scope.launch {
            Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO)
            val buffer = ByteArray(AUDIO_FRAME_BYTES)
            try {
                while (isActive) {
                    val n = recorder?.read(buffer, 0, buffer.size, AudioRecord.READ_BLOCKING) ?: break
                    if (n > 0 && !muted) {
                        val pcm = buffer.copyOf(n)
                        try {
                            val body = JSONObject().put("sender", deviceId).put("ts", System.currentTimeMillis()).put("pcm", rawUrl(pcm))
                                .toString().toByteArray(Charsets.UTF_8)
                            sendEncrypted(DOMAIN_AUDIO, body)
                            body.fill(0)
                        } finally { pcm.fill(0) }
                    }
                }
            } finally { buffer.fill(0) }
        }
    }

    @Suppress("DEPRECATION")
    fun setSpeaker(enabled: Boolean) {
        val audio = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        audio.mode = AudioManager.MODE_IN_COMMUNICATION
        audio.isSpeakerphoneOn = enabled
    }

    suspend fun close() = withContext(Dispatchers.IO) {
        audioJob?.cancel(); audioJob = null
        receiveJob?.cancel(); receiveJob = null
        runCatching { recorder?.stop() }; recorder?.release(); recorder = null
        runCatching { player?.stop() }; player?.release(); player = null
        runCatching { uplink?.close() }; uplink = null
        scope.cancel()
    }

    companion object {
        private const val EPOCH = 1L
        private const val DOMAIN_AUDIO = 1
        private const val DOMAIN_VIDEO = 2
        private const val DOMAIN_CONTROL = 4
        private const val AUDIO_SAMPLE_RATE = 16_000
        private const val AUDIO_FRAME_MILLIS = 20
        private const val AUDIO_FRAME_BYTES = AUDIO_SAMPLE_RATE * AUDIO_FRAME_MILLIS / 1000 * 2
        private fun rawUrl(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        private fun rawUrlDecode(value: String): ByteArray = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}

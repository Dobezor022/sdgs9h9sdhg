using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FedMes.Desktop.Core.CryptoCore;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Core.Transport2;

namespace FedMes.Desktop.Core.Calling;

/// <summary>
/// FSA2 encrypted realtime transport for FedMes calls. The relay only sees the opaque
/// capability and encrypted frames. Audio/video encoding and device capture live in the UI app.
/// </summary>
public sealed class FedMesRealtimeCallTransport : IAsyncDisposable
{
    public const int AudioDomain = 1;
    public const int VideoDomain = 2;
    public const int ControlDomain = 4;
    public const int MaxVideoJpegBytes = 150 * 1024;
    private const long Epoch = 1;

    private static readonly JsonSerializerOptions WireJson = new() {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };
    private readonly RealtimeStreamClient _stream = new();
    private readonly FedMesSecurity2Client _crypto;
    private readonly string _deviceId;
    private readonly CallDescriptor _descriptor;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ConcurrentDictionary<int, long> _sequences = new();
    private readonly ConcurrentDictionary<string, ulong> _replayHighWater = new(StringComparer.Ordinal);
    private readonly Dictionary<int, string> _keys = [];
    private Task? _receiveTask;
    private int _started;

    public FedMesRealtimeCallTransport(string deviceId, CallDescriptor descriptor, FedMesSecurity2Client crypto)
    {
        _deviceId = string.IsNullOrWhiteSpace(deviceId) ? throw new ArgumentException("device id is required", nameof(deviceId)) : deviceId;
        _descriptor = descriptor ?? throw new ArgumentNullException(nameof(descriptor));
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
    }

    public event EventHandler? PeerJoined;
    public event EventHandler? PeerLeft;
    public event Action<ReadOnlyMemory<byte>>? AudioFrameReceived;
    public event Action<ReadOnlyMemory<byte>>? VideoFrameReceived;
    public event Action<Exception>? TransportFaulted;

    public async Task StartAsync(Uri server, CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) return;
        string transcript = CallCryptoTranscript(_descriptor);
        string callRoot = await _crypto.NewCallRootAsync(_descriptor.SharedSecretBase64Url, transcript, cancellationToken).ConfigureAwait(false);
        try
        {
            _keys[AudioDomain] = await _crypto.MediaEpochKeyAsync(callRoot, AudioDomain, 0, Epoch, string.Empty, cancellationToken).ConfigureAwait(false);
            _keys[VideoDomain] = await _crypto.MediaEpochKeyAsync(callRoot, VideoDomain, 0, Epoch, string.Empty, cancellationToken).ConfigureAwait(false);
            _keys[ControlDomain] = await _crypto.MediaEpochKeyAsync(callRoot, ControlDomain, 0, Epoch, string.Empty, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // The worker returns base64 text; managed strings cannot be zeroed. Do not persist them.
            callRoot = string.Empty;
        }

        await _stream.OpenUplinkAsync(server, _descriptor.CapabilityBase64Url, cancellationToken).ConfigureAwait(false);
        CancellationToken linkedToken = _lifetime.Token;
        _receiveTask = Task.Run(() => ReceiveWithReconnectAsync(server, linkedToken), linkedToken);
    }

    public Task SendHelloAsync(CancellationToken ct) => SendControlAsync("hello", ct);
    public Task SendJoinAsync(CancellationToken ct) => SendControlAsync("join", ct);
    public Task SendLeaveAsync(CancellationToken ct) => SendControlAsync("leave", ct);

    public async Task SendControlAsync(string kind, CancellationToken ct)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new ControlPayload(_deviceId, kind, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), WireJson);
        try { await SendEncryptedAsync(ControlDomain, bytes, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public async Task SendAudioAsync(ReadOnlyMemory<byte> pcm16Mono, CancellationToken ct)
    {
        if (pcm16Mono.IsEmpty) return;
        string encoded = Base64Url(pcm16Mono.Span);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new AudioPayload(_deviceId, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), encoded), WireJson);
        try { await SendEncryptedAsync(AudioDomain, bytes, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public async Task SendVideoJpegAsync(ReadOnlyMemory<byte> jpeg, CancellationToken ct)
    {
        if (jpeg.IsEmpty || jpeg.Length > MaxVideoJpegBytes) return;
        string encoded = Base64Url(jpeg.Span);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new VideoPayload(_deviceId, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), encoded), WireJson);
        try { await SendEncryptedAsync(VideoDomain, bytes, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task SendEncryptedAsync(int domain, ReadOnlyMemory<byte> plaintext, CancellationToken ct)
    {
        if (!_keys.TryGetValue(domain, out string? key)) throw new InvalidOperationException("Call transport is not started.");
        long sequence = _sequences.AddOrUpdate(domain, 1, static (_, previous) => checked(previous + 1));
        string plain = Base64Url(plaintext.Span);
        S2MediaPacket packet = await _crypto.EncryptMediaAsync(key, _descriptor.RouteBase64Url, Epoch, sequence, plain, ct).ConfigureAwait(false);
        byte[] frame = JsonSerializer.SerializeToUtf8Bytes(new WireFrame(domain, packet), WireJson);
        try { await _stream.SendFrameAsync(frame, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(frame); }
    }

    private async Task ReceiveWithReconnectAsync(Uri server, CancellationToken ct)
    {
        int delayMs = 250;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _stream.ReceiveLoopAsync(server, _descriptor.CapabilityBase64Url, frame => HandleFrameAsync(frame, ct), ct).ConfigureAwait(false);
                if (!ct.IsCancellationRequested) throw new IOException("FedMes call stream closed.");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error) when (error is HttpRequestException or IOException or JsonException or CryptographicException or InvalidOperationException)
            {
                TransportFaulted?.Invoke(error);
                try { await Task.Delay(delayMs, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                delayMs = Math.Min(delayMs * 2, 4000);
            }
        }
    }

    private async ValueTask HandleFrameAsync(ReadOnlyMemory<byte> frame, CancellationToken ct)
    {
        WireFrame? wire;
        try { wire = JsonSerializer.Deserialize<WireFrame>(frame.Span, WireJson); }
        catch (JsonException) { return; }
        if (wire is null || !_keys.TryGetValue(wire.Domain, out string? key)) return;

        string plaintextBase64;
        try { plaintextBase64 = await _crypto.DecryptMediaAsync(key, _descriptor.RouteBase64Url, wire.Packet, ct).ConfigureAwait(false); }
        catch (Exception error) when (error is CryptographicException or InvalidOperationException or IOException) { return; }

        byte[] plaintext;
        try { plaintext = FromBase64Url(plaintextBase64); }
        catch (FormatException) { return; }
        try
        {
            using JsonDocument document = JsonDocument.Parse(plaintext);
            JsonElement root = document.RootElement;
            string sender = root.TryGetProperty("sender", out JsonElement senderNode) ? senderNode.GetString() ?? string.Empty : string.Empty;
            if (sender.Length == 0 || string.Equals(sender, _deviceId, StringComparison.Ordinal)) return;

            string replayKey = sender + ":" + wire.Domain.ToString(System.Globalization.CultureInfo.InvariantCulture);
            ulong previous = _replayHighWater.GetOrAdd(replayKey, 0);
            if (wire.Packet.Sequence <= previous) return;
            _replayHighWater[replayKey] = wire.Packet.Sequence;

            switch (wire.Domain)
            {
                case ControlDomain:
                    string kind = root.TryGetProperty("kind", out JsonElement kindNode) ? kindNode.GetString() ?? string.Empty : string.Empty;
                    if (kind is "hello" or "join") PeerJoined?.Invoke(this, EventArgs.Empty);
                    else if (kind == "leave") PeerLeft?.Invoke(this, EventArgs.Empty);
                    break;
                case AudioDomain:
                    if (root.TryGetProperty("pcm", out JsonElement pcmNode) && pcmNode.GetString() is string pcmText)
                    {
                        byte[] pcm = FromBase64Url(pcmText);
                        try { AudioFrameReceived?.Invoke(pcm); }
                        finally { CryptographicOperations.ZeroMemory(pcm); }
                    }
                    break;
                case VideoDomain:
                    if (root.TryGetProperty("jpeg", out JsonElement jpegNode) && jpegNode.GetString() is string jpegText)
                    {
                        byte[] jpeg = FromBase64Url(jpegText);
                        if (jpeg.Length <= MaxVideoJpegBytes) VideoFrameReceived?.Invoke(jpeg);
                        CryptographicOperations.ZeroMemory(jpeg);
                    }
                    break;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_lifetime.IsCancellationRequested) _lifetime.Cancel();
        if (_receiveTask is not null)
        {
            try { await _receiveTask.ConfigureAwait(false); } catch { }
            _receiveTask = null;
        }
        await _stream.DisposeAsync().ConfigureAwait(false);
        _lifetime.Dispose();
        _keys.Clear();
    }

    public static CallDescriptor CreateDescriptor(string initiatorUsername, CallMode mode)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        byte[] capability = RandomNumberGenerator.GetBytes(32);
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] route = RandomNumberGenerator.GetBytes(32);
        try
        {
            return new CallDescriptor(
                Guid.NewGuid().ToString(),
                mode,
                CallEvent.Invite,
                Base64Url(capability),
                Base64Url(secret),
                Base64Url(route),
                now.ToUnixTimeMilliseconds(),
                now,
                now.AddMinutes(15),
                initiatorUsername);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(capability);
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(route);
        }
    }

    private static string CallCryptoTranscript(CallDescriptor descriptor)
    {
        byte[] source = Encoding.UTF8.GetBytes($"{descriptor.CallId}|{descriptor.Generation}|{descriptor.InitiatorUsername}");
        byte[] digest = SHA256.HashData(source);
        CryptographicOperations.ZeroMemory(source);
        try { return Base64Url(digest); }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }

    public static byte[] CapabilityBytes(CallDescriptor descriptor) => FromBase64Url(descriptor.CapabilityBase64Url);
    private static string Base64Url(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] FromBase64Url(string value)
    {
        string normalized = value.Replace('-', '+').Replace('_', '/');
        normalized += normalized.Length % 4 switch { 2 => "==", 3 => "=", _ => string.Empty };
        return Convert.FromBase64String(normalized);
    }

    private sealed record WireFrame(int Domain, S2MediaPacket Packet);
    private sealed record ControlPayload(string Sender, string Kind, long Ts);
    private sealed record AudioPayload(string Sender, long Ts, string Pcm);
    private sealed record VideoPayload(string Sender, long Ts, string Jpeg);
}

public sealed record DesktopCallSession(CallDescriptor Descriptor, FedMesRealtimeCallTransport Transport);

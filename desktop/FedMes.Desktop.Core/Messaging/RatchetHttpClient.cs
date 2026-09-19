using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Core.Messaging;

public sealed class RatchetHttpClient : IDisposable
{
    public const int ProtocolVersion = 4;
    private const int MaximumResponseBytes = 4 * 1024 * 1024;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ServerEndpointMode _endpointMode;

    public RatchetHttpClient(HttpClient? httpClient = null, ServerEndpointMode endpointMode = ServerEndpointMode.Production)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(45) };
        _ownsHttp = httpClient is null;
        _endpointMode = endpointMode;
    }

    public async Task PutBundleAsync(
        DesktopAccount account,
        int bundleVersion,
        string curve25519IdentityKey,
        string ed25519IdentityKey,
        byte[] signedPayload,
        byte[] signature,
        IReadOnlyList<OneTimeKey> oneTimeKeys,
        CancellationToken cancellationToken)
    {
        await RequestAsync<JsonElement>(account, HttpMethod.Put, "/api/v3/crypto/ratchet/bundle", new
        {
            version = ProtocolVersion,
            bundle_version = bundleVersion,
            curve25519_identity_key = curve25519IdentityKey,
            ed25519_identity_key = ed25519IdentityKey,
            signed_payload = RawUrl(signedPayload),
            signature = RawUrl(signature),
            one_time_keys = oneTimeKeys.Select(value => new
            {
                key_id = value.KeyId,
                public_key = value.PublicKey,
                signature = RawUrl(value.Signature),
            }).ToArray(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ClaimedKey> ClaimAsync(DesktopAccount account, string targetDeviceId, CancellationToken cancellationToken)
    {
        ClaimResponse root = await RequestAsync<ClaimResponse>(account, HttpMethod.Post, "/api/v3/crypto/ratchet/claim", new
        {
            version = ProtocolVersion,
            target_device_id = targetDeviceId,
        }, cancellationToken).ConfigureAwait(false);
        RequireVersion(root.Version);
        return new ClaimedKey(
            root.DeviceId,
            root.Username,
            root.BundleVersion,
            root.Curve25519IdentityKey,
            root.Ed25519IdentityKey,
            DecodeRawUrl(root.SignedPayload, 32, 65536),
            DecodeRawUrl(root.BundleSignature, 32, 2048),
            new OneTimeKey(
                root.OneTimeKey.KeyId,
                root.OneTimeKey.PublicKey,
                DecodeRawUrl(root.OneTimeKey.Signature, 32, 2048)));
    }

    public async Task<GroupVersionReservation> ReserveGroupVersionAsync(
        DesktopAccount account,
        string chatId,
        string rotationId,
        CancellationToken cancellationToken)
    {
        GroupReservationResponse root = await RequestAsync<GroupReservationResponse>(account, HttpMethod.Post, "/api/v3/crypto/megolm/reserve", new
        {
            version = ProtocolVersion,
            chat_id = chatId,
            rotation_id = rotationId,
        }, cancellationToken).ConfigureAwait(false);
        RequireVersion(root.Version);
        if (!string.Equals(root.ChatId, chatId, StringComparison.Ordinal) ||
            !string.Equals(root.RotationId, rotationId, StringComparison.Ordinal) || root.RoomKeyVersion <= 0)
            throw new CryptographicException("Invalid group reservation response.");
        return new GroupVersionReservation(root.ChatId, root.RotationId, root.RoomKeyVersion);
    }

    public async Task PutGroupSessionAsync(
        DesktopAccount account,
        string chatId,
        long roomKeyVersion,
        string sessionId,
        string rotationId,
        IReadOnlyList<GroupKeyUpload> packages,
        CancellationToken cancellationToken)
    {
        await RequestAsync<JsonElement>(account, HttpMethod.Post, "/api/v3/crypto/megolm/sessions", new
        {
            version = ProtocolVersion,
            chat_id = chatId,
            room_key_version = roomKeyVersion,
            session_id = sessionId,
            rotation_id = rotationId,
            packages = packages.Select(value => new
            {
                recipient_device_id = value.RecipientDeviceId,
                olm_session_id = value.OlmSessionId,
                message_type = value.MessageType,
                encrypted_session_key = RawUrl(value.EncryptedSessionKey),
            }).ToArray(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<GroupPackage>> ListGroupPackagesAsync(
        DesktopAccount account,
        int limit,
        CancellationToken cancellationToken)
    {
        GroupPackageListResponse root = await RequestAsync<GroupPackageListResponse>(
            account,
            HttpMethod.Get,
            $"/api/v3/crypto/megolm/packages?limit={Math.Clamp(limit, 1, 200)}",
            null,
            cancellationToken).ConfigureAwait(false);
        RequireVersion(root.Version);
        return (root.Packages ?? []).Select(value => new GroupPackage(
            value.ChatId,
            value.RoomKeyVersion,
            value.SessionId,
            value.SenderDeviceId,
            value.SenderCurve25519Key,
            value.RotationId,
            value.OlmSessionId,
            value.MessageType,
            DecodeRawUrl(value.EncryptedSessionKey, 16, 65536))).ToArray();
    }

    public async Task ConsumeGroupPackageAsync(
        DesktopAccount account,
        string chatId,
        long roomKeyVersion,
        CancellationToken cancellationToken)
    {
        await RequestAsync<JsonElement>(account, HttpMethod.Post, "/api/v3/crypto/megolm/packages/consume", new
        {
            version = ProtocolVersion,
            chat_id = chatId,
            room_key_version = roomKeyVersion,
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> RequestAsync<T>(
        DesktopAccount account,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        Uri server = ServerEndpointPolicy.Normalize(account.ServerUrl, _endpointMode);
        using var request = new HttpRequestMessage(method, ServerEndpointPolicy.Build(server, path, _endpointMode));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", account.SessionToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoStore = true };
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        using HttpResponseMessage response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string error = await HttpResponseReader.ReadErrorBodyAsync(response, cancellationToken).ConfigureAwait(false);
            string code = "ratchet_request_failed";
            try
            {
                using JsonDocument document = JsonDocument.Parse(error);
                code = document.RootElement.GetProperty("error").GetProperty("code").GetString() ?? code;
            }
            catch (JsonException) { }
            throw new CryptographicException($"FedMes ratchet request failed: {code}");
        }
        return await HttpResponseReader.ReadJsonAsync<T>(response, JsonOptions, MaximumResponseBytes, cancellationToken)
            .ConfigureAwait(false);
    }

    private static void RequireVersion(int version)
    {
        if (version != ProtocolVersion) throw new CryptographicException("Ratchet protocol version mismatch.");
    }

    internal static string RawUrl(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static byte[] DecodeRawUrl(string value, int minimum = 1, int maximum = int.MaxValue)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new CryptographicException("Invalid base64url value.");
        string normalized = value.Replace('-', '+').Replace('_', '/');
        normalized += new string('=', (4 - normalized.Length % 4) % 4);
        byte[] decoded;
        try { decoded = Convert.FromBase64String(normalized); }
        catch (FormatException error) { throw new CryptographicException("Invalid base64url value.", error); }
        if (decoded.Length < minimum || decoded.Length > maximum)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new CryptographicException("Invalid base64url value length.");
        }
        return decoded;
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    public sealed record OneTimeKey(string KeyId, string PublicKey, byte[] Signature);
    public sealed record ClaimedKey(
        string DeviceId,
        string Username,
        int BundleVersion,
        string Curve25519IdentityKey,
        string Ed25519IdentityKey,
        byte[] SignedPayload,
        byte[] BundleSignature,
        OneTimeKey OneTimeKey);
    public sealed record GroupVersionReservation(string ChatId, string RotationId, long RoomKeyVersion);
    public sealed record GroupKeyUpload(string RecipientDeviceId, string OlmSessionId, int MessageType, byte[] EncryptedSessionKey);
    public sealed record GroupPackage(
        string ChatId,
        long RoomKeyVersion,
        string SessionId,
        string SenderDeviceId,
        string SenderCurve25519Key,
        string RotationId,
        string OlmSessionId,
        int MessageType,
        byte[] EncryptedSessionKey);

    private sealed record ClaimResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("device_id")] string DeviceId,
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("bundle_version")] int BundleVersion,
        [property: JsonPropertyName("curve25519_identity_key")] string Curve25519IdentityKey,
        [property: JsonPropertyName("ed25519_identity_key")] string Ed25519IdentityKey,
        [property: JsonPropertyName("signed_payload")] string SignedPayload,
        [property: JsonPropertyName("bundle_signature")] string BundleSignature,
        [property: JsonPropertyName("one_time_key")] OneTimeKeyResponse OneTimeKey);
    private sealed record OneTimeKeyResponse(
        [property: JsonPropertyName("key_id")] string KeyId,
        [property: JsonPropertyName("public_key")] string PublicKey,
        [property: JsonPropertyName("signature")] string Signature);
    private sealed record GroupReservationResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("chat_id")] string ChatId,
        [property: JsonPropertyName("rotation_id")] string RotationId,
        [property: JsonPropertyName("room_key_version")] long RoomKeyVersion);
    private sealed record GroupPackageListResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("packages")] IReadOnlyList<GroupPackageResponse>? Packages);
    private sealed record GroupPackageResponse(
        [property: JsonPropertyName("chat_id")] string ChatId,
        [property: JsonPropertyName("room_key_version")] long RoomKeyVersion,
        [property: JsonPropertyName("session_id")] string SessionId,
        [property: JsonPropertyName("sender_device_id")] string SenderDeviceId,
        [property: JsonPropertyName("sender_curve25519_key")] string SenderCurve25519Key,
        [property: JsonPropertyName("rotation_id")] string RotationId,
        [property: JsonPropertyName("olm_session_id")] string OlmSessionId,
        [property: JsonPropertyName("message_type")] int MessageType,
        [property: JsonPropertyName("encrypted_session_key")] string EncryptedSessionKey);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

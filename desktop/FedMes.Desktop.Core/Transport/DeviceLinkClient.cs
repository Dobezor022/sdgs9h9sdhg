using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Domain;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.Transport;

public sealed record DeviceLinkTicket(
    string LinkId,
    string Secret,
    byte[] QrPng,
    DateTimeOffset ExpiresAt);

public sealed class DeviceLinkClient : IDisposable
{
    private const int MaximumJsonResponseBytes = 2 * 1024 * 1024;
    private const int MaximumQrPngBytes = 1024 * 1024;
    private static readonly byte[] PngSignature = [137, 80, 78, 71, 13, 10, 26, 10];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ServerEndpointMode _endpointMode;

    public DeviceLinkClient(
        HttpClient? httpClient = null,
        ServerEndpointMode endpointMode = ServerEndpointMode.Production)
    {
        if (!Enum.IsDefined(endpointMode))
        {
            throw new ArgumentOutOfRangeException(nameof(endpointMode));
        }

        _http = httpClient ?? new HttpClient();
        _ownsHttp = httpClient is null;
        _endpointMode = endpointMode;
        if (_ownsHttp)
        {
            _http.Timeout = TimeSpan.FromSeconds(25);
        }
    }

    public async Task<DeviceLinkTicket> CreateAsync(
        Uri server,
        string displayName,
        DesktopDeviceIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentNullException.ThrowIfNull(identity);
        var request = new CreateLinkRequest(
            1,
            displayName.Trim(),
            "windows",
            new PublicKeyRequest(DesktopDeviceIdentity.IdentityAlgorithm, identity.IdentityPublicKeySpkiBase64),
            new PublicKeyRequest(DesktopDeviceIdentity.EncryptionAlgorithm, identity.EncryptionPublicKeySpkiBase64));
        CreateLinkResponse response = await PostAsync<CreateLinkRequest, CreateLinkResponse>(
            server,
            "/api/v1/device-links",
            request,
            cancellationToken).ConfigureAwait(false);
        if (response.Version != 1 || !Guid.TryParse(response.LinkId, out _))
        {
            throw new InvalidDataException("The FedMes server returned an invalid device-link identity.");
        }

        ValidateRawBase64Url(response.Secret, 32, "device-link secret");
        byte[] qrPng;
        try
        {
            qrPng = Convert.FromBase64String(response.QrPngBase64 ?? string.Empty);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException("The FedMes server returned an invalid QR image.", error);
        }
        if (qrPng.Length is < 8 or > MaximumQrPngBytes || !qrPng.AsSpan(0, 8).SequenceEqual(PngSignature))
        {
            CryptographicOperations.ZeroMemory(qrPng);
            throw new InvalidDataException("The FedMes server returned an invalid QR image.");
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (response.ExpiresAt <= now.AddSeconds(-5) || response.ExpiresAt > now.AddMinutes(5))
        {
            CryptographicOperations.ZeroMemory(qrPng);
            throw new InvalidDataException("The FedMes server returned an invalid device-link expiration time.");
        }

        return new DeviceLinkTicket(
            response.LinkId,
            response.Secret,
            qrPng,
            response.ExpiresAt);
    }

    public async Task<DesktopAccount> WaitForApprovalAsync(
        Uri server,
        DeviceLinkTicket ticket,
        DesktopDeviceIdentity identity,
        string displayName,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(identity);
        int transientFailures = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= ticket.ExpiresAt)
            {
                throw new InvalidOperationException("Срок действия QR истёк. Создайте новый QR.");
            }

            LinkStatusResponse status;
            try
            {
                status = await PostAsync<LinkSecretRequest, LinkStatusResponse>(
                    server,
                    $"/api/v1/device-links/{Uri.EscapeDataString(ticket.LinkId)}/status",
                    new LinkSecretRequest(1, ticket.Secret),
                    cancellationToken).ConfigureAwait(false);
                transientFailures = 0;
            }
            catch (HttpRequestException error) when (IsTransientLinkError(error) && DateTimeOffset.UtcNow < ticket.ExpiresAt)
            {
                transientFailures++;
                progress?.Report("Связь с сервером восстанавливается…");
                int delayMilliseconds = Math.Min(2_000, 250 * transientFailures);
                await Task.Delay(TimeSpan.FromMilliseconds(delayMilliseconds), cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (status.Version != 1)
            {
                throw new InvalidDataException("The FedMes server returned an unsupported device-link response.");
            }

            switch (status.Status)
            {
                case "pending":
                    progress?.Report("Ожидание подтверждения на телефоне…");
                    await Task.Delay(TimeSpan.FromMilliseconds(300), cancellationToken).ConfigureAwait(false);
                    continue;
                case "approved":
                    return await CompleteApprovedLinkAsync(server, ticket, status, identity, displayName, cancellationToken)
                        .ConfigureAwait(false);
                case "cancelled":
                    throw new InvalidOperationException("Вход отменён.");
                case "consumed":
                    throw new InvalidOperationException("Этот QR уже использован.");
                default:
                    throw new InvalidOperationException("Срок действия QR истёк. Создайте новый QR.");
            }
        }
    }

    public async Task CancelAsync(Uri server, DeviceLinkTicket ticket, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        using var request = CreateJsonRequest(
            ServerEndpointPolicy.Build(
                server,
                $"/api/v1/device-links/{Uri.EscapeDataString(ticket.LinkId)}/cancel",
                _endpointMode),
            new LinkSecretRequest(1, ticket.Secret));
        using HttpResponseMessage response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            await ThrowServerErrorAsync(response, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task RevokeCurrentDeviceAsync(DesktopAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);
        Uri server = NormalizeServerUrl(account.ServerUrl, _endpointMode);
        using var request = new HttpRequestMessage(
            HttpMethod.Delete,
            ServerEndpointPolicy.Build(server, "/api/v1/account/device", _endpointMode));
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", account.SessionToken);
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode && response.StatusCode != System.Net.HttpStatusCode.Unauthorized)
        {
            await ThrowServerErrorAsync(response, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<DesktopAccount> RefreshSessionAsync(
        DesktopAccount account,
        DesktopDeviceIdentity identity,
        CancellationToken cancellationToken)
    {
        Uri server = NormalizeServerUrl(account.ServerUrl, _endpointMode);
        ChallengeResponse envelope = await PostAsync<ChallengeRequest, ChallengeResponse>(
            server,
            "/api/v1/auth/challenge",
            new ChallengeRequest(
                1,
                account.Username,
                new PublicKeyRequest(DesktopDeviceIdentity.IdentityAlgorithm, identity.IdentityPublicKeySpkiBase64),
                "session.refresh"),
            cancellationToken).ConfigureAwait(false);
        if (envelope.Version != 1)
        {
            throw new CryptographicException("The server returned an unsupported authentication protocol version.");
        }

        Challenge challenge = envelope.Challenge
            ?? throw new CryptographicException("The server returned an empty authentication challenge.");
        string expectedAudience = ServerEndpointPolicy.AuthenticationAudience(server, _endpointMode);
        if (!string.Equals(challenge.DeviceId, account.DeviceId, StringComparison.Ordinal) ||
            !Guid.TryParse(challenge.Id, out _) ||
            !Guid.TryParse(challenge.DeviceId, out _) ||
            !string.Equals(challenge.Purpose, "session.refresh", StringComparison.Ordinal) ||
            !string.Equals(challenge.Audience, expectedAudience, StringComparison.Ordinal) ||
            challenge.ExpiresAt <= DateTimeOffset.UtcNow ||
            challenge.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            throw new CryptographicException("Сервер вернул другое устройство.");
        }

        ValidateRawBase64Url(challenge.Nonce, 32, "authentication nonce");

        byte[] canonical = Encoding.UTF8.GetBytes(string.Join("\n",
            "fedmes-device-auth-v1",
            challenge.Audience,
            account.Username,
            challenge.DeviceId,
            challenge.Id,
            "session.refresh",
            challenge.Nonce));
        string signature;
        try
        {
            signature = identity.SignSha256Base64(canonical);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }

        SessionResponse response = await PostAsync<SessionRequest, SessionResponse>(
            server,
            "/api/v1/auth/session",
            new SessionRequest(
                1,
                account.Username,
                challenge.DeviceId,
                challenge.Id,
                challenge.Nonce,
                "session.refresh",
                signature),
            cancellationToken).ConfigureAwait(false);
        Session refreshedSession = ValidateSessionResponse(response, account, identity);
        return account with
        {
            SessionId = refreshedSession.Id,
            SessionToken = refreshedSession.Token,
            SessionExpiresAt = refreshedSession.ExpiresAt,
        };
    }

    public static Uri NormalizeServerUrl(
        string value,
        ServerEndpointMode endpointMode = ServerEndpointMode.Production)
    {
        return ServerEndpointPolicy.Normalize(value, endpointMode);
    }

    private static async Task<DesktopAccount> CompleteApprovedLinkAsync(
        Uri server,
        DeviceLinkTicket ticket,
        LinkStatusResponse status,
        DesktopDeviceIdentity identity,
        string displayName,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(status.EncryptedSessionToken) ||
            string.IsNullOrWhiteSpace(status.Username) ||
            string.IsNullOrWhiteSpace(status.DeviceId) ||
            string.IsNullOrWhiteSpace(status.SessionId) ||
            status.SessionExpiresAt is null ||
            !FixedFamilyUsers.IsAllowed(status.Username) ||
            !Guid.TryParse(status.DeviceId, out _) ||
            !Guid.TryParse(status.SessionId, out _) ||
            status.SessionExpiresAt <= DateTimeOffset.UtcNow ||
            status.SessionExpiresAt > DateTimeOffset.UtcNow.AddMinutes(30))
        {
            throw new InvalidOperationException("Сервер вернул неполный результат входа.");
        }

        byte[] encrypted = Convert.FromBase64String(status.EncryptedSessionToken);
        byte[] token = [];
        try
        {
            token = identity.DecryptSessionToken(encrypted);
            if (token.Length != 32)
            {
                throw new CryptographicException("Токен входа имеет неверный размер.");
            }

            string tokenBase64Url = Convert.ToBase64String(token).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var account = new DesktopAccount(
                server.GetLeftPart(UriPartial.Authority),
                status.Username,
                status.DeviceId,
                status.SessionId,
                tokenBase64Url,
                status.SessionExpiresAt.Value,
                displayName,
                NormalizeAuthenticationState(status.AuthenticationState));
            return account;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
            CryptographicOperations.ZeroMemory(token);
        }
    }

    private static string NormalizeAuthenticationState(string? value)
    {
        string state = string.IsNullOrWhiteSpace(value) ? "READY" : value.Trim().ToUpperInvariant();
        return state switch
        {
            "UNREGISTERED" or "REGISTRATION_PENDING" or "AUTHENTICATED_NO_KEYS" or
            "KEY_TRANSFER_PENDING" or "KEYS_RESTORED" or "READY" or "REVOKED" or
            "RECOVERY_REQUIRED" => state,
            _ => throw new CryptographicException("The server returned an unsupported account security state."),
        };
    }

    public async Task AcknowledgeCompletedLinkAsync(
        Uri server,
        DeviceLinkTicket ticket,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(ticket);
        HttpRequestException? lastNetworkError = null;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                using var request = CreateJsonRequest(
                    ServerEndpointPolicy.Build(
                        server,
                        $"/api/v1/device-links/{Uri.EscapeDataString(ticket.LinkId)}/complete",
                        _endpointMode),
                    new LinkSecretRequest(1, ticket.Secret));
                using HttpResponseMessage response = await _http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    return;
                }

                string code = await ReadServerErrorCodeAsync(response, cancellationToken).ConfigureAwait(false);
                if (response.StatusCode == System.Net.HttpStatusCode.Conflict &&
                    string.Equals(code, "device_link_used", StringComparison.Ordinal))
                {
                    return;
                }

                throw CreateServerException(response, code);
            }
            catch (HttpRequestException error) when (attempt < 4 && error.StatusCode is null)
            {
                lastNetworkError = error;
                await Task.Delay(TimeSpan.FromMilliseconds(500 * (attempt + 1)), cancellationToken).ConfigureAwait(false);
            }
        }

        throw lastNetworkError ?? new HttpRequestException("Не удалось подтвердить завершение входа.");
    }

    private static bool IsTransientLinkError(HttpRequestException error) =>
        error.StatusCode is null or
        System.Net.HttpStatusCode.RequestTimeout or
        System.Net.HttpStatusCode.TooManyRequests or
        System.Net.HttpStatusCode.BadGateway or
        System.Net.HttpStatusCode.ServiceUnavailable or
        System.Net.HttpStatusCode.GatewayTimeout;

    private async Task<TResponse> PostAsync<TRequest, TResponse>(
        Uri server,
        string path,
        TRequest request,
        CancellationToken cancellationToken)
    {
        using var message = CreateJsonRequest(ServerEndpointPolicy.Build(server, path, _endpointMode), request);
        using HttpResponseMessage response = await _http.SendAsync(
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            await ThrowServerErrorAsync(response, cancellationToken).ConfigureAwait(false);
        }

        return await HttpResponseReader.ReadJsonAsync<TResponse>(
            response,
            JsonOptions,
            MaximumJsonResponseBytes,
            cancellationToken).ConfigureAwait(false);
    }

    private static HttpRequestMessage CreateJsonRequest<TRequest>(Uri uri, TRequest value)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = JsonContent.Create(value, options: JsonOptions),
        };
        request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoStore = true };
        return request;
    }

    private static async Task ThrowServerErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string code = await ReadServerErrorCodeAsync(response, cancellationToken).ConfigureAwait(false);
        throw CreateServerException(response, code);
    }

    private static async Task<string> ReadServerErrorCodeAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        string body = await HttpResponseReader.ReadErrorBodyAsync(response, cancellationToken).ConfigureAwait(false);
        string code = $"http_{(int)response.StatusCode}";
        try
        {
            using JsonDocument json = JsonDocument.Parse(body);
            code = json.RootElement.GetProperty("error").GetProperty("code").GetString() ?? code;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
        {
        }

        return code;
    }

    private static HttpRequestException CreateServerException(HttpResponseMessage response, string code) =>
        new(code switch
        {
            "device_link_expired" => "Срок действия QR истёк.",
            "device_link_used" => "QR уже использован.",
            "device_link_conflict" => "Этот компьютер уже подключён.",
            "session_invalid" => "Сессия телефона недействительна.",
            "invalid_signature" => "Подпись устройства отклонена.",
            _ => $"Сервер отклонил запрос: {code}",
        }, null, response.StatusCode);

    private static void ValidateRawBase64Url(string? value, int expectedBytes, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('='))
        {
            throw new InvalidDataException($"The server returned an invalid {fieldName}.");
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        }
        catch (FormatException error)
        {
            throw new InvalidDataException($"The server returned an invalid {fieldName}.", error);
        }

        try
        {
            if (decoded.Length != expectedBytes)
            {
                throw new InvalidDataException($"The server returned an invalid {fieldName}.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static Session ValidateSessionResponse(
        SessionResponse response,
        DesktopAccount account,
        DesktopDeviceIdentity identity)
    {
        SessionDevice? device = response.Device;
        Session? session = response.Session;
        string expectedFingerprint = Convert.ToHexString(
            SHA256.HashData(Convert.FromBase64String(identity.IdentityPublicKeySpkiBase64))).ToLowerInvariant();
        if (response.Version != 1 ||
            device is null ||
            session is null ||
            !string.Equals(device.Id, account.DeviceId, StringComparison.Ordinal) ||
            !string.Equals(device.Username, account.Username, StringComparison.Ordinal) ||
            !string.Equals(device.KeyAlgorithm, DesktopDeviceIdentity.IdentityAlgorithm, StringComparison.Ordinal) ||
            !string.Equals(device.KeyFingerprint, expectedFingerprint, StringComparison.Ordinal) ||
            !Guid.TryParse(session.Id, out _) ||
            session.IssuedAt > DateTimeOffset.UtcNow.AddMinutes(1) ||
            session.ExpiresAt <= DateTimeOffset.UtcNow ||
            session.ExpiresAt > session.IssuedAt.AddMinutes(30))
        {
            throw new CryptographicException("The server returned an invalid refreshed-session context.");
        }

        ValidateRawBase64Url(session.Token, 32, "session token");
        return session;
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private sealed record PublicKeyRequest(
        [property: JsonPropertyName("algorithm")] string Algorithm,
        [property: JsonPropertyName("public_key_spki")] string PublicKeySpki);

    private sealed record CreateLinkRequest(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("display_name")] string DisplayName,
        [property: JsonPropertyName("platform")] string Platform,
        [property: JsonPropertyName("identity")] PublicKeyRequest Identity,
        [property: JsonPropertyName("encryption")] PublicKeyRequest Encryption);

    private sealed record CreateLinkResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("link_id")] string LinkId,
        [property: JsonPropertyName("secret")] string Secret,
        [property: JsonPropertyName("qr_png_base64")] string QrPngBase64,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

    private sealed record LinkSecretRequest(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("secret")] string Secret);

    private sealed record LinkStatusResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("status")] string Status,
        [property: JsonPropertyName("username")] string? Username,
        [property: JsonPropertyName("device_id")] string? DeviceId,
        [property: JsonPropertyName("session_id")] string? SessionId,
        [property: JsonPropertyName("encrypted_session_token")] string? EncryptedSessionToken,
        [property: JsonPropertyName("session_expires_at")] DateTimeOffset? SessionExpiresAt,
        [property: JsonPropertyName("authentication_state")] string? AuthenticationState);

    private sealed record ChallengeRequest(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("device")] PublicKeyRequest Device,
        [property: JsonPropertyName("purpose")] string Purpose);

    private sealed record ChallengeResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("challenge")] Challenge? Challenge);

    private sealed record Challenge(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("device_id")] string DeviceId,
        [property: JsonPropertyName("audience")] string Audience,
        [property: JsonPropertyName("purpose")] string Purpose,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

    private sealed record SessionRequest(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("device_id")] string DeviceId,
        [property: JsonPropertyName("challenge_id")] string ChallengeId,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("purpose")] string Purpose,
        [property: JsonPropertyName("signature")] string Signature);

    private sealed record SessionResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("device")] SessionDevice? Device,
        [property: JsonPropertyName("session")] Session? Session);

    private sealed record SessionDevice(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("key_algorithm")] string KeyAlgorithm,
        [property: JsonPropertyName("key_fingerprint")] string KeyFingerprint);

    private sealed record Session(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);
}

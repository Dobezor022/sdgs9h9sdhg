using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Core.AccountSecurity;

public sealed class OpaqueAuthHttpClient
{
    private const int ProtocolVersion = 4;
    private readonly HttpClient _http;

    public OpaqueAuthHttpClient(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            ConnectTimeout = TimeSpan.FromSeconds(10),
        }) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public Task<OpaqueStartWire> RegistrationStartAsync(DesktopAccount account, string message, bool passwordChange, CancellationToken ct) =>
        SendAsync<OpaqueStartWire>(account.ServerUrl,
            passwordChange ? "/api/v3/auth/opaque/password-change/start" : "/api/v3/auth/opaque/registration/start",
            HttpMethod.Post, new { version = ProtocolVersion, request_id = Guid.NewGuid().ToString(), username = account.Username, message }, account.SessionToken, ct);

    public async Task RegistrationFinishAsync(DesktopAccount account, string attemptId, string record, bool passwordChange, CancellationToken ct)
    {
        _ = await SendAsync<JsonElement>(account.ServerUrl,
            passwordChange ? "/api/v3/auth/opaque/password-change/finish" : "/api/v3/auth/opaque/registration/finish",
            HttpMethod.Post, new { version = ProtocolVersion, attempt_id = attemptId, message = record }, account.SessionToken, ct).ConfigureAwait(false);
    }

    public Task<OpaqueStartWire> LoginStartAsync(
        string serverUrl, string username, string ke1, string deviceId, string displayName,
        string signingAlgorithm, string signingPublicKeySpkiBase64,
        string agreementAlgorithm, string agreementPublicKeySpkiBase64,
        CancellationToken ct) => SendAsync<OpaqueStartWire>(serverUrl, "/api/v3/auth/opaque/login/start", HttpMethod.Post, new
        {
            version = ProtocolVersion,
            request_id = Guid.NewGuid().ToString(),
            username,
            message = ke1,
            device_id = deviceId,
            display_name = displayName,
            platform = "windows",
            signing_algorithm = signingAlgorithm,
            signing_public_key_spki = ToBase64Url(signingPublicKeySpkiBase64),
            key_agreement_algorithm = agreementAlgorithm,
            key_agreement_public_key_spki = ToBase64Url(agreementPublicKeySpkiBase64),
        }, null, ct);

    public Task<OpaqueLoginWire> LoginFinishAsync(string serverUrl, string attemptId, string ke3, CancellationToken ct) =>
        SendAsync<OpaqueLoginWire>(serverUrl, "/api/v3/auth/opaque/login/finish", HttpMethod.Post,
            new { version = ProtocolVersion, attempt_id = attemptId, message = ke3 }, null, ct);

    public Task<OpaqueRecoveryWire> GetRecoveryPackageAsync(DesktopAccount account, CancellationToken ct) =>
        SendAsync<OpaqueRecoveryWire>(account.ServerUrl, "/api/v3/security/opaque-recovery-package", HttpMethod.Get, null, account.SessionToken, ct);

    public async Task PutRecoveryPackageAsync(DesktopAccount account, OpaqueRecoveryEnvelope value, CancellationToken ct)
    {
        _ = await SendAsync<JsonElement>(account.ServerUrl, "/api/v3/security/opaque-recovery-package", HttpMethod.Put, new
        {
            version = ProtocolVersion,
            vault_revision = value.VaultRevision,
            package_version = value.PackageVersion,
            nonce = Base64Url(value.Nonce),
            ciphertext = Base64Url(value.Ciphertext),
            ciphertext_sha256 = Convert.ToHexStringLower(value.CiphertextHash),
        }, account.SessionToken, ct).ConfigureAwait(false);
    }

    private async Task<T> SendAsync<T>(string serverUrl, string path, HttpMethod method, object? body, string? bearer, CancellationToken ct)
    {
        Uri endpoint = ServerEndpointPolicy.Build(ServerEndpointPolicy.Normalize(serverUrl), path);
        using var request = new HttpRequestMessage(method, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(bearer)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string code = "opaque_request_failed";
            string errorBody = await HttpResponseReader.ReadErrorBodyAsync(response, ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(errorBody))
            {
                try
                {
                    using JsonDocument errorDocument = JsonDocument.Parse(errorBody);
                    code = errorDocument.RootElement.GetProperty("error").GetProperty("code").GetString() ?? code;
                }
                catch (JsonException) { }
            }
            throw new CryptographicException(code);
        }

        return await HttpResponseReader.ReadJsonAsync<T>(response, JsonOptions, 2 * 1024 * 1024, ct).ConfigureAwait(false);
    }

    private static string ToBase64Url(string standard)
    {
        byte[] bytes = Convert.FromBase64String(standard);
        try { return Base64Url(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string Base64Url(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static byte[] Base64UrlDecode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}

public sealed record OpaqueStartWire(
    [property: JsonPropertyName("attempt_id")] string AttemptId,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("suite")] string Suite,
    [property: JsonPropertyName("server_identity")] string? ServerIdentity,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

public sealed record OpaqueLoginWire(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("device_id")] string DeviceId,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("session_token")] string SessionToken,
    [property: JsonPropertyName("authentication_state")] string AuthenticationState,
    [property: JsonPropertyName("provisioning_request_id")] string ProvisioningRequestId,
    [property: JsonPropertyName("server_proof")] string ServerProof,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

public sealed record OpaqueRecoveryWire(
    [property: JsonPropertyName("vault_revision")] long VaultRevision,
    [property: JsonPropertyName("package_version")] int PackageVersion,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("ciphertext")] string Ciphertext,
    [property: JsonPropertyName("ciphertext_sha256")] string CiphertextSha256);

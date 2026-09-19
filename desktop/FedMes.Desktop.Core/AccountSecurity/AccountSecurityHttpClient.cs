using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Core.AccountSecurity;

public sealed class AccountSecurityHttpClient : IDisposable
{
    private const int MaximumSecurityResponseBytes = 18 * 1024 * 1024;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ServerEndpointMode _endpointMode;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public AccountSecurityHttpClient(
        HttpClient? httpClient = null,
        ServerEndpointMode endpointMode = ServerEndpointMode.Production)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _ownsHttp = httpClient is null;
        _endpointMode = endpointMode;
    }

    public async Task<AccountSecurityState> GetStateAsync(DesktopAccount account, CancellationToken cancellationToken)
    {
        StateEnvelope envelope = await SendAsync<StateEnvelope>(account, HttpMethod.Get, "/api/v2/security/state", null, null, cancellationToken)
            .ConfigureAwait(false);
        ValidateVersion(envelope.Version);
        return envelope.Security ?? throw new CryptographicException("The server returned an empty security state.");
    }

    public async Task<EncryptedAccountVault> GetVaultAsync(DesktopAccount account, CancellationToken cancellationToken)
    {
        VaultEnvelope envelope = await SendAsync<VaultEnvelope>(account, HttpMethod.Get, "/api/v2/security/vault", null, null, cancellationToken)
            .ConfigureAwait(false);
        ValidateVersion(envelope.Version);
        return new EncryptedAccountVault(
            envelope.Revision,
            envelope.VaultVersion,
            envelope.CryptoVersion,
            envelope.AadVersion,
            DecodeBase64(envelope.Nonce, AccountSecurityProtocol.NonceBytes, 24, "vault nonce"),
            DecodeBase64(envelope.Ciphertext, 17, 16 * 1024 * 1024, "vault ciphertext"),
            ValidateHash(envelope.CiphertextSha256));
    }

    public async Task<EncryptedAccountVault> PutVaultAsync(
        DesktopAccount account,
        EncryptedAccountVault vault,
        long expectedPreviousRevision,
        byte[] accessVerifier,
        CancellationToken cancellationToken)
    {
        var request = new
        {
            version = AccountSecurityProtocol.Version,
            expected_previous_revision = expectedPreviousRevision,
            vault_version = vault.VaultVersion,
            crypto_version = vault.CryptoVersion,
            aad_version = vault.AadVersion,
            nonce = Convert.ToBase64String(vault.Nonce),
            ciphertext = Convert.ToBase64String(vault.Ciphertext),
            ciphertext_sha256 = vault.CiphertextSha256,
            access_verifier = Convert.ToBase64String(accessVerifier),
        };
        VaultEnvelope envelope = await SendAsync<VaultEnvelope>(
            account,
            HttpMethod.Put,
            "/api/v2/security/vault",
            request,
            Guid.NewGuid().ToString(),
            cancellationToken).ConfigureAwait(false);
        ValidateVersion(envelope.Version);
        return new EncryptedAccountVault(
            envelope.Revision,
            envelope.VaultVersion,
            envelope.CryptoVersion,
            envelope.AadVersion,
            DecodeBase64(envelope.Nonce, AccountSecurityProtocol.NonceBytes, 24, "vault nonce"),
            DecodeBase64(envelope.Ciphertext, 17, 16 * 1024 * 1024, "vault ciphertext"),
            ValidateHash(envelope.CiphertextSha256));
    }

    public async Task<EncryptedRecoveryPackage> GetRecoveryPackageAsync(DesktopAccount account, CancellationToken cancellationToken)
    {
        RecoveryEnvelope envelope = await SendAsync<RecoveryEnvelope>(
            account,
            HttpMethod.Get,
            "/api/v2/security/recovery-package",
            null,
            null,
            cancellationToken).ConfigureAwait(false);
        ValidateVersion(envelope.Version);
        return MapRecovery(envelope);
    }

    public async Task<EncryptedRecoveryPackage> PutRecoveryPackageAsync(
        DesktopAccount account,
        EncryptedRecoveryPackage package,
        CancellationToken cancellationToken)
    {
        var request = new
        {
            version = AccountSecurityProtocol.Version,
            id = package.Id,
            vault_revision = package.VaultRevision,
            package_version = package.PackageVersion,
            crypto_version = package.CryptoVersion,
            aad_version = package.AadVersion,
            kdf_name = package.KdfName,
            kdf_parameters = package.KdfParameters,
            salt = Convert.ToBase64String(package.Salt),
            nonce = Convert.ToBase64String(package.Nonce),
            ciphertext = Convert.ToBase64String(package.Ciphertext),
            ciphertext_sha256 = package.CiphertextSha256,
        };
        RecoveryEnvelope envelope = await SendAsync<RecoveryEnvelope>(
            account,
            HttpMethod.Put,
            "/api/v2/security/recovery-package",
            request,
            Guid.NewGuid().ToString(),
            cancellationToken).ConfigureAwait(false);
        ValidateVersion(envelope.Version);
        return MapRecovery(envelope);
    }

    public async Task CompleteRecoveryAsync(
        DesktopAccount account,
        long vaultRevision,
        byte[] accessVerifier,
        CancellationToken cancellationToken)
    {
        var request = new
        {
            version = AccountSecurityProtocol.Version,
            vault_revision = vaultRevision,
            access_verifier = Convert.ToBase64String(accessVerifier),
        };
        await SendNoContentAsync(account, HttpMethod.Post, "/api/v2/security/recovery/complete", request, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<T> SendAsync<T>(
        DesktopAccount account,
        HttpMethod method,
        string path,
        object? body,
        string? requestId,
        CancellationToken cancellationToken)
    {
        Uri server = ServerEndpointPolicy.Normalize(account.ServerUrl, _endpointMode);
        using var request = new HttpRequestMessage(method, ServerEndpointPolicy.Build(server, path, _endpointMode));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", account.SessionToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(requestId)) request.Headers.TryAddWithoutValidation("X-FedMes-Request-ID", requestId);
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken).ConfigureAwait(false);
        }
        byte[] bytes = await ReadLimitedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, JsonOptions)
                ?? throw new JsonException("The server returned an empty JSON document.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task SendNoContentAsync(
        DesktopAccount account,
        HttpMethod method,
        string path,
        object body,
        CancellationToken cancellationToken)
    {
        Uri server = ServerEndpointPolicy.Normalize(account.ServerUrl, _endpointMode);
        using var request = new HttpRequestMessage(method, ServerEndpointPolicy.Build(server, path, _endpointMode));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", account.SessionToken);
        request.Content = JsonContent.Create(body, options: JsonOptions);
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<Exception> CreateExceptionAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string code = "security_request_failed";
        try
        {
            byte[] bytes = await ReadLimitedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            try
            {
                using JsonDocument document = JsonDocument.Parse(bytes);
                if (document.RootElement.TryGetProperty("error", out JsonElement value)) code = value.GetString() ?? code;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch (Exception error) when (error is IOException or JsonException or InvalidDataException)
        {
        }
        return response.StatusCode switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => new UnauthorizedAccessException("The FedMes security session is no longer valid."),
            HttpStatusCode.NotFound => new AccountSecurityRecordNotFoundException(code),
            HttpStatusCode.Conflict or HttpStatusCode.Locked => new InvalidOperationException(code),
            _ => new HttpRequestException(code, null, response.StatusCode),
        };
    }

    private static async Task<byte[]> ReadLimitedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumSecurityResponseBytes) throw new InvalidDataException("Security response is too large.");
        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        byte[] buffer = GC.AllocateUninitializedArray<byte>(32 * 1024);
        try
        {
            int total = 0;
            while (true)
            {
                int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                total = checked(total + read);
                if (total > MaximumSecurityResponseBytes) throw new InvalidDataException("Security response is too large.");
                output.Write(buffer, 0, read);
            }
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static EncryptedRecoveryPackage MapRecovery(RecoveryEnvelope envelope) => new(
        envelope.Id,
        envelope.VaultRevision,
        envelope.PackageVersion,
        envelope.CryptoVersion,
        envelope.AadVersion,
        envelope.KdfName,
        envelope.KdfParameters,
        DecodeBase64(envelope.Salt, 16, 64, "recovery salt"),
        DecodeBase64(envelope.Nonce, AccountSecurityProtocol.NonceBytes, 24, "recovery nonce"),
        DecodeBase64(envelope.Ciphertext, 17, 1024 * 1024, "recovery ciphertext"),
        ValidateHash(envelope.CiphertextSha256));

    private static byte[] DecodeBase64(string text, int minimum, int maximum, string name)
    {
        byte[] value;
        try { value = Convert.FromBase64String(text); }
        catch (FormatException error) { throw new CryptographicException($"Invalid {name}.", error); }
        if (value.Length < minimum || value.Length > maximum)
        {
            CryptographicOperations.ZeroMemory(value);
            throw new CryptographicException($"Invalid {name} size.");
        }
        return value;
    }

    private static string ValidateHash(string text)
    {
        if (text.Length != 64 || !text.All(Uri.IsHexDigit)) throw new CryptographicException("Invalid ciphertext hash.");
        return text.ToLowerInvariant();
    }

    private static void ValidateVersion(int version)
    {
        if (version != AccountSecurityProtocol.Version) throw new CryptographicException("Unsupported FedMes security protocol version.");
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    private sealed record StateEnvelope(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("security")] AccountSecurityState? Security);

    private sealed record VaultEnvelope(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("revision")] long Revision,
        [property: JsonPropertyName("vault_version")] int VaultVersion,
        [property: JsonPropertyName("crypto_version")] int CryptoVersion,
        [property: JsonPropertyName("aad_version")] int AadVersion,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("ciphertext")] string Ciphertext,
        [property: JsonPropertyName("ciphertext_sha256")] string CiphertextSha256);

    private sealed record RecoveryEnvelope(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("vault_revision")] long VaultRevision,
        [property: JsonPropertyName("package_version")] int PackageVersion,
        [property: JsonPropertyName("crypto_version")] int CryptoVersion,
        [property: JsonPropertyName("aad_version")] int AadVersion,
        [property: JsonPropertyName("kdf_name")] string KdfName,
        [property: JsonPropertyName("kdf_parameters")] string KdfParameters,
        [property: JsonPropertyName("salt")] string Salt,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("ciphertext")] string Ciphertext,
        [property: JsonPropertyName("ciphertext_sha256")] string CiphertextSha256);
}

public sealed record AccountSecurityState(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("device_id")] string DeviceId,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("protocol_version")] int ProtocolVersion,
    [property: JsonPropertyName("crypto_version")] int CryptoVersion,
    [property: JsonPropertyName("vault_revision")] long VaultRevision,
    [property: JsonPropertyName("recovery_configured")] bool RecoveryConfigured,
    [property: JsonPropertyName("opaque_enrolled")] bool OpaqueEnrolled);

public sealed class AccountSecurityRecordNotFoundException : Exception
{
    public AccountSecurityRecordNotFoundException(string message) : base(message) { }
}

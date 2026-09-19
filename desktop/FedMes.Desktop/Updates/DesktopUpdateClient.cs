using System.Buffers;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Updates;

public sealed record DesktopUpdateRelease(
    string VersionName,
    long VersionCode,
    long MinimumSupportedCode,
    Uri Server,
    string DownloadPath,
    string DownloadTicket,
    string Sha256,
    long SizeBytes,
    string Notes,
    DateTimeOffset PublishedAt,
    bool Required);

public sealed class DesktopUpdateTicketExpiredException : Exception
{
    public DesktopUpdateTicketExpiredException() : base("Билет загрузки обновления истёк.") { }
}

public sealed class DesktopUpdateClient : IDisposable
{
    private const int UpdateProtocolVersion = 2;
    private const string DownloadEndpointPath = "/api/v1/updates/download";
    private const int MaximumJsonBytes = 128 * 1024;
    private const long MaximumExecutableBytes = 1024L * 1024L * 1024L;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly HttpClient _httpClient;
    private bool _disposed;

    public DesktopUpdateClient()
    {
        _httpClient = new HttpClient(new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        })
        {
            Timeout = TimeSpan.FromMinutes(45),
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"FedMes-Windows/{AppRelease.VersionName}");
    }

    public async Task<DesktopUpdateRelease?> CheckAsync(
        DesktopAccount account,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(account);
        Uri server = new(account.ServerUrl, UriKind.Absolute);
        if (!string.Equals(server.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Обновления разрешены только через HTTPS.");
        }

        Uri endpoint = new(
            server,
            $"/api/v1/updates/check?platform=windows-x64&version_name={Uri.EscapeDataString(AppRelease.VersionName)}&version_code={AppRelease.VersionCode.ToString(CultureInfo.InvariantCulture)}&client_nonce={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)}");
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", account.SessionToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };

        using HttpResponseMessage response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.ServiceUnavailable) return null;
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            throw new UnauthorizedAccessException("Сессия FedMes не разрешает получить обновление.");
        }
        response.EnsureSuccessStatusCode();

        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var limited = new MemoryStream();
        await CopyLimitedAsync(stream, limited, MaximumJsonBytes, cancellationToken).ConfigureAwait(false);
        UpdateResponse payload = JsonSerializer.Deserialize<UpdateResponse>(limited.ToArray(), JsonOptions)
            ?? throw new InvalidDataException("Сервер обновлений вернул пустой ответ.");
        if (payload.Version != UpdateProtocolVersion ||
            !string.Equals(payload.Platform, "windows-x64", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Версия протокола обновления не поддерживается.");
        }
        if (!payload.UpdateAvailable) return null;
        if (!string.Equals(payload.Latest.DownloadMethod, "POST", StringComparison.Ordinal) ||
            !string.Equals(payload.Latest.DownloadPath, DownloadEndpointPath, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Сервер вернул небезопасный способ загрузки обновления.");
        }
        if (payload.Latest.DownloadTicket.Length is < 64 or > 4096)
        {
            throw new InvalidDataException("Сервер вернул неправильный билет загрузки.");
        }

        string sha256 = payload.Latest.Sha256.Trim().ToLowerInvariant();
        if (sha256.Length != 64 || sha256.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidDataException("Сервер вернул неправильную контрольную сумму обновления.");
        }
        if (payload.Latest.SizeBytes <= 0 || payload.Latest.SizeBytes > MaximumExecutableBytes)
        {
            throw new InvalidDataException("Сервер вернул неправильный размер обновления.");
        }

        return new DesktopUpdateRelease(
            payload.Latest.VersionName,
            payload.Latest.VersionCode,
            payload.Latest.MinimumSupportedCode,
            server,
            payload.Latest.DownloadPath,
            payload.Latest.DownloadTicket,
            sha256,
            payload.Latest.SizeBytes,
            payload.Latest.Notes,
            payload.Latest.PublishedAt,
            payload.Required);
    }

    public async Task<string> DownloadAsync(
        DesktopUpdateRelease release,
        string sessionToken,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionToken);

        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes",
            "Updates");
        Directory.CreateDirectory(directory);
        string destination = Path.Combine(
            directory,
            $"FedMes-{release.VersionName}-{release.VersionCode}-{release.Sha256[..12]}.exe");
        foreach (string stale in Directory.EnumerateFiles(directory))
        {
            if (!string.Equals(stale, destination, StringComparison.OrdinalIgnoreCase)) TryDelete(stale);
        }

        await DownloadVerifiedOnceAsync(
            release,
            sessionToken,
            destination,
            progress,
            cancellationToken).ConfigureAwait(false);
        return destination;
    }

    private async Task DownloadVerifiedOnceAsync(
        DesktopUpdateRelease release,
        string sessionToken,
        string destination,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        string temporary = destination + ".part";
        TryDelete(temporary);
        Uri endpoint = new(release.Server, release.DownloadPath);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(new DownloadRequest(1, release.DownloadTicket), JsonOptions);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new ByteArrayContent(body),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sessionToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
            request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
            request.Headers.AcceptEncoding.Clear();
            request.Headers.AcceptEncoding.ParseAdd("identity");
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
            {
                CharSet = "utf-8",
            };

            using HttpResponseMessage response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Gone) throw new DesktopUpdateTicketExpiredException();
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new UnauthorizedAccessException("Сервер отклонил авторизацию обновления.");
            }
            response.EnsureSuccessStatusCode();

            string? headerHash = GetHeader(response, "X-FedMes-SHA256")?.Trim().ToLowerInvariant();
            string? headerSizeRaw = GetHeader(response, "X-FedMes-Size");
            if (!long.TryParse(headerSizeRaw, NumberStyles.None, CultureInfo.InvariantCulture, out long headerSize) ||
                !string.Equals(headerHash, release.Sha256, StringComparison.Ordinal) ||
                headerSize != release.SizeBytes)
            {
                throw new InvalidDataException("Метаданные файла не совпадают с подписанным билетом.");
            }

            await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
            long total = 0;
            try
            {
                await using (var output = new FileStream(
                    temporary,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    128 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    while (true)
                    {
                        int read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                        if (read == 0) break;
                        total += read;
                        if (total > release.SizeBytes || total > MaximumExecutableBytes)
                        {
                            throw new InvalidDataException("Размер обновления не совпадает с манифестом.");
                        }
                        await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        hash.AppendData(buffer, 0, read);
                        progress?.Report((int)Math.Clamp(total * 100L / release.SizeBytes, 0, 99));
                    }
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                TryDelete(temporary);
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }

            if (total != release.SizeBytes)
            {
                TryDelete(temporary);
                throw new InvalidDataException("Обновление загружено не полностью.");
            }
            byte[] actualHash = hash.GetHashAndReset();
            byte[] expectedHash = Convert.FromHexString(release.Sha256);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                {
                    TryDelete(temporary);
                    throw new CryptographicException("SHA-256 обновления не совпал с серверным манифестом.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualHash);
                CryptographicOperations.ZeroMemory(expectedHash);
            }

            File.Move(temporary, destination, overwrite: true);
            progress?.Report(100);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
            if (File.Exists(temporary) && !File.Exists(destination)) TryDelete(temporary);
        }
    }

    private static string? GetHeader(HttpResponseMessage response, string name)
    {
        if (response.Headers.TryGetValues(name, out IEnumerable<string>? values)) return values.FirstOrDefault();
        if (response.Content.Headers.TryGetValues(name, out values)) return values.FirstOrDefault();
        return null;
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }

    private static async Task CopyLimitedAsync(
        Stream input,
        Stream output,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        int total = 0;
        try
        {
            while (true)
            {
                int read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0) return;
                total += read;
                if (total > maximumBytes) throw new InvalidDataException("Ответ сервера обновлений слишком большой.");
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private sealed record DownloadRequest(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("ticket")] string Ticket);

    private sealed record UpdateResponse(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("platform")] string Platform,
        [property: JsonPropertyName("current_version")] string CurrentVersion,
        [property: JsonPropertyName("current_code")] long CurrentCode,
        [property: JsonPropertyName("update_available")] bool UpdateAvailable,
        [property: JsonPropertyName("required")] bool Required,
        [property: JsonPropertyName("latest")] LatestRelease Latest);

    private sealed record LatestRelease(
        [property: JsonPropertyName("version_name")] string VersionName,
        [property: JsonPropertyName("version_code")] long VersionCode,
        [property: JsonPropertyName("minimum_supported_code")] long MinimumSupportedCode,
        [property: JsonPropertyName("download_method")] string DownloadMethod,
        [property: JsonPropertyName("download_path")] string DownloadPath,
        [property: JsonPropertyName("download_ticket")] string DownloadTicket,
        [property: JsonPropertyName("ticket_expires_in_seconds")] int TicketExpiresInSeconds,
        [property: JsonPropertyName("sha256")] string Sha256,
        [property: JsonPropertyName("size_bytes")] long SizeBytes,
        [property: JsonPropertyName("notes")] string Notes,
        [property: JsonPropertyName("published_at")] DateTimeOffset PublishedAt);
}

internal static class AppRelease
{
    public const string VersionName = "3.0.0";
    public const long VersionCode = 30000;
}

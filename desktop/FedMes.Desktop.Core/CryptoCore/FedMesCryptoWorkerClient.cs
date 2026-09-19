using System.Diagnostics;
using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FedMes.Desktop.Core.CryptoCore;

/// <summary>
/// Long-lived JSON-RPC bridge to the shared Go OPAQUE/Olm/Megolm core.
/// The worker is inherited by no child process, receives no command-line secrets,
/// and is terminated when the desktop client exits.
/// </summary>
public sealed class FedMesCryptoWorkerClient : IAsyncDisposable, IDisposable
{
    private const int MaximumResponseCharacters = 32 * 1024 * 1024;
    private readonly string _workerPath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private StreamWriter? _input;
    private StreamReader? _output;
    private bool _disposed;

    public FedMesCryptoWorkerClient(string? workerPath = null)
    {
        _workerPath = workerPath ?? ResolveWorkerPath();
    }

    private static string ResolveWorkerPath()
    {
        string adjacent = Path.Combine(AppContext.BaseDirectory, "fedmes-crypto-worker.exe");
        if (File.Exists(adjacent)) return adjacent;

        Assembly assembly = Assembly.GetEntryAssembly()
            ?? throw new CryptographicException("FedMes entry assembly is unavailable.");
        const string resourceName = "FedMes.Desktop.Assets.fedmes-crypto-worker.exe";
        using Stream resource = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException("FedMes embedded crypto worker is missing. Rebuild all targets.", resourceName);
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes", "crypto", "3.0.0-30000");
        Directory.CreateDirectory(directory);
        string destination = Path.Combine(directory, "fedmes-crypto-worker.exe");
        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";

        byte[] resourceBytes;
        using (var memory = new MemoryStream())
        {
            resource.CopyTo(memory);
            resourceBytes = memory.ToArray();
        }
        byte[] resourceHash = SHA256.HashData(resourceBytes);
        if (File.Exists(destination))
        {
            byte[] existingBytes = File.ReadAllBytes(destination);
            byte[] existingHash = SHA256.HashData(existingBytes);
            try
            {
                if (CryptographicOperations.FixedTimeEquals(resourceHash, existingHash))
                {
                    CryptographicOperations.ZeroMemory(resourceBytes);
                    CryptographicOperations.ZeroMemory(resourceHash);
                    return destination;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(existingBytes);
                CryptographicOperations.ZeroMemory(existingHash);
            }
        }

        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                output.Write(resourceBytes);
                output.Flush(flushToDisk: true);
            }
            byte[] writtenBytes = File.ReadAllBytes(temporary);
            byte[] writtenHash = SHA256.HashData(writtenBytes);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(resourceHash, writtenHash))
                    throw new CryptographicException("FedMes crypto worker extraction failed integrity verification.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(writtenBytes);
                CryptographicOperations.ZeroMemory(writtenHash);
            }
            File.Move(temporary, destination, overwrite: true);
            return destination;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(resourceBytes);
            CryptographicOperations.ZeroMemory(resourceHash);
            try { File.Delete(temporary); } catch (IOException) { }
        }
    }

    public async Task<string> InvokeAsync(string method, object parameters, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentNullException.ThrowIfNull(parameters);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureStarted();
            string id = Guid.NewGuid().ToString("N");
            byte[] requestBytes = JsonSerializer.SerializeToUtf8Bytes(new WorkerRequest(id, method, parameters), JsonOptions);
            try
            {
                string requestLine = Encoding.UTF8.GetString(requestBytes);
                await _input!.WriteLineAsync(requestLine.AsMemory(), cancellationToken).ConfigureAwait(false);
                await _input.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(requestBytes);
            }

            string? line = await _output!.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null || line.Length > MaximumResponseCharacters)
            {
                RestartAfterFailure();
                throw new CryptographicException("FedMes crypto worker stopped unexpectedly.");
            }
            WorkerResponse? response = JsonSerializer.Deserialize<WorkerResponse>(line, JsonOptions);
            if (response is null || !string.Equals(response.Id, id, StringComparison.Ordinal))
            {
                RestartAfterFailure();
                throw new CryptographicException("FedMes crypto worker returned an invalid response.");
            }
            if (!response.Ok)
            {
                throw new CryptographicException(response.Error ?? "FedMes crypto operation failed.");
            }
            return response.Value ?? string.Empty;
        }
        catch (OperationCanceledException)
        {
            RestartAfterFailure();
            throw;
        }
        catch (IOException)
        {
            RestartAfterFailure();
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<T> InvokeJsonAsync<T>(string method, object parameters, CancellationToken cancellationToken)
    {
        string json = await InvokeAsync(method, parameters, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(json, JsonOptions)
            ?? throw new CryptographicException("FedMes crypto result is empty.");
    }

    private void EnsureStarted()
    {
        if (_process is { HasExited: false }) return;
        if (!File.Exists(_workerPath))
        {
            throw new FileNotFoundException("FedMes shared crypto worker is missing. Rebuild the Windows client.", _workerPath);
        }
        var start = new ProcessStartInfo
        {
            FileName = _workerPath,
            WorkingDirectory = AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        start.Environment["GODEBUG"] = "madvdontneed=1";
        _process = Process.Start(start) ?? throw new CryptographicException("FedMes crypto worker could not start.");
        _input = _process.StandardInput;
        _output = _process.StandardOutput;
        _ = DrainStandardErrorAsync(_process.StandardError);
    }

    private static async Task DrainStandardErrorAsync(StreamReader reader)
    {
        char[] buffer = new char[1024];
        try
        {
            while (await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false) > 0)
            {
                Array.Clear(buffer);
            }
        }
        catch (ObjectDisposedException) { }
        catch (IOException) { }
        finally { Array.Clear(buffer); }
    }

    private void RestartAfterFailure()
    {
        try { _input?.Dispose(); } catch { }
        try { _output?.Dispose(); } catch { }
        if (_process is not null)
        {
            try { if (!_process.HasExited) _process.Kill(entireProcessTree: true); } catch { }
            _process.Dispose();
        }
        _input = null;
        _output = null;
        _process = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        RestartAfterFailure();
        _gate.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private sealed record WorkerRequest(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("method")] string Method,
        [property: JsonPropertyName("params")] object Parameters);

    private sealed record WorkerResponse(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("ok")] bool Ok,
        [property: JsonPropertyName("value")] string? Value,
        [property: JsonPropertyName("error")] string? Error);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
    };
}

public sealed record OpaqueStartResult(
    [property: JsonPropertyName("handle")] string Handle,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("suite")] string Suite);

public sealed record OpaqueFinishResult(
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("session_key")] string? SessionKey,
    [property: JsonPropertyName("export_key")] string ExportKey,
    [property: JsonPropertyName("suite")] string Suite);

public sealed record OlmAccountResult(
    [property: JsonPropertyName("pickle")] string Pickle,
    [property: JsonPropertyName("identity_keys")] string IdentityKeys,
    [property: JsonPropertyName("one_time_keys")] string OneTimeKeys);

public sealed record OlmEncryptedResult(
    [property: JsonPropertyName("pickle")] string Pickle,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("message_type")] int MessageType,
    [property: JsonPropertyName("ciphertext")] string Ciphertext);

public sealed record OlmDecryptedResult(
    [property: JsonPropertyName("account_pickle")] string? AccountPickle,
    [property: JsonPropertyName("session_pickle")] string SessionPickle,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("plaintext")] string Plaintext);

public sealed record MegolmOutboundResult(
    [property: JsonPropertyName("pickle")] string Pickle,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("session_key")] string SessionKey,
    [property: JsonPropertyName("message_index")] uint MessageIndex);

public sealed record MegolmEncryptedResult(
    [property: JsonPropertyName("pickle")] string Pickle,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("message_index")] uint MessageIndex,
    [property: JsonPropertyName("ciphertext")] string Ciphertext);

public sealed record MegolmDecryptedResult(
    [property: JsonPropertyName("pickle")] string Pickle,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("message_index")] uint MessageIndex,
    [property: JsonPropertyName("plaintext")] string Plaintext);

using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Media.Imaging;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.Services;

public sealed class MediaCacheService : IDisposable
{
    private readonly MessagingRepository _repository;
    private readonly string _directory;
    private readonly ConcurrentDictionary<string, Task<string>> _fileTasks = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Task<BitmapImage?>> _previewTasks = new(StringComparer.Ordinal);
    private bool _disposed;

    public MediaCacheService(MessagingRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _directory = Path.Combine(Path.GetTempPath(), "FedMes", "desktop-media", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
    }

    public async Task<BitmapImage?> GetPreviewAsync(
        DecryptedMessage message,
        MediaDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string key = $"{message.Id}:{descriptor.Preview?.Id ?? descriptor.Id}:preview";
        Task<BitmapImage?> task = _previewTasks.GetOrAdd(
            key,
            _ => LoadPreviewAsync(key, message, descriptor, cancellationToken));
        try
        {
            return await task.ConfigureAwait(false);
        }
        finally
        {
            // The tile owns the resulting frozen bitmap. Keeping every completed task here retained
            // all previews ever visited in a large chat and could exhaust the WPF process.
            if (_previewTasks.TryGetValue(key, out Task<BitmapImage?>? current) && ReferenceEquals(current, task))
            {
                _previewTasks.TryRemove(key, out _);
            }
        }
    }

    public async Task<string> GetDecryptedFileAsync(
        DecryptedMessage message,
        MediaDescriptor descriptor,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string key = $"{message.Id}:{descriptor.Id}";
        Task<string> task = _fileTasks.GetOrAdd(
            key,
            _ => DownloadFileAsync(message, descriptor, progress, cancellationToken));
        try
        {
            return await task.ConfigureAwait(false);
        }
        catch
        {
            if (_fileTasks.TryGetValue(key, out Task<string>? current) && ReferenceEquals(current, task))
            {
                _fileTasks.TryRemove(key, out _);
            }

            throw;
        }
    }

    public async Task SaveAsAsync(
        DecryptedMessage message,
        MediaDescriptor descriptor,
        string destination,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        string cached = await GetDecryptedFileAsync(message, descriptor, progress, cancellationToken).ConfigureAwait(false);
        await using FileStream source = File.OpenRead(cached);
        await using FileStream target = new(destination, FileMode.Create, FileAccess.Write, FileShare.None);
        await source.CopyToAsync(target, cancellationToken).ConfigureAwait(false);
    }

    private async Task<BitmapImage?> LoadPreviewAsync(
        string cacheKey,
        DecryptedMessage message,
        MediaDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        byte[]? bytes = null;
        string cachedPreviewPath = Path.Combine(_directory, $"preview-{HashKey(cacheKey)}.bin");
        try
        {
            if (File.Exists(cachedPreviewPath))
            {
                bytes = await File.ReadAllBytesAsync(cachedPreviewPath, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                bytes = await _repository.DownloadPreviewAsync(message.ChatId, message.Id, descriptor, cancellationToken)
                    .ConfigureAwait(false);
                if (bytes is null &&
                    descriptor.MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) &&
                    descriptor.OriginalSize <= MaximumInlinePreviewFallbackBytes)
                {
                    bytes = await _repository.DownloadAttachmentAsync(
                        message.ChatId,
                        message.Id,
                        descriptor,
                        null,
                        cancellationToken).ConfigureAwait(false);
                }
                if (bytes is not null)
                {
                    await File.WriteAllBytesAsync(cachedPreviewPath, bytes, cancellationToken).ConfigureAwait(false);
                }
            }

            if (bytes is null) return null;
            return DecodeImage(bytes);
        }
        catch (Exception error) when (error is IOException or NotSupportedException or System.Net.Http.HttpRequestException or CryptographicException)
        {
            return null;
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<string> DownloadFileAsync(
        DecryptedMessage message,
        MediaDescriptor descriptor,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        byte[] plaintext = await _repository.DownloadAttachmentAsync(
            message.ChatId,
            message.Id,
            descriptor,
            progress,
            cancellationToken).ConfigureAwait(false);
        string extension = Path.GetExtension(descriptor.Name);
        if (extension.Length > 12 || extension.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) extension = string.Empty;
        string path = Path.Combine(_directory, $"{message.Id}-{descriptor.Id}{extension}");
        try
        {
            await File.WriteAllBytesAsync(path, plaintext, cancellationToken).ConfigureAwait(false);
            return path;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static BitmapImage DecodeImage(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.CreateOptions = BitmapCreateOptions.IgnoreColorProfile;
        image.DecodePixelWidth = PreviewDecodePixelWidth;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    private static string HashKey(string value)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
        byte[] hash = SHA256.HashData(bytes);
        try
        {
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private const int PreviewDecodePixelWidth = 640;
    private const long MaximumInlinePreviewFallbackBytes = 16L * 1024 * 1024;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

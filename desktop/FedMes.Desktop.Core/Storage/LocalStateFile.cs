using System.Text;
using System.Security.Cryptography;

namespace FedMes.Desktop.Core.Storage;

internal static class LocalStateFile
{
    private static readonly UTF8Encoding Utf8WithoutBom = new(false, true);

    public static string ReadAllText(string path, long maximumBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumBytes, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumBytes, int.MaxValue - 1L);
        byte[] buffer = new byte[(int)maximumBytes + 1];
        int total = 0;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            while (total < buffer.Length)
            {
                int read = stream.Read(buffer, total, buffer.Length - total);
                if (read == 0)
                {
                    if (total == 0)
                    {
                        throw new InvalidDataException("The local FedMes state file is empty.");
                    }

                    return Utf8WithoutBom.GetString(buffer, 0, total);
                }

                total += read;
            }

            throw new InvalidDataException($"The local FedMes state file exceeds {maximumBytes} bytes.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static void WriteAllTextAtomic(string path, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(value);
        string directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("The local FedMes state path has no parent directory.");
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, Utf8WithoutBom, 4096, leaveOpen: true))
            {
                writer.Write(value);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            TryDelete(temporary);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }
}

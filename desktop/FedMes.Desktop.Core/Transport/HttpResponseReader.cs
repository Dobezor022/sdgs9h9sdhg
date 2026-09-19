using System.Text;
using System.Text.Json;

namespace FedMes.Desktop.Core.Transport;

internal static class HttpResponseReader
{
    public const int MaximumErrorBytes = 64 * 1024;

    public static async Task<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        JsonSerializerOptions options,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumBytes, 1);

        RejectOversizedContentLength(response, maximumBytes);
        await using Stream source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var bounded = new SizeLimitedReadStream(source, maximumBytes);
        T? result = await JsonSerializer.DeserializeAsync<T>(bounded, options, cancellationToken).ConfigureAwait(false);
        return result ?? throw new InvalidDataException("The FedMes server returned an empty JSON response.");
    }

    public static async Task<string> ReadErrorBodyAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Content.Headers.ContentLength is > MaximumErrorBytes)
        {
            return string.Empty;
        }

        await using Stream source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        byte[] buffer = new byte[MaximumErrorBytes + 1];
        int total = 0;
        try
        {
            while (total < buffer.Length)
            {
                int read = await source.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return Encoding.UTF8.GetString(buffer, 0, total);
                }

                total += read;
            }

            return string.Empty;
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    public static void RejectOversizedContentLength(HttpResponseMessage response, long maximumBytes)
    {
        long? contentLength = response.Content.Headers.ContentLength;
        if (contentLength is < 0 || contentLength > maximumBytes)
        {
            throw new InvalidDataException($"The FedMes response exceeds the {maximumBytes}-byte client limit.");
        }
    }

    private sealed class SizeLimitedReadStream(Stream inner, long maximumBytes) : Stream
    {
        private long _remaining = maximumBytes;

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            return Read(buffer.AsSpan(offset, count));
        }

        public override int Read(Span<byte> buffer)
        {
            int allowed = AllowedCount(buffer.Length);
            int read = inner.Read(buffer[..allowed]);
            AccountFor(read);
            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining == 0)
            {
                byte[] probe = new byte[1];
                int extra = await inner.ReadAsync(probe, cancellationToken).ConfigureAwait(false);
                if (extra > 0)
                {
                    throw new InvalidDataException("The FedMes response exceeded the client size limit.");
                }

                return 0;
            }

            int allowed = (int)Math.Min(buffer.Length, _remaining);
            int read = await inner.ReadAsync(buffer[..allowed], cancellationToken).ConfigureAwait(false);
            AccountFor(read);
            return read;
        }

        private int AllowedCount(int requested)
        {
            if (_remaining > 0)
            {
                return (int)Math.Min(requested, _remaining);
            }

            int extra = inner.ReadByte();
            if (extra >= 0)
            {
                throw new InvalidDataException("The FedMes response exceeded the client size limit.");
            }

            return 0;
        }

        private void AccountFor(int read)
        {
            _remaining -= read;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
    }
}

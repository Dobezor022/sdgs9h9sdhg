using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http.Headers;

namespace FedMes.Desktop.Core.Transport2;

/// <summary>Two independent HTTP/2 streams carrying only encrypted realtime frames.</summary>
public sealed class RealtimeStreamClient : IAsyncDisposable
{
    private readonly HttpClient _http;
    private readonly bool _owns;
    private Pipe? _uplinkPipe;
    private Task<HttpResponseMessage>? _uplinkRequest;

    public RealtimeStreamClient(HttpClient? http=null)
    {
        _owns=http is null;
        _http=http??new HttpClient(new SocketsHttpHandler{EnableMultipleHttp2Connections=true,PooledConnectionLifetime=TimeSpan.FromMinutes(10)}){Timeout=Timeout.InfiniteTimeSpan};
    }

    public async Task OpenUplinkAsync(Uri server,string capability,CancellationToken ct)
    {
        if(_uplinkPipe is not null)throw new InvalidOperationException("uplink already open");
        _uplinkPipe=new Pipe(new PipeOptions(pauseWriterThreshold:512*1024,resumeWriterThreshold:128*1024,useSynchronizationContext:false));
        var content=new StreamContent(_uplinkPipe.Reader.AsStream());content.Headers.ContentType=new MediaTypeHeaderValue("application/octet-stream");
        var req=New(HttpMethod.Post,new Uri(server,"/api/v4/stream"),capability);req.Content=content;
        _uplinkRequest=_http.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,ct);
        await Task.Yield();
    }

    public async ValueTask SendFrameAsync(ReadOnlyMemory<byte> frame,CancellationToken ct)
    {
        if(_uplinkPipe is null)throw new InvalidOperationException("uplink is not open");
        if(frame.Length is <1 or >256*1024)throw new ArgumentOutOfRangeException(nameof(frame));
        Memory<byte> target=_uplinkPipe.Writer.GetMemory(4+frame.Length);BinaryPrimitives.WriteUInt32BigEndian(target.Span[..4],(uint)frame.Length);frame.CopyTo(target[4..]);_uplinkPipe.Writer.Advance(4+frame.Length);var flush=await _uplinkPipe.Writer.FlushAsync(ct).ConfigureAwait(false);if(flush.IsCanceled||flush.IsCompleted)throw new IOException("FedMes realtime uplink closed");
    }

    public async Task ReceiveLoopAsync(Uri server,string capability,Func<ReadOnlyMemory<byte>,ValueTask> onFrame,CancellationToken ct)
    {
        using var req=New(HttpMethod.Get,new Uri(server,"/api/v4/stream"),capability);req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using var resp=await _http.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,ct).ConfigureAwait(false);resp.EnsureSuccessStatusCode();await using Stream input=await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        byte[] length=new byte[4];try{while(!ct.IsCancellationRequested){await ReadExactlyAsync(input,length,ct).ConfigureAwait(false);int n=checked((int)BinaryPrimitives.ReadUInt32BigEndian(length));if(n is <1 or >256*1024)throw new IOException("invalid FedMes realtime frame");byte[] frame=GC.AllocateUninitializedArray<byte>(n);try{await ReadExactlyAsync(input,frame,ct).ConfigureAwait(false);await onFrame(frame).ConfigureAwait(false);}finally{System.Security.Cryptography.CryptographicOperations.ZeroMemory(frame);}}}finally{Array.Clear(length);}
    }

    private static async Task ReadExactlyAsync(Stream stream,Memory<byte> buffer,CancellationToken ct){int off=0;while(off<buffer.Length){int n=await stream.ReadAsync(buffer[off..],ct).ConfigureAwait(false);if(n==0)throw new EndOfStreamException();off+=n;}}
    private static HttpRequestMessage New(HttpMethod method,Uri uri,string capability){var r=new HttpRequestMessage(method,uri){Version=HttpVersion.Version20,VersionPolicy=HttpVersionPolicy.RequestVersionOrHigher};r.Headers.TryAddWithoutValidation("X-Object-Capability",capability);r.Headers.CacheControl=new(){NoStore=true};return r;}

    public async ValueTask DisposeAsync(){if(_uplinkPipe is not null){await _uplinkPipe.Writer.CompleteAsync().ConfigureAwait(false);await _uplinkPipe.Reader.CompleteAsync().ConfigureAwait(false);_uplinkPipe=null;}if(_uplinkRequest is not null){try{using var r=await _uplinkRequest.ConfigureAwait(false);}catch{} _uplinkRequest=null;}if(_owns)_http.Dispose();}
}

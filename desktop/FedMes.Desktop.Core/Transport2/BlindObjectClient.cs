using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace FedMes.Desktop.Core.Transport2;

public sealed class BlindObjectClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _owns;
    public BlindObjectClient(HttpClient? http = null)
    {
        _owns = http is null;
        _http = http ?? new HttpClient(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(10), EnableMultipleHttp2Connections = true });
        _http.Timeout = TimeSpan.FromSeconds(30);
    }

    public static string RouteDigest(ReadOnlySpan<byte> capability) => RawUrl(SHA256.HashData(capability));
    public static string RandomObjectId() { Span<byte> b = stackalloc byte[16]; RandomNumberGenerator.Fill(b); return RawUrl(b); }

    public async Task RegisterRouteAsync(Uri server, string sessionToken, string routeDigest, long generation, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Put, new Uri(server, "/api/v4/object/route"));
        req.Headers.Authorization = new("Bearer", sessionToken);
        req.Content = JsonContent.Create(new { version=1, route_digest=routeDigest, generation, lifetime_seconds=86400, max_object_bytes=2*1024*1024, max_pending_objects=512 });
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false); resp.EnsureSuccessStatusCode();
    }

    public async Task PutAsync(Uri server, string capability, string objectId, int lengthClass, string ciphertext, CancellationToken ct)
    {
        using var req = New(HttpMethod.Post, new Uri(server,"/api/v4/object"), capability);
        req.Content = JsonContent.Create(new { version=1, object_id=objectId, length_class=lengthClass, ciphertext, lifetime_seconds=259200 });
        using var resp = await _http.SendAsync(req,ct).ConfigureAwait(false); resp.EnsureSuccessStatusCode();
    }

    public async Task<IReadOnlyList<BlindObject>> PullAsync(Uri server, string capability, int limit, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit,1); ArgumentOutOfRangeException.ThrowIfGreaterThan(limit,256);
        using var req = New(HttpMethod.Get,new Uri(server,$"/api/v4/object?limit={limit}"),capability);
        using var resp = await _http.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,ct).ConfigureAwait(false);resp.EnsureSuccessStatusCode();
        var result = await resp.Content.ReadFromJsonAsync<BlindObjectList>(cancellationToken:ct).ConfigureAwait(false);
        return result?.Objects ?? Array.Empty<BlindObject>();
    }

    public async Task AckAsync(Uri server,string capability,string objectId,CancellationToken ct)
    {
        using var req=New(HttpMethod.Delete,new Uri(server,"/api/v4/object/"+Uri.EscapeDataString(objectId)),capability);
        using var resp=await _http.SendAsync(req,ct).ConfigureAwait(false);if(resp.StatusCode!=HttpStatusCode.NotFound)resp.EnsureSuccessStatusCode();
    }

    private static HttpRequestMessage New(HttpMethod method,Uri uri,string capability){var r=new HttpRequestMessage(method,uri);r.Headers.TryAddWithoutValidation("X-Object-Capability",capability);r.Headers.CacheControl=new(){NoStore=true};return r;}
    private static string RawUrl(ReadOnlySpan<byte> value)=>Convert.ToBase64String(value).TrimEnd('=').Replace('+','-').Replace('/','_');
    public void Dispose(){if(_owns)_http.Dispose();}
}

public sealed record BlindObject([property:JsonPropertyName("object_id")]string ObjectId,[property:JsonPropertyName("length_class")]int LengthClass,[property:JsonPropertyName("ciphertext")]string Ciphertext);
public sealed record BlindObjectList([property:JsonPropertyName("objects")]BlindObject[] Objects);

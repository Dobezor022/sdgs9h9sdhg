using System.Net;
using System.Text;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Tests.Messaging;

[TestClass]
public sealed class MessagingApiClientTests
{
    private static readonly DesktopAccount HttpsAccount = new(
        "https://fedmes.example",
        "grisha",
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "test-session-token",
        DateTimeOffset.UtcNow.AddMinutes(15),
        "Desktop test");

    [TestMethod]
    public async Task ConstructorDoesNotMutateAnInjectedHttpClientAfterUse()
    {
        using var http = new HttpClient(new DelegateHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent))));
        http.Timeout = TimeSpan.FromSeconds(11);
        using (HttpResponseMessage response = await http.GetAsync("https://fedmes.example/healthz"))
        {
            Assert.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
        }

        using var client = new MessagingApiClient(http);

        Assert.AreEqual(TimeSpan.FromSeconds(11), http.Timeout);
    }

    [TestMethod]
    public async Task RemoteCleartextAccountIsRejectedBeforeSendingItsBearerToken()
    {
        int requestCount = 0;
        using var http = new HttpClient(new DelegateHandler((_, _) =>
        {
            requestCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }));
        using var client = new MessagingApiClient(
            http,
            ServerEndpointMode.PrototypePrivateNetwork);
        DesktopAccount unsafeAccount = HttpsAccount with { ServerUrl = "http://8.8.8.8:8008" };

        await Assert.ThrowsExactlyAsync<ServerEndpointPolicyException>(() =>
            client.ListChatsAsync(unsafeAccount, CancellationToken.None));

        Assert.AreEqual(0, requestCount);
    }

    [TestMethod]
    public async Task PrototypeModeAllowsABoundedLiteralPrivateNetworkRequest()
    {
        int requestCount = 0;
        using var http = new HttpClient(new DelegateHandler((request, _) =>
        {
            requestCount++;
            Assert.AreEqual("192.168.1.5", request.RequestUri!.Host);
            Assert.AreEqual("Bearer", request.Headers.Authorization!.Scheme);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"version\":1,\"chats\":[]}", Encoding.UTF8, "application/json"),
            });
        }));
        using var client = new MessagingApiClient(
            http,
            ServerEndpointMode.PrototypePrivateNetwork);
        DesktopAccount privateAccount = HttpsAccount with { ServerUrl = "http://192.168.1.5:8008" };

        IReadOnlyList<ChatSummary> chats = await client.ListChatsAsync(privateAccount, CancellationToken.None);

        Assert.AreEqual(0, chats.Count);
        Assert.AreEqual(1, requestCount);
    }

    [TestMethod]
    public async Task OversizedJsonContentLengthIsRejectedWithoutReadingTheBody()
    {
        var body = new HeaderOnlyContent(64L * 1024 * 1024 + 1);
        using var http = new HttpClient(new DelegateHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = body })));
        using var client = new MessagingApiClient(http);

        await Assert.ThrowsExactlyAsync<InvalidDataException>(() =>
            client.ListChatsAsync(HttpsAccount, CancellationToken.None));

        Assert.AreEqual(0, body.SerializeCount);
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => callback(request, cancellationToken);
    }

    private sealed class HeaderOnlyContent(long contentLength) : HttpContent
    {
        public int SerializeCount { get; private set; }

        protected override bool TryComputeLength(out long length)
        {
            length = contentLength;
            return true;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            SerializeCount++;
            return Task.CompletedTask;
        }
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Security;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Tests.Transport;

[TestClass]
public sealed class DeviceLinkClientTests
{
    private static readonly Uri LoopbackServer = new("http://127.0.0.1:8008");

    [TestMethod]
    public async Task ConstructorDoesNotMutateAnInjectedHttpClientAfterUse()
    {
        using var http = new HttpClient(new DelegateHandler((_, _) =>
            Task.FromResult(JsonResponse(HttpStatusCode.OK, new { version = 1 }))));
        http.Timeout = TimeSpan.FromSeconds(7);
        using (HttpResponseMessage response = await http.GetAsync("https://fedmes.example/healthz"))
        {
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        using var client = new DeviceLinkClient(http);

        Assert.AreEqual(TimeSpan.FromSeconds(7), http.Timeout);
    }

    [TestMethod]
    public async Task ApprovedLinkIsNotAcknowledgedBeforeTheCallerPersistsTheAccount()
    {
        string root = CreateTestDirectory();
        try
        {
            using DesktopDeviceIdentity identity = CreateIdentity(root);
            byte[] token = RandomNumberGenerator.GetBytes(32);
            byte[] encrypted = EncryptForIdentity(identity, token);
            int requestCount = 0;
            using var http = new HttpClient(new DelegateHandler((request, _) =>
            {
                requestCount++;
                Assert.IsTrue(request.RequestUri!.AbsolutePath.EndsWith("/status", StringComparison.Ordinal));
                return Task.FromResult(JsonResponse(HttpStatusCode.OK, new
                {
                    version = 1,
                    status = "approved",
                    username = "grisha",
                    device_id = "11111111-1111-4111-8111-111111111111",
                    session_id = "22222222-2222-4222-8222-222222222222",
                    encrypted_session_token = Convert.ToBase64String(encrypted),
                    session_expires_at = DateTimeOffset.UtcNow.AddMinutes(15),
                }));
            }));
            using var client = new DeviceLinkClient(http);
            var ticket = new DeviceLinkTicket(
                "33333333-3333-4333-8333-333333333333",
                RawBase64Url(RandomNumberGenerator.GetBytes(32)),
                [],
                DateTimeOffset.UtcNow.AddMinutes(2));

            DesktopAccount account = await client.WaitForApprovalAsync(
                LoopbackServer,
                ticket,
                identity,
                "Desktop test",
                null,
                CancellationToken.None);

            Assert.AreEqual(1, requestCount, "The /complete endpoint must not run before account persistence succeeds.");
            Assert.AreEqual(RawBase64Url(token), account.SessionToken);
            CryptographicOperations.ZeroMemory(token);
            CryptographicOperations.ZeroMemory(encrypted);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public async Task AcknowledgeTreatsOnlyAlreadyConsumedAsIdempotentSuccess()
    {
        var responses = new Queue<HttpResponseMessage>(
        [
            ErrorResponse(HttpStatusCode.Conflict, "device_link_used"),
            ErrorResponse(HttpStatusCode.Conflict, "device_link_conflict"),
        ]);
        using var http = new HttpClient(new DelegateHandler((_, _) => Task.FromResult(responses.Dequeue())));
        using var client = new DeviceLinkClient(http);
        var ticket = new DeviceLinkTicket(
            "33333333-3333-4333-8333-333333333333",
            RawBase64Url(RandomNumberGenerator.GetBytes(32)),
            [],
            DateTimeOffset.UtcNow.AddMinutes(2));

        await client.AcknowledgeCompletedLinkAsync(LoopbackServer, ticket, CancellationToken.None);
        HttpRequestException error = await Assert.ThrowsExactlyAsync<HttpRequestException>(() =>
            client.AcknowledgeCompletedLinkAsync(LoopbackServer, ticket, CancellationToken.None));

        Assert.AreEqual(HttpStatusCode.Conflict, error.StatusCode);
    }

    [TestMethod]
    public Task RefreshSessionVerifiesChallengeSignatureAndResponseContext() =>
        VerifySuccessfulRefreshAsync(LoopbackServer, ServerEndpointMode.Production);

    [TestMethod]
    public Task PrototypeModeRefreshesALegacyPrivateNetworkAccount() =>
        VerifySuccessfulRefreshAsync(
            new Uri("http://192.168.1.5:8008"),
            ServerEndpointMode.PrototypePrivateNetwork);

    private static async Task VerifySuccessfulRefreshAsync(Uri server, ServerEndpointMode endpointMode)
    {
        string root = CreateTestDirectory();
        try
        {
            using DesktopDeviceIdentity identity = CreateIdentity(root);
            string deviceId = "11111111-1111-4111-8111-111111111111";
            string challengeId = "22222222-2222-4222-8222-222222222222";
            string nonce = RawBase64Url(RandomNumberGenerator.GetBytes(32));
            string refreshedToken = RawBase64Url(RandomNumberGenerator.GetBytes(32));
            DateTimeOffset issuedAt = DateTimeOffset.UtcNow;
            string fingerprint = Fingerprint(identity.IdentityPublicKeySpkiBase64);
            string audience = ServerEndpointPolicy.AuthenticationAudience(server, endpointMode);
            int requestCount = 0;
            using var http = new HttpClient(new DelegateHandler(async (request, cancellationToken) =>
            {
                requestCount++;
                if (request.RequestUri!.AbsolutePath.EndsWith("/challenge", StringComparison.Ordinal))
                {
                    return JsonResponse(HttpStatusCode.Created, new
                    {
                        version = 1,
                        challenge = new
                        {
                            id = challengeId,
                            device_id = deviceId,
                            audience,
                            purpose = "session.refresh",
                            nonce,
                            expires_at = DateTimeOffset.UtcNow.AddSeconds(10),
                        },
                    });
                }

                string requestJson = await request.Content!.ReadAsStringAsync(cancellationToken);
                using JsonDocument document = JsonDocument.Parse(requestJson);
                string signatureBase64 = document.RootElement.GetProperty("signature").GetString()!;
                byte[] canonical = Encoding.UTF8.GetBytes(string.Join('\n',
                    "fedmes-device-auth-v1",
                    audience,
                    "grisha",
                    deviceId,
                    challengeId,
                    "session.refresh",
                    nonce));
                byte[] signature = Convert.FromBase64String(signatureBase64);
                byte[] publicKey = Convert.FromBase64String(identity.IdentityPublicKeySpkiBase64);
                try
                {
                    using ECDsa verifier = ECDsa.Create();
                    verifier.ImportSubjectPublicKeyInfo(publicKey, out _);
                    Assert.IsTrue(verifier.VerifyData(
                        canonical,
                        signature,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.Rfc3279DerSequence));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(canonical);
                    CryptographicOperations.ZeroMemory(signature);
                    CryptographicOperations.ZeroMemory(publicKey);
                }

                return JsonResponse(HttpStatusCode.Created, new
                {
                    version = 1,
                    device = new
                    {
                        id = deviceId,
                        username = "grisha",
                        key_algorithm = DesktopDeviceIdentity.IdentityAlgorithm,
                        key_fingerprint = fingerprint,
                    },
                    session = new
                    {
                        id = "44444444-4444-4444-8444-444444444444",
                        token = refreshedToken,
                        issued_at = issuedAt,
                        expires_at = issuedAt.AddMinutes(15),
                    },
                });
            }));
            using var client = new DeviceLinkClient(http, endpointMode);
            var account = new DesktopAccount(
                server.AbsoluteUri,
                "grisha",
                deviceId,
                "55555555-5555-4555-8555-555555555555",
                RawBase64Url(RandomNumberGenerator.GetBytes(32)),
                DateTimeOffset.UtcNow.AddSeconds(1),
                "Desktop test");

            DesktopAccount refreshed = await client.RefreshSessionAsync(account, identity, CancellationToken.None);

            Assert.AreEqual(2, requestCount);
            Assert.AreEqual(refreshedToken, refreshed.SessionToken);
            Assert.AreEqual("44444444-4444-4444-8444-444444444444", refreshed.SessionId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public async Task PrototypeModeRejectsPublicLegacyEndpointBeforeSendingIdentityRequest()
    {
        string root = CreateTestDirectory();
        try
        {
            using DesktopDeviceIdentity identity = CreateIdentity(root);
            int requestCount = 0;
            using var http = new HttpClient(new DelegateHandler((_, _) =>
            {
                requestCount++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
            }));
            using var client = new DeviceLinkClient(http, ServerEndpointMode.PrototypePrivateNetwork);
            var account = new DesktopAccount(
                "http://8.8.8.8:8008",
                "grisha",
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                RawBase64Url(RandomNumberGenerator.GetBytes(32)),
                DateTimeOffset.UtcNow.AddSeconds(1),
                "Desktop test");

            await Assert.ThrowsExactlyAsync<ServerEndpointPolicyException>(() =>
                client.RefreshSessionAsync(account, identity, CancellationToken.None));

            Assert.AreEqual(0, requestCount, "A blocked endpoint must fail before a bearer token or identity request is sent.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static DesktopDeviceIdentity CreateIdentity(string root)
    {
        var store = new DesktopDeviceIdentityStore(new CopyProtector(), Path.Combine(root, "identity.json"));
        return store.LoadOrCreate();
    }

    private static byte[] EncryptForIdentity(DesktopDeviceIdentity identity, byte[] plaintext)
    {
        byte[] publicKey = Convert.FromBase64String(identity.EncryptionPublicKeySpkiBase64);
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
            return rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static string Fingerprint(string publicKeyBase64)
    {
        byte[] publicKey = Convert.FromBase64String(publicKeyBase64);
        byte[] digest = SHA256.HashData(publicKey);
        try
        {
            return Convert.ToHexString(digest).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode statusCode, object body) => new(statusCode)
    {
        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
    };

    private static HttpResponseMessage ErrorResponse(HttpStatusCode statusCode, string code) =>
        JsonResponse(statusCode, new { version = 1, error = new { code } });

    private static string RawBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string CreateTestDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => callback(request, cancellationToken);
    }

    private sealed class CopyProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext) => plaintext.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedData) => protectedData.ToArray();
    }
}

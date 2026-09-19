using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Tests.Transport;

[TestClass]
public sealed class ServerEndpointPolicyTests
{
    [TestMethod]
    [DataRow("https://fedmes.example", "https://fedmes.example/")]
    [DataRow("https://FEDMES.example:8443/", "https://fedmes.example:8443/")]
    [DataRow("http://127.0.0.1:8008", "http://127.0.0.1:8008/")]
    [DataRow("http://localhost:8008/", "http://localhost:8008/")]
    public void NormalizeAcceptsHttpsAndLoopbackDevelopmentHttp(string input, string expected)
    {
        Assert.AreEqual(expected, ServerEndpointPolicy.Normalize(input).AbsoluteUri);
    }

    [TestMethod]
    [DataRow("http://fedmes.example")]
    [DataRow("http://192.168.1.5:8008")]
    [DataRow("https://user:password@fedmes.example")]
    [DataRow("https://fedmes.example/api")]
    [DataRow("https://fedmes.example?token=value")]
    [DataRow("https://fedmes.example/#fragment")]
    public void NormalizeRejectsUnsafeOrigins(string input)
    {
        Assert.ThrowsExactly<ServerEndpointPolicyException>(() => ServerEndpointPolicy.Normalize(input));
    }

    [TestMethod]
    [DataRow("http://10.0.0.1:8008")]
    [DataRow("http://127.0.0.1:8008")]
    [DataRow("http://172.16.0.1:8008")]
    [DataRow("http://172.31.255.254:8008")]
    [DataRow("http://192.168.1.5:8008")]
    [DataRow("http://169.254.10.20:8008")]
    [DataRow("http://[::1]:8008")]
    [DataRow("http://[fd00::1]:8008")]
    [DataRow("http://[fe80::1]:8008")]
    public void PrototypeModeAcceptsOnlyLiteralPrivateOrLinkLocalHttp(string input)
    {
        Uri result = ServerEndpointPolicy.Normalize(input, ServerEndpointMode.PrototypePrivateNetwork);

        Assert.AreEqual(Uri.UriSchemeHttp, result.Scheme);
    }

    [TestMethod]
    [DataRow("http://8.8.8.8:8008")]
    [DataRow("http://localhost:8008")]
    [DataRow("http://fedmes.example:8008")]
    [DataRow("http://0.0.0.0:8008")]
    [DataRow("http://224.0.0.1:8008")]
    [DataRow("http://[2001:4860:4860::8888]:8008")]
    public void PrototypeModeStillRejectsPublicHostnameAndUnspecifiedHttp(string input)
    {
        Assert.ThrowsExactly<ServerEndpointPolicyException>(() =>
            ServerEndpointPolicy.Normalize(input, ServerEndpointMode.PrototypePrivateNetwork));
    }

    [TestMethod]
    public void AuthenticationAudienceMatchesServerHostContract()
    {
        Assert.AreEqual(
            "fedmes.example:8443",
            ServerEndpointPolicy.AuthenticationAudience(new Uri("https://FEDMES.example:8443")));
        Assert.AreEqual(
            "[::1]:8008",
            ServerEndpointPolicy.AuthenticationAudience(new Uri("http://[::1]:8008")));
    }
}

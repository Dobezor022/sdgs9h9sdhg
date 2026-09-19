using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace FedMes.Desktop.Core.Transport;

public enum ServerEndpointMode
{
    Production,
    PrototypePrivateNetwork,
}

public sealed class ServerEndpointPolicyException : ArgumentException
{
    public ServerEndpointPolicyException(string message, string parameterName)
        : base(message, parameterName)
    {
    }
}

public static class ServerEndpointPolicy
{
    public static Uri Normalize(
        string value,
        ServerEndpointMode mode = ServerEndpointMode.Production)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ServerEndpointPolicyException("The FedMes server URL is required.", nameof(value));
        }

        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode));
        }

        string candidate = value.Trim().TrimEnd('/');
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            uri.AbsolutePath != "/" ||
            uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 ||
            uri.Port is < 1 or > 65535)
        {
            throw new ServerEndpointPolicyException(
                "The FedMes server URL must be an HTTP(S) origin without credentials, path, query, or fragment.",
                nameof(value));
        }

        if (uri.Scheme == Uri.UriSchemeHttp && !IsAllowedCleartextEndpoint(uri, mode))
        {
            throw new ServerEndpointPolicyException(
                mode == ServerEndpointMode.PrototypePrivateNetwork
                    ? "Prototype cleartext HTTP is allowed only for literal loopback, private, or link-local addresses. Use HTTPS for other servers."
                    : "Cleartext HTTP is allowed only for a loopback development server. Use HTTPS for remote servers.",
                nameof(value));
        }

        return new Uri(uri.GetLeftPart(UriPartial.Authority), UriKind.Absolute);
    }

    public static Uri Build(
        Uri server,
        string absolutePath,
        ServerEndpointMode mode = ServerEndpointMode.Production)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentException.ThrowIfNullOrWhiteSpace(absolutePath);
        if (!absolutePath.StartsWith('/') || absolutePath.StartsWith("//", StringComparison.Ordinal))
        {
            throw new ArgumentException("An API path must be absolute and cannot contain an authority.", nameof(absolutePath));
        }

        Uri normalized = Normalize(server.AbsoluteUri, mode);
        return new Uri(normalized, absolutePath);
    }

    public static string AuthenticationAudience(
        Uri server,
        ServerEndpointMode mode = ServerEndpointMode.Production)
    {
        Uri normalized = Normalize(server.AbsoluteUri, mode);
        string host = normalized.IdnHost.ToLower(CultureInfo.InvariantCulture);
        if (host.Contains(':', StringComparison.Ordinal))
        {
            host = $"[{host}]";
        }

        return normalized.IsDefaultPort ? host : $"{host}:{normalized.Port}";
    }

    private static bool IsAllowedCleartextEndpoint(Uri uri, ServerEndpointMode mode)
    {
        if (mode == ServerEndpointMode.Production)
        {
            return uri.IsLoopback;
        }

        if (mode != ServerEndpointMode.PrototypePrivateNetwork ||
            !IPAddress.TryParse(uri.IdnHost, out IPAddress? address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork =>
                bytes[0] == 10 ||
                (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                (bytes[0] == 192 && bytes[1] == 168) ||
                (bytes[0] == 169 && bytes[1] == 254),
            AddressFamily.InterNetworkV6 =>
                (bytes[0] & 0xfe) == 0xfc ||
                (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80),
            _ => false,
        };
    }
}

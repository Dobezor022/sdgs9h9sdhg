using System.Collections.ObjectModel;

namespace FedMes.Desktop.Core.Domain;

public static class FixedFamilyUsers
{
    private static readonly string[] UserNames =
    [
        "grisha",
        "papa",
        "mama",
        "yura",
        "vasya",
    ];

    private static readonly HashSet<string> AllowedUserNames =
        new(UserNames, StringComparer.Ordinal);

    public static ReadOnlyCollection<string> All { get; } = Array.AsReadOnly(UserNames);

    public static bool IsAllowed(string? userName) =>
        userName is not null && AllowedUserNames.Contains(userName);

    public static string RequireAllowed(string userName)
    {
        ArgumentNullException.ThrowIfNull(userName);

        if (!IsAllowed(userName))
        {
            throw new ArgumentException("The user is not a member of the fixed FedMes family.", nameof(userName));
        }

        return userName;
    }
}

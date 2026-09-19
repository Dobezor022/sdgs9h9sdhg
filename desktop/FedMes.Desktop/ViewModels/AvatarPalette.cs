using System.Windows;
using System.Windows.Media;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.ViewModels;

internal static class AvatarPalette
{
    private static readonly Brush Blue = CreateGradient(0x2A, 0xAB, 0xEE, 0x38, 0x67, 0xD6);
    private static readonly Brush Green = CreateGradient(0x39, 0xB9, 0x82, 0x22, 0xA6, 0xB3);
    private static readonly Brush Orange = CreateGradient(0xFF, 0x9F, 0x43, 0xEE, 0x52, 0x53);
    private static readonly Brush Purple = CreateGradient(0x88, 0x54, 0xD0, 0x38, 0x67, 0xD6);
    private static readonly Brush Gray = CreateGradient(0x77, 0x88, 0x99, 0x46, 0x57, 0x68);

    public static Brush ForUser(string? username) => username?.ToLowerInvariant() switch
    {
        "grisha" => Blue,
        "papa" => Green,
        "mama" => Orange,
        "yura" => Purple,
        "vasya" => Blue,
        "family" => Green,
        _ => Gray,
    };

    public static Brush ForChat(ChatSummary chat, string currentUsername)
    {
        ArgumentNullException.ThrowIfNull(chat);
        string avatarOwner = chat.Kind switch
        {
            "favorites" => currentUsername,
            "family" => "family",
            _ => chat.Members.FirstOrDefault(member =>
                    !string.Equals(member, currentUsername, StringComparison.Ordinal))
                ?? chat.Title,
        };
        return ForUser(avatarOwner);
    }

    private static LinearGradientBrush CreateGradient(
        byte firstRed,
        byte firstGreen,
        byte firstBlue,
        byte secondRed,
        byte secondGreen,
        byte secondBlue)
    {
        var brush = new LinearGradientBrush(
            Color.FromRgb(firstRed, firstGreen, firstBlue),
            Color.FromRgb(secondRed, secondGreen, secondBlue),
            new Point(0, 0),
            new Point(1, 1));
        brush.Freeze();
        return brush;
    }
}

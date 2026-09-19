using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace FedMes.Desktop.Services;

public static class DesktopThemeManager
{
    public static bool IsDark(DesktopThemeMode mode) => mode switch
    {
        DesktopThemeMode.Dark => true,
        DesktopThemeMode.Light => false,
        _ => IsWindowsAppsDark(),
    };

    public static void Apply(DesktopThemeMode mode)
    {
        Application? application = Application.Current;
        if (application is null) return;

        bool dark = IsDark(mode);
        SetColor(application, "FedMesAccentBrush", "#3390EC");
        SetColor(application, "FedMesAccentHoverBrush", "#2B7FC6");
        SetColor(application, "FedMesDangerBrush", "#E14B4B");
        SetColor(application, "FedMesOnlineBrush", "#31B77A");
        SetColor(application, "FedMesWarningBrush", "#E8A33A");
        SetColor(application, "FedMesQuoteMarksBrush", "#66727C");
        SetColor(application, "FedMesAckBrush", "#3B88C3");
        SetColor(application, "FedMesPendingBrush", "#8E8E93");

        if (dark)
        {
            SetColor(application, "FedMesBackgroundBrush", "#0E1621");
            SetColor(application, "FedMesSurfaceBrush", "#17212B");
            SetColor(application, "FedMesSecondarySurfaceBrush", "#202B36");
            SetColor(application, "FedMesPrimaryTextBrush", "#F4F7FA");
            SetColor(application, "FedMesSecondaryTextBrush", "#8E9DAA");
            SetColor(application, "FedMesDividerBrush", "#2B3A48");
            SetColor(application, "FedMesIncomingBubbleBrush", "#182533");
            SetColor(application, "FedMesOutgoingBubbleBrush", "#2B5278");
            SetColor(application, "FedMesChatBackgroundBrush", "#0E1621");
            SetColor(application, "FedMesHoverBrush", "#202B36");
            SetColor(application, "FedMesNameTextBrush", "#FFFFFF");
            SetColor(application, "FedMesQuoteBackgroundBrush", "#E2E5E8");
            SetColor(application, "FedMesQuoteBarBrush", "#F8F9FA");
            SetColor(application, "FedMesFormattingSurfaceBrush", "#17212B");
            SetColor(application, "FedMesFormattingBorderBrush", "#14527A");
            SetColor(application, "FedMesFormattingTextBrush", "#FFFFFF");
            SetColor(application, "FedMesOverlayBrush", "#B0000000");
            SetColor(application, "FedMesMessageMetaBrush", "#FFFFFF");
            SetColor(application, "FedMesMessageMetaOverlayBrush", "#99000000");
            SetColor(application, "FedMesMessageTextBrush", "#F4F7FA");
            SetColor(application, "FedMesSelectedBrush", "#202B36");
        }
        else
        {
            SetColor(application, "FedMesBackgroundBrush", "#F4F7FA");
            SetColor(application, "FedMesSurfaceBrush", "#FFFFFF");
            SetColor(application, "FedMesSecondarySurfaceBrush", "#EDF2F6");
            SetColor(application, "FedMesPrimaryTextBrush", "#17212B");
            SetColor(application, "FedMesSecondaryTextBrush", "#70808D");
            SetColor(application, "FedMesDividerBrush", "#DCE5EC");
            SetColor(application, "FedMesIncomingBubbleBrush", "#FFFFFF");
            SetColor(application, "FedMesOutgoingBubbleBrush", "#E1FFC7");
            SetColor(application, "FedMesChatBackgroundBrush", "#F4F7FA");
            SetColor(application, "FedMesHoverBrush", "#EDF2F6");
            SetColor(application, "FedMesNameTextBrush", "#111111");
            SetColor(application, "FedMesQuoteBackgroundBrush", "#D9DDE1");
            SetColor(application, "FedMesQuoteBarBrush", "#F7F8F9");
            SetColor(application, "FedMesFormattingSurfaceBrush", "#FFFFFF");
            SetColor(application, "FedMesFormattingBorderBrush", "#79C8F2");
            SetColor(application, "FedMesFormattingTextBrush", "#111111");
            SetColor(application, "FedMesOverlayBrush", "#99000000");
            SetColor(application, "FedMesMessageMetaBrush", "#000000");
            SetColor(application, "FedMesMessageMetaOverlayBrush", "#CCFFFFFF");
            SetColor(application, "FedMesMessageTextBrush", "#17212B");
            SetColor(application, "FedMesSelectedBrush", "#EDF2F6");
        }
    }

    private static void SetColor(Application application, string key, string hex)
    {
        object? parsed = ColorConverter.ConvertFromString(hex);
        if (parsed is not Color color) throw new FormatException($"Некорректный цвет темы: {hex}");
        if (application.Resources[key] is SolidColorBrush brush && !brush.IsFrozen)
        {
            brush.Color = color;
        }
        else
        {
            application.Resources[key] = new SolidColorBrush(color);
        }
    }

    private static bool IsWindowsAppsDark()
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                writable: false);
            return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
        catch (Exception error) when (error is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }
}

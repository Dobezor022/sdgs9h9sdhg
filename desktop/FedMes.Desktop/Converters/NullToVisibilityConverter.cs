using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace FedMes.Desktop.Converters;

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool inverse = string.Equals(parameter as string, "Inverse", StringComparison.OrdinalIgnoreCase);
        bool isNull = value is null;
        bool visible = inverse ? !isNull : isNull;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

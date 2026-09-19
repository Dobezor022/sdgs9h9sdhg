using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace FedMes.Desktop.Converters;

public sealed class BooleanToGridLengthConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? new GridLength(1, GridUnitType.Auto) : new GridLength(0);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

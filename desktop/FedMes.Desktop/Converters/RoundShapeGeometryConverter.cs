using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.Converters;

public sealed class RoundShapeGeometryConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        RoundVideoShape.Square => new RectangleGeometry(new Rect(0, 0, 220, 220), 24, 24),
        RoundVideoShape.Heart => new EllipseGeometry(new Point(110, 110), 110, 110),
        _ => new EllipseGeometry(new Point(110, 110), 110, 110),
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

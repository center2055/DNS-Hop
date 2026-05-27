using Avalonia.Data.Converters;
using System;
using System.Globalization;

namespace DNSHop.App.ViewModels.Pages;

public sealed class FractionToWidthConverter : IValueConverter
{
    public static readonly FractionToWidthConverter Default = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        double fraction = value is double d ? d : 0.0;
        double total = parameter switch
        {
            double n => n,
            string s when double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => 200.0,
        };

        return Math.Max(0.0, Math.Min(total, fraction * total));
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return Avalonia.Data.BindingOperations.DoNothing;
    }
}

using Avalonia.Data.Converters;
using Avalonia.Media;
using DNSHop.App.Models;
using System;
using System.Globalization;

namespace DNSHop.App.Converters;

public sealed class StatusToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            DnsServerStatus.Alive => new SolidColorBrush(Color.Parse("#3DC47E")),
            DnsServerStatus.Redirecting => new SolidColorBrush(Color.Parse("#F0B74B")),
            DnsServerStatus.Dead => new SolidColorBrush(Color.Parse("#E04F5F")),
            _ => new SolidColorBrush(Color.Parse("#8E9DAE")),
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}


using System.Globalization;

namespace DNSHop.App.Utilities;

internal static class UiValueFormatter
{
    public static CultureInfo DisplayCulture { get; } = CultureInfo.GetCultureInfo("en-US");

    public static string FormatMilliseconds(double? value, bool includeUnit = true)
    {
        if (value is null)
        {
            return "n/a";
        }

        string formatted = value.Value.ToString("0.0", DisplayCulture);
        return includeUnit ? $"{formatted} ms" : formatted;
    }

    public static string FormatNumber(double value, string format = "0.0")
        => value.ToString(format, DisplayCulture);

    public static string FormatPercent(double value, string format = "P0")
        => value.ToString(format, DisplayCulture);

    public static string FormatProbeTriplet(
        double? cached,
        double? uncached,
        double? dotCom,
        bool includeUnit = false,
        string nullPlaceholder = "n/a",
        string allNullText = "n/a")
    {
        if (cached is null && uncached is null && dotCom is null)
        {
            return allNullText;
        }

        string triplet = string.Join(
            " / ",
            cached is null ? nullPlaceholder : FormatMilliseconds(cached, includeUnit: false),
            uncached is null ? nullPlaceholder : FormatMilliseconds(uncached, includeUnit: false),
            dotCom is null ? nullPlaceholder : FormatMilliseconds(dotCom, includeUnit: false));

        return includeUnit ? $"{triplet} ms" : triplet;
    }
}

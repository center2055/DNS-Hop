using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using System;
using System.Globalization;

namespace DNSHop.App.Controls;

public sealed class ResponseBarsControl : Control
{
    public static readonly StyledProperty<double?> CachedMillisecondsProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double?>(nameof(CachedMilliseconds));

    public static readonly StyledProperty<double?> UncachedMillisecondsProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double?>(nameof(UncachedMilliseconds));

    public static readonly StyledProperty<double?> DotComMillisecondsProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double?>(nameof(DotComMilliseconds));

    public static readonly StyledProperty<double?> AverageMillisecondsProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double?>(nameof(AverageMilliseconds));

    public static readonly StyledProperty<double> MaximumValueProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double>(nameof(MaximumValue), 300);

    public static readonly StyledProperty<double> CachedMaximumValueProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double>(nameof(CachedMaximumValue), 120);

    public static readonly StyledProperty<double> UncachedMaximumValueProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double>(nameof(UncachedMaximumValue), 250);

    public static readonly StyledProperty<double> DotComMaximumValueProperty =
        AvaloniaProperty.Register<ResponseBarsControl, double>(nameof(DotComMaximumValue), 120);

    public static readonly StyledProperty<string?> ThemeTokenProperty =
        AvaloniaProperty.Register<ResponseBarsControl, string?>(nameof(ThemeToken));

    static ResponseBarsControl()
    {
        AffectsRender<ResponseBarsControl>(
            CachedMillisecondsProperty,
            UncachedMillisecondsProperty,
            DotComMillisecondsProperty,
            AverageMillisecondsProperty,
            MaximumValueProperty,
            CachedMaximumValueProperty,
            UncachedMaximumValueProperty,
            DotComMaximumValueProperty,
            ThemeTokenProperty);
    }

    public double? CachedMilliseconds
    {
        get => GetValue(CachedMillisecondsProperty);
        set => SetValue(CachedMillisecondsProperty, value);
    }

    public double? UncachedMilliseconds
    {
        get => GetValue(UncachedMillisecondsProperty);
        set => SetValue(UncachedMillisecondsProperty, value);
    }

    public double? DotComMilliseconds
    {
        get => GetValue(DotComMillisecondsProperty);
        set => SetValue(DotComMillisecondsProperty, value);
    }

    public double? AverageMilliseconds
    {
        get => GetValue(AverageMillisecondsProperty);
        set => SetValue(AverageMillisecondsProperty, value);
    }

    public double MaximumValue
    {
        get => GetValue(MaximumValueProperty);
        set => SetValue(MaximumValueProperty, value);
    }

    public double CachedMaximumValue
    {
        get => GetValue(CachedMaximumValueProperty);
        set => SetValue(CachedMaximumValueProperty, value);
    }

    public double UncachedMaximumValue
    {
        get => GetValue(UncachedMaximumValueProperty);
        set => SetValue(UncachedMaximumValueProperty, value);
    }

    public double DotComMaximumValue
    {
        get => GetValue(DotComMaximumValueProperty);
        set => SetValue(DotComMaximumValueProperty, value);
    }

    public string? ThemeToken
    {
        get => GetValue(ThemeTokenProperty);
        set => SetValue(ThemeTokenProperty, value);
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var bounds = Bounds;
        if (bounds.Width < 20 || bounds.Height < 12)
        {
            return;
        }

        var backgroundBrush = ResolveBrush("ResponseBarBackgroundBrush", "#FF1A2538");
        var noDataBackgroundBrush = ResolveBrush("ResponseBarNoDataBackgroundBrush", "#FF24395A");
        var textBrush = ResolveBrush("ResponseBarTextBrush", "#FFFFFFFF");
        var noDataTextBrush = ResolveBrush("ResponseBarNoDataTextBrush", "#FFBFD0EA");
        var borderBrush = ResolveBrush("ResponseBarBorderBrush", "#FF3F587D");

        bool hasData = CachedMilliseconds is not null
            || UncachedMilliseconds is not null
            || DotComMilliseconds is not null;

        var frame = new Rect(
            bounds.X + 1,
            bounds.Y + 1,
            Math.Max(1, bounds.Width - 2),
            Math.Max(1, bounds.Height - 2));

        context.FillRectangle(hasData ? backgroundBrush : noDataBackgroundBrush, frame);
        context.DrawRectangle(new Pen(borderBrush, 1), frame);

        double barAreaWidth = Math.Max(1, frame.Width - 60);
        double barHeight = Math.Max(2, Math.Floor((frame.Height - 10) / 3));
        double barSpacing = 2;
        double totalBarsHeight = (barHeight * 3) + (barSpacing * 2);
        double baseX = frame.X + 4;
        double baseY = frame.Y + Math.Max(1, Math.Floor((frame.Height - totalBarsHeight) / 2));

        if (hasData)
        {
            DrawBar(CachedMilliseconds, Math.Max(20, CachedMaximumValue), Color.Parse("#E04F5F"), baseY);
            DrawBar(UncachedMilliseconds, Math.Max(20, UncachedMaximumValue), Color.Parse("#3DC47E"), baseY + barHeight + barSpacing);
            DrawBar(DotComMilliseconds, Math.Max(20, DotComMaximumValue), Color.Parse("#4D7BFF"), baseY + (2 * (barHeight + barSpacing)));
        }

        string label = AverageMilliseconds is null ? "n/a" : $"{AverageMilliseconds:0}";
        var text = new FormattedText(
            label,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            new Typeface("Inter"),
            11,
            hasData ? textBrush : noDataTextBrush);

        context.DrawText(text, new Point(frame.Right - text.Width - 5, frame.Y + 2));

        return;

        void DrawBar(double? value, double scaleMax, Color color, double y)
        {
            if (value is null)
            {
                return;
            }

            double ratio = Math.Clamp(value.Value / scaleMax, 0, 1);
            var brush = new SolidColorBrush(color);

            context.FillRectangle(
                brush,
                new Rect(baseX, y, Math.Max(1, Math.Floor(ratio * barAreaWidth)), barHeight));
        }
    }

    private IBrush ResolveBrush(string key, string fallbackHex)
    {
        if (TryGetResource(key, Application.Current?.RequestedThemeVariant, out object? localResource)
            && localResource is IBrush localBrush)
        {
            return localBrush;
        }

        if (Application.Current?.Resources is { } resources
            && resources.TryGetValue(key, out object? resource)
            && resource is IBrush brush)
        {
            return brush;
        }

        return new SolidColorBrush(Color.Parse(fallbackHex));
    }
}


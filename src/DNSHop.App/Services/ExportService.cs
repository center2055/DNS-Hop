using Avalonia;
using Avalonia.Input;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

public sealed class ExportService
{
    // Keep the last clipboard bitmap alive so clipboard backends that reference
    // application memory do not end up with an empty image after disposal.
    private static readonly object ClipboardBitmapSync = new();
    private static Bitmap? _clipboardBitmapHold;

    public async Task<string> ExportCsvAsync(IReadOnlyList<DnsBenchmarkResult> results, CancellationToken cancellationToken)
        => await ExportCsvAsync(results, outputPath: null, cancellationToken).ConfigureAwait(false);

    public async Task<string> ExportCsvAsync(
        IReadOnlyList<DnsBenchmarkResult> results,
        string? outputPath,
        CancellationToken cancellationToken)
    {
        string path = ResolveOutputPath(outputPath, "csv");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var rows = results
            .OrderBy(static r => r.AverageMilliseconds ?? double.MaxValue)
            .Select(ExportRow.FromResult)
            .ToArray();

        await using var streamWriter = new StreamWriter(path, append: false, Encoding.UTF8);

        await streamWriter.WriteLineAsync(
            "Endpoint,Provider,Protocol,Status,SupportsDnssec,RedirectsNxDomain,PoisoningConfidence,PoisoningEvidence,CachedMs,UncachedMs,DotComMs,AverageMs,SuccessfulQueries,FailedQueries,LastError");

        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string line = string.Join(',',
                EscapeCsv(row.Endpoint),
                EscapeCsv(row.Provider),
                EscapeCsv(row.Protocol),
                EscapeCsv(row.Status),
                row.SupportsDnssec ? "true" : "false",
                row.RedirectsNxDomain ? "true" : "false",
                row.PoisoningConfidence.ToString("0.###", CultureInfo.InvariantCulture),
                EscapeCsv(row.PoisoningEvidence),
                FormatNullableDouble(row.CachedMs),
                FormatNullableDouble(row.UncachedMs),
                FormatNullableDouble(row.DotComMs),
                FormatNullableDouble(row.AverageMs),
                row.SuccessfulQueries.ToString(CultureInfo.InvariantCulture),
                row.FailedQueries.ToString(CultureInfo.InvariantCulture),
                EscapeCsv(row.LastError));

            await streamWriter.WriteLineAsync(line);
        }

        await streamWriter.FlushAsync(cancellationToken);

        return path;
    }

    public async Task<string> ExportJsonAsync(IReadOnlyList<DnsBenchmarkResult> results, CancellationToken cancellationToken)
        => await ExportJsonAsync(results, outputPath: null, cancellationToken).ConfigureAwait(false);

    public async Task<string> ExportJsonAsync(
        IReadOnlyList<DnsBenchmarkResult> results,
        string? outputPath,
        CancellationToken cancellationToken)
    {
        string path = ResolveOutputPath(outputPath, "json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var rows = results
            .OrderBy(static r => r.AverageMilliseconds ?? double.MaxValue)
            .Select(ExportRow.FromResult)
            .ToArray();

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(
            stream,
            rows,
            ExportJsonContext.Default.ExportRowArray,
            cancellationToken);

        return path;
    }

    public async Task<string> ExportChartToClipboardAsync(IReadOnlyList<DnsBenchmarkResult> results, CancellationToken cancellationToken)
        => await ExportChartToClipboardAsync(results, outputPath: null, cancellationToken).ConfigureAwait(false);

    public async Task<string> ExportChartToClipboardAsync(
        IReadOnlyList<DnsBenchmarkResult> results,
        string? outputPath,
        CancellationToken cancellationToken)
    {
        EnsureChartHasData(results);

        string path = ResolveOutputPath(outputPath, "png");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        using var renderTarget = BuildComparisonChart(results);

        await using (var fileStream = File.Create(path))
        {
            renderTarget.Save(fileStream);
            await fileStream.FlushAsync(cancellationToken);
        }

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow?.Clipboard is { } clipboard)
        {
            try
            {
                await TrySetBitmapOnClipboardAsync(clipboard, renderTarget).ConfigureAwait(false);
            }
            catch
            {
                // Keep export resilient even when clipboard integration is unavailable.
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        return path;
    }

    public async Task<bool> CopyChartToClipboardAsync(
        IReadOnlyList<DnsBenchmarkResult> results,
        CancellationToken cancellationToken)
    {
        EnsureChartHasData(results);

        using var renderTarget = BuildComparisonChart(results);

        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop
            && desktop.MainWindow?.Clipboard is { } clipboard)
        {
            await TrySetBitmapOnClipboardAsync(clipboard, renderTarget).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return true;
        }

        return false;
    }

    private static async Task TrySetBitmapOnClipboardAsync(
        IClipboard clipboard,
        RenderTargetBitmap renderTarget)
    {
        Bitmap clipboardBitmap = BuildClipboardBitmap(renderTarget);

        try
        {
            await clipboard.SetBitmapAsync(clipboardBitmap).ConfigureAwait(false);
            await clipboard.FlushAsync().ConfigureAwait(false);
            HoldClipboardBitmap(clipboardBitmap);
            return;
        }
        catch
        {
            // Fall through to data-transfer strategy.
        }

        try
        {
            var transfer = new DataTransfer();
            var item = new DataTransferItem();
            item.SetBitmap(clipboardBitmap);
            transfer.Add(item);

            await clipboard.SetDataAsync(transfer).ConfigureAwait(false);
            await clipboard.FlushAsync().ConfigureAwait(false);
            HoldClipboardBitmap(clipboardBitmap);
            return;
        }
        catch
        {
            clipboardBitmap.Dispose();
            throw;
        }
    }

    private static void HoldClipboardBitmap(Bitmap bitmap)
    {
        lock (ClipboardBitmapSync)
        {
            Bitmap? previous = _clipboardBitmapHold;
            _clipboardBitmapHold = bitmap;
            previous?.Dispose();
        }
    }

    private static RenderTargetBitmap BuildComparisonChart(IReadOnlyList<DnsBenchmarkResult> results)
    {
        var topResults = results
            .Where(static result =>
                result.CachedMilliseconds is not null
                || result.UncachedMilliseconds is not null
                || result.DotComMilliseconds is not null
                || result.AverageMilliseconds is not null)
            .Select(result => new
            {
                Result = result,
                Score = ComputeChartSummaryMilliseconds(result),
            })
            .OrderBy(static row => row.Score ?? double.MaxValue)
            .ThenBy(static row => row.Result.Server.Provider, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static row => row.Result.Server.EndpointDisplay, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Select(static row => row.Result)
            .ToArray();

        int rowHeight = 34;
        int width = 1280;
        int height = 120 + (Math.Max(1, topResults.Length) * rowHeight);

        var bitmap = new RenderTargetBitmap(new PixelSize(width, height));

        using var context = bitmap.CreateDrawingContext(clear: true);

        var backgroundBrush = new SolidColorBrush(Color.Parse("#121B29"));
        var panelBrush = new SolidColorBrush(Color.Parse("#1D2A3F"));
        var cachedBrush = new SolidColorBrush(Color.Parse("#E04F5F"));
        var uncachedBrush = new SolidColorBrush(Color.Parse("#3DC47E"));
        var dotComBrush = new SolidColorBrush(Color.Parse("#4D7BFF"));
        var textBrush = Brushes.White;
        var subTextBrush = new SolidColorBrush(Color.Parse("#B6C5D8"));

        context.FillRectangle(backgroundBrush, new Rect(0, 0, width, height));

        DrawText(
            context,
            "DNS Hop Benchmark Snapshot",
            new Point(24, 20),
            24,
            FontWeight.Bold,
            textBrush);

        DrawText(
            context,
            "Cached (red), Uncached (green), DotCom (blue)",
            new Point(24, 56),
            14,
            FontWeight.Normal,
            subTextBrush);

        context.FillRectangle(panelBrush, new Rect(20, 84, width - 40, height - 104));

        double maxMetric = Math.Max(
            50,
            topResults
                .SelectMany(static result => new[]
                {
                    result.CachedMilliseconds ?? 0,
                    result.UncachedMilliseconds ?? 0,
                    result.DotComMilliseconds ?? 0,
                })
                .DefaultIfEmpty(0)
                .Max());

        for (int index = 0; index < topResults.Length; index++)
        {
            var result = topResults[index];
            double y = 94 + (index * rowHeight);

            DrawText(context, result.Server.EndpointDisplay, new Point(28, y + 4), 13, FontWeight.SemiBold, textBrush);
            DrawText(context, result.Server.Provider, new Point(310, y + 4), 12, FontWeight.Normal, subTextBrush);

            DrawBar(context, result.CachedMilliseconds, maxMetric, cachedBrush, y + 4);
            DrawBar(context, result.UncachedMilliseconds, maxMetric, uncachedBrush, y + 14);
            DrawBar(context, result.DotComMilliseconds, maxMetric, dotComBrush, y + 24);

            double? summaryMilliseconds = ComputeChartSummaryMilliseconds(result);
            DrawText(
                context,
                summaryMilliseconds is null ? "n/a" : $"{summaryMilliseconds:0.0} ms",
                new Point(width - 140, y + 6),
                12,
                FontWeight.SemiBold,
                textBrush);
        }

        return bitmap;

        static void DrawBar(DrawingContext drawingContext, double? valueMs, double maxMetricMs, IBrush brush, double y)
        {
            if (valueMs is null)
            {
                return;
            }

            double ratio = Math.Clamp(valueMs.Value / maxMetricMs, 0, 1);
            double barWidth = ratio * 560;
            var rect = new Rect(500, y, Math.Max(1, barWidth), 7);
            drawingContext.FillRectangle(brush, rect);
        }
    }

    private static double? ComputeChartSummaryMilliseconds(DnsBenchmarkResult result)
    {
        if (result.AverageMilliseconds is double average)
        {
            return average;
        }

        double[] available = [result.CachedMilliseconds ?? double.NaN, result.UncachedMilliseconds ?? double.NaN, result.DotComMilliseconds ?? double.NaN];
        double[] valid = available.Where(static value => !double.IsNaN(value) && value > 0).ToArray();

        return valid.Length == 0
            ? null
            : valid.Average();
    }

    private static Bitmap BuildClipboardBitmap(RenderTargetBitmap renderTarget)
    {
        PixelSize pixelSize = renderTarget.PixelSize;
        Vector dpi = renderTarget.Dpi;

        var bitmap = new WriteableBitmap(
            pixelSize,
            dpi,
            PixelFormat.Bgra8888,
            AlphaFormat.Premul);

        using var frameBuffer = bitmap.Lock();
        renderTarget.CopyPixels(
            new PixelRect(0, 0, pixelSize.Width, pixelSize.Height),
            frameBuffer.Address,
            frameBuffer.RowBytes * pixelSize.Height,
            frameBuffer.RowBytes);

        return bitmap;
    }

    private static void EnsureChartHasData(IReadOnlyList<DnsBenchmarkResult> results)
    {
        bool hasData = results.Any(static result =>
            result.CachedMilliseconds is not null
            || result.UncachedMilliseconds is not null
            || result.DotComMilliseconds is not null
            || result.AverageMilliseconds is not null);

        if (!hasData)
        {
            throw new InvalidOperationException("No benchmark data yet. Run a benchmark before copying the chart.");
        }
    }

    private static void DrawText(
        DrawingContext context,
        string text,
        Point origin,
        double fontSize,
        FontWeight weight,
        IBrush brush)
    {
        var formattedText = new FormattedText(
            text,
            CultureInfo.InvariantCulture,
            FlowDirection.LeftToRight,
            new Typeface("Inter", FontStyle.Normal, weight),
            fontSize,
            brush);

        context.DrawText(formattedText, origin);
    }

    private static string BuildExportPath(string extension)
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrWhiteSpace(root))
        {
            root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }

        if (string.IsNullOrWhiteSpace(root))
        {
            root = Path.GetTempPath();
        }

        string exportsFolder = Path.Combine(
            root,
            "DNS Hop",
            "Exports");

        string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);

        return Path.Combine(exportsFolder, $"DNS-Hop-Benchmark-{timestamp}.{extension}");
    }

    private static string ResolveOutputPath(string? explicitPath, string extension)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            string trimmed = explicitPath.Trim();
            if (!Path.HasExtension(trimmed))
            {
                return $"{trimmed}.{extension}";
            }

            return trimmed;
        }

        return BuildExportPath(extension);
    }

    private static string FormatNullableDouble(double? value)
        => value?.ToString("0.###", CultureInfo.InvariantCulture) ?? string.Empty;

    private static string EscapeCsv(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        bool needsQuotes = raw.Contains(',') || raw.Contains('"') || raw.Contains('\n') || raw.Contains('\r');
        if (!needsQuotes)
        {
            return raw;
        }

        return "\"" + raw.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}


using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class LogsPageViewModel : PageViewModel
{
    private const int MaxDisplayedLines = 500;

    private readonly AppServices _services;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private string _logPath = string.Empty;

    [ObservableProperty]
    private bool _showInfo = true;

    [ObservableProperty]
    private bool _showWarn = true;

    [ObservableProperty]
    private bool _showError = true;

    [ObservableProperty]
    private int _totalLines;

    [ObservableProperty]
    private string _exportStatus = string.Empty;

    public LogsPageViewModel(AppServices services) : base("Logs", "Logs.Title")
    {
        _services = services;
    }

    public ObservableCollection<LogEntry> Entries { get; } = new();

    public override void OnActivated()
    {
        Refresh();
    }

    [RelayCommand]
    private void Refresh()
    {
        try
        {
            LogPath = AppDiagnostics.CurrentLogPath;
            Entries.Clear();
            if (!File.Exists(LogPath))
            {
                TotalLines = 0;
                return;
            }

            var lines = File.ReadAllLines(LogPath);
            TotalLines = lines.Length;

            IEnumerable<LogEntry> parsed = lines
                .Select(ParseLine)
                .Where(e => MatchesLevel(e.Level) && MatchesFilter(e));

            foreach (var entry in parsed.TakeLast(MaxDisplayedLines))
            {
                Entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            Entries.Add(new LogEntry("ERROR", "Logs", ex.Message, string.Empty));
        }
    }

    [RelayCommand]
    private void OpenFolder()
    {
        try
        {
            var dir = AppDiagnostics.LogsDirectory;
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            AppDiagnostics.WriteWarning("Logs", $"Open folder failed: {ex.Message}");
        }
    }

    [RelayCommand]
    private async Task ExportAsync()
    {
        try
        {
            if (!File.Exists(LogPath))
            {
                ExportStatus = "—";
                return;
            }

            var folder = AppDiagnostics.LogsDirectory;
            var name = $"dns-hop-export-{DateTime.Now:yyyyMMdd-HHmmss}.log";
            var target = Path.Combine(folder, name);
            await Task.Run(() => File.Copy(LogPath, target, overwrite: true)).ConfigureAwait(false);
            ExportStatus = target;
        }
        catch (Exception ex)
        {
            ExportStatus = ex.Message;
        }
    }

    partial void OnFilterTextChanged(string value) => Refresh();
    partial void OnShowInfoChanged(bool value) => Refresh();
    partial void OnShowWarnChanged(bool value) => Refresh();
    partial void OnShowErrorChanged(bool value) => Refresh();

    private bool MatchesLevel(string level) => level switch
    {
        "ERROR" => ShowError,
        "WARN" => ShowWarn,
        "INFO" => ShowInfo,
        _ => true,
    };

    private bool MatchesFilter(LogEntry entry)
    {
        if (string.IsNullOrWhiteSpace(FilterText))
        {
            return true;
        }

        return entry.Message.Contains(FilterText, StringComparison.OrdinalIgnoreCase)
            || entry.Component.Contains(FilterText, StringComparison.OrdinalIgnoreCase);
    }

    private static LogEntry ParseLine(string line)
    {
        // Format: 2026-05-27T13:50:41.318+00:00 [WARN] [Benchmark] message
        try
        {
            int firstBracket = line.IndexOf('[');
            if (firstBracket < 0)
            {
                return new LogEntry("INFO", string.Empty, line, string.Empty);
            }

            string timestamp = line[..firstBracket].Trim();

            int levelEnd = line.IndexOf(']', firstBracket);
            string level = line[(firstBracket + 1)..levelEnd];

            int componentStart = line.IndexOf('[', levelEnd);
            int componentEnd = line.IndexOf(']', componentStart + 1);
            string component = line[(componentStart + 1)..componentEnd];

            string message = line[(componentEnd + 1)..].Trim();
            return new LogEntry(level, component, message, timestamp);
        }
        catch
        {
            return new LogEntry("INFO", string.Empty, line, string.Empty);
        }
    }
}

public sealed class LogEntry
{
    public LogEntry(string level, string component, string message, string timestamp)
    {
        Level = level;
        Component = component;
        Message = message;
        Timestamp = timestamp;
    }

    public string Level { get; }
    public string Component { get; }
    public string Message { get; }
    public string Timestamp { get; }

    public bool IsError => Level == "ERROR";
    public bool IsWarn => Level == "WARN";
    public bool IsInfo => Level == "INFO";
}

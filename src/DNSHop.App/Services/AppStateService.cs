using CommunityToolkit.Mvvm.ComponentModel;
using DNSHop.App.Models;
using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace DNSHop.App.Services;

internal sealed partial class AppStateService : ObservableObject
{
    [ObservableProperty]
    private string? _activeProfileId;

    [ObservableProperty]
    private string? _detectedRegion;

    [ObservableProperty]
    private DateTimeOffset? _lastBenchmarkAt;

    [ObservableProperty]
    private int _lastBenchmarkServerCount;

    [ObservableProperty]
    private LeakTestResult? _lastLeakTest;

    [ObservableProperty]
    private string? _activeAdapterName;

    public ObservableCollection<DnsProfile> Profiles { get; } = new();

    public ObservableCollection<AppliedDnsEntry> ApplyHistory { get; } = new();

    public ObservableCollection<DnsBenchmarkResult> LastResults { get; } = new();

    public void RecordApplied(AppliedDnsEntry entry)
    {
        ApplyHistory.Insert(0, entry);
        while (ApplyHistory.Count > 5)
        {
            ApplyHistory.RemoveAt(ApplyHistory.Count - 1);
        }
    }

    public AppliedDnsEntry? PreviousApplied()
    {
        return ApplyHistory.Count >= 2 ? ApplyHistory[1] : null;
    }

    public DnsProfile? GetActiveProfile()
    {
        if (string.IsNullOrWhiteSpace(ActiveProfileId))
        {
            return null;
        }

        return Profiles.FirstOrDefault(p => string.Equals(p.Id, ActiveProfileId, StringComparison.Ordinal));
    }
}

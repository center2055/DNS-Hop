using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using DNSHop.App.Services;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.ViewModels.Pages;

internal sealed partial class ProfilesPageViewModel : PageViewModel
{
    private readonly AppServices _services;

    [ObservableProperty]
    private DnsProfile? _selected;

    [ObservableProperty]
    private bool _isEditing;

    [ObservableProperty]
    private DnsProfile? _draft;

    public ProfilesPageViewModel(AppServices services) : base("Profiles", "Profiles.Title")
    {
        _services = services;
        BuiltIns = new ObservableCollection<DnsProfile>(_services.Profiles.GetBuiltIns(_services.Localization));
        _services.Localization.CultureChanged += (_, _) => RefreshBuiltIns();
        LoadCustom();
    }

    public ObservableCollection<DnsProfile> BuiltIns { get; }

    public ObservableCollection<DnsProfile> Custom => _services.AppState.Profiles;

    public ObservableCollection<AppliedDnsEntry> History => _services.AppState.ApplyHistory;

    [RelayCommand]
    private void New()
    {
        Draft = DnsProfile.CreateUserProfile(Localization["Profiles.New"]);
        IsEditing = true;
    }

    [RelayCommand]
    private void Edit(DnsProfile profile)
    {
        if (profile.IsBuiltIn)
        {
            return;
        }

        Draft = new DnsProfile
        {
            Id = profile.Id,
            Name = profile.Name,
            Description = profile.Description,
            PreferredIPv4 = profile.PreferredIPv4,
            AlternateIPv4 = profile.AlternateIPv4,
            PreferredIPv6 = profile.PreferredIPv6,
            AlternateIPv6 = profile.AlternateIPv6,
            EncryptedEndpoint = profile.EncryptedEndpoint,
            EncryptedProtocol = profile.EncryptedProtocol,
        };
        IsEditing = true;
    }

    [RelayCommand]
    private void SaveDraft()
    {
        if (Draft is null)
        {
            return;
        }

        var existing = Custom.FirstOrDefault(p => p.Id == Draft.Id);
        if (existing is null)
        {
            Custom.Add(Draft);
        }
        else
        {
            int index = Custom.IndexOf(existing);
            Custom[index] = Draft;
        }

        IsEditing = false;
        Draft = null;
        Persist();
    }

    [RelayCommand]
    private void CancelEdit()
    {
        IsEditing = false;
        Draft = null;
    }

    [RelayCommand]
    private void Delete(DnsProfile profile)
    {
        if (profile.IsBuiltIn)
        {
            return;
        }

        Custom.Remove(profile);
        if (_services.AppState.ActiveProfileId == profile.Id)
        {
            _services.AppState.ActiveProfileId = null;
        }
        Persist();
    }

    [RelayCommand]
    private async Task ApplyAsync(DnsProfile profile)
    {
        if (profile is null)
        {
            return;
        }

        var result = await _services.SystemDns.ApplyProfileAsync(profile, CancellationToken.None).ConfigureAwait(false);
        if (result.Success)
        {
            _services.AppState.ActiveProfileId = profile.Id;
            _services.AppState.RecordApplied(new AppliedDnsEntry
            {
                AppliedAt = DateTimeOffset.UtcNow,
                DisplayLabel = profile.Name,
                PreferredIPv4 = profile.PreferredIPv4,
                AlternateIPv4 = profile.AlternateIPv4,
                PreferredIPv6 = profile.PreferredIPv6,
                AlternateIPv6 = profile.AlternateIPv6,
                ProfileId = profile.Id,
            });
            Persist();
        }
    }

    private void LoadCustom()
    {
        var settings = _services.Settings.Load();
        Custom.Clear();
        foreach (var p in settings.Profiles)
        {
            Custom.Add(p);
        }
        _services.AppState.ActiveProfileId = settings.ActiveProfileId;
        _services.AppState.ApplyHistory.Clear();
        foreach (var e in settings.ApplyHistory)
        {
            _services.AppState.ApplyHistory.Add(e);
        }
    }

    private void RefreshBuiltIns()
    {
        BuiltIns.Clear();
        foreach (var p in _services.Profiles.GetBuiltIns(_services.Localization))
        {
            BuiltIns.Add(p);
        }
    }

    private void Persist()
    {
        var current = _services.Settings.Load();
        _services.Settings.Save(new AppSettings
        {
            Theme = current.Theme,
            Language = current.Language,
            UseMica = current.UseMica,
            LastNavSection = current.LastNavSection,
            TimeoutMilliseconds = current.TimeoutMilliseconds,
            ConcurrencyLimit = current.ConcurrencyLimit,
            AttemptsPerProbe = current.AttemptsPerProbe,
            AutoUpdateListOnStartup = current.AutoUpdateListOnStartup,
            CheckForAppUpdatesOnStartup = current.CheckForAppUpdatesOnStartup,
            OutboundProxyType = current.OutboundProxyType,
            OutboundProxyHost = current.OutboundProxyHost,
            OutboundProxyPort = current.OutboundProxyPort,
            CustomServers = current.CustomServers,
            ActiveProfileId = _services.AppState.ActiveProfileId,
            Profiles = Custom.ToArray(),
            ApplyHistory = _services.AppState.ApplyHistory.ToArray(),
        });
    }
}

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DNSHop.App.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace DNSHop.App.ViewModels;

public partial class MainWindowViewModel
{
    private const string CustomDnsClassicProtocolName = "Classic DNS (UDP/TCP)";
    private const string CustomDnsDohProtocolName = "DNS over HTTPS (DoH)";
    private const string CustomDnsDotProtocolName = "DNS over TLS (DoT)";

    public string[] AvailableCustomDnsProtocols { get; } =
    [
        CustomDnsClassicProtocolName,
        CustomDnsDohProtocolName,
        CustomDnsDotProtocolName,
    ];

    public bool HasCustomDnsValidationMessage => !string.IsNullOrWhiteSpace(CustomDnsValidationMessage);

    public bool IsCustomDnsClassicSelected =>
        string.Equals(SelectedCustomDnsProtocol, CustomDnsClassicProtocolName, StringComparison.Ordinal);

    public bool IsCustomDnsDohSelected =>
        string.Equals(SelectedCustomDnsProtocol, CustomDnsDohProtocolName, StringComparison.Ordinal);

    public bool IsCustomDnsDotSelected =>
        string.Equals(SelectedCustomDnsProtocol, CustomDnsDotProtocolName, StringComparison.Ordinal);

    public bool IsCustomDnsAddressOrHostVisible => !IsCustomDnsDohSelected;

    public bool IsCustomDnsPortVisible => !IsCustomDnsDohSelected;

    public bool IsCustomDnsDohEndpointVisible => IsCustomDnsDohSelected;

    public bool IsCustomDnsDotTlsHostVisible => IsCustomDnsDotSelected;

    [ObservableProperty]
    private bool isAddCustomDnsDialogVisible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCustomDnsValidationMessage))]
    private string customDnsValidationMessage = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsClassicSelected))]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsDohSelected))]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsDotSelected))]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsAddressOrHostVisible))]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsPortVisible))]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsDohEndpointVisible))]
    [NotifyPropertyChangedFor(nameof(IsCustomDnsDotTlsHostVisible))]
    private string selectedCustomDnsProtocol = CustomDnsClassicProtocolName;

    [ObservableProperty]
    private string customDnsProvider = string.Empty;

    [ObservableProperty]
    private string customDnsAddressOrHost = string.Empty;

    [ObservableProperty]
    private int customDnsPort = 53;

    [ObservableProperty]
    private string customDnsDohEndpoint = string.Empty;

    [ObservableProperty]
    private string customDnsDotTlsHost = string.Empty;

    [ObservableProperty]
    private bool customDnsPinOnAdd;

    partial void OnSelectedCustomDnsProtocolChanged(string value)
    {
        ClearCustomDnsValidationMessage();

        if (IsCustomDnsClassicSelected && CustomDnsPort == 853)
        {
            CustomDnsPort = 53;
        }
        else if (IsCustomDnsDotSelected && CustomDnsPort == 53)
        {
            CustomDnsPort = 853;
        }
    }

    partial void OnCustomDnsProviderChanged(string value) => ClearCustomDnsValidationMessage();

    partial void OnCustomDnsAddressOrHostChanged(string value) => ClearCustomDnsValidationMessage();

    partial void OnCustomDnsPortChanged(int value) => ClearCustomDnsValidationMessage();

    partial void OnCustomDnsDohEndpointChanged(string value) => ClearCustomDnsValidationMessage();

    partial void OnCustomDnsDotTlsHostChanged(string value) => ClearCustomDnsValidationMessage();

    [RelayCommand]
    private void OpenAddCustomDnsDialog()
    {
        ResetCustomDnsForm();
        IsAddCustomDnsDialogVisible = true;
    }

    [RelayCommand]
    private void CancelAddCustomDns()
    {
        IsAddCustomDnsDialogVisible = false;
        ClearCustomDnsValidationMessage();
    }

    [RelayCommand]
    private void AddCustomDns()
    {
        if (!TryBuildCustomDnsServer(out DnsServerDefinition? server, out string validationError))
        {
            CustomDnsValidationMessage = validationError;
            StatusMessage = validationError;
            return;
        }

        string serverKey = BuildCustomDnsKey(server);
        if (Servers.Any(row => string.Equals(BuildCustomDnsKey(row.Server), serverKey, StringComparison.OrdinalIgnoreCase))
            || _customServers.Any(existing => string.Equals(BuildCustomDnsKey(existing), serverKey, StringComparison.OrdinalIgnoreCase)))
        {
            string duplicateMessage = $"Custom DNS endpoint {server.EndpointDisplay} already exists.";
            CustomDnsValidationMessage = duplicateMessage;
            StatusMessage = duplicateMessage;
            return;
        }

        _customServers.Add(server);

        DnsServerResultViewModel row = CreateServerRow(server);
        Servers.Add(row);

        bool clearedFilter = false;
        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            string normalizedFilter = FilterText.Trim().ToLowerInvariant();
            if (!row.MatchesFilter(normalizedFilter))
            {
                FilterText = string.Empty;
                clearedFilter = true;
            }
        }

        ApplyFilterAndSort();
        UpdateIdleProgressSnapshot();
        StartBenchmarkCommand.NotifyCanExecuteChanged();

        SelectedServer = row;
        SaveSettingsSnapshot();

        IsAddCustomDnsDialogVisible = false;
        ClearCustomDnsValidationMessage();

        StatusMessage = clearedFilter
            ? $"Added custom DNS endpoint {row.Endpoint} and cleared the active filter to show it."
            : $"Added custom DNS endpoint {row.Endpoint}.";
    }

    private void ResetCustomDnsForm()
    {
        SelectedCustomDnsProtocol = CustomDnsClassicProtocolName;
        CustomDnsProvider = string.Empty;
        CustomDnsAddressOrHost = string.Empty;
        CustomDnsPort = 53;
        CustomDnsDohEndpoint = string.Empty;
        CustomDnsDotTlsHost = string.Empty;
        CustomDnsPinOnAdd = false;
        ClearCustomDnsValidationMessage();
    }

    private void ClearCustomDnsValidationMessage()
    {
        if (!string.IsNullOrEmpty(CustomDnsValidationMessage))
        {
            CustomDnsValidationMessage = string.Empty;
        }
    }

    private bool TryBuildCustomDnsServer(out DnsServerDefinition server, out string validationError)
    {
        validationError = string.Empty;
        server = null!;

        string provider = string.IsNullOrWhiteSpace(CustomDnsProvider)
            ? "Custom DNS"
            : CustomDnsProvider.Trim();

        switch (GetSelectedCustomDnsProtocol())
        {
            case DnsProtocol.UdpTcp:
            {
                string address = CustomDnsAddressOrHost.Trim();
                if (string.IsNullOrWhiteSpace(address))
                {
                    validationError = "Enter an IPv4 or IPv6 address for a classic DNS resolver.";
                    return false;
                }

                if (!IPAddress.TryParse(address, out IPAddress? ipAddress))
                {
                    validationError = "Classic DNS entries require a valid IPv4 or IPv6 address.";
                    return false;
                }

                if (!IsValidCustomPort(CustomDnsPort))
                {
                    validationError = "Port must be between 1 and 65535.";
                    return false;
                }

                server = DnsServerDefinition.CreateUdpTcp(ipAddress.ToString(), provider, CustomDnsPort);
                break;
            }

            case DnsProtocol.Doh:
            {
                string endpoint = CustomDnsDohEndpoint.Trim();
                if (string.IsNullOrWhiteSpace(endpoint))
                {
                    validationError = "Enter an HTTPS URL for the DoH endpoint.";
                    return false;
                }

                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? dohUri)
                    || !string.Equals(dohUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                {
                    validationError = "DoH endpoints must be absolute HTTPS URLs, for example https://dns.example.com/dns-query.";
                    return false;
                }

                server = DnsServerDefinition.CreateDoh(dohUri.AbsoluteUri, provider);
                break;
            }

            case DnsProtocol.Dot:
            {
                string addressOrHost = CustomDnsAddressOrHost.Trim();
                if (string.IsNullOrWhiteSpace(addressOrHost))
                {
                    validationError = "Enter the IP address or hostname to connect to for the DoT endpoint.";
                    return false;
                }

                if (!IsValidCustomPort(CustomDnsPort))
                {
                    validationError = "Port must be between 1 and 65535.";
                    return false;
                }

                string tlsHost = string.IsNullOrWhiteSpace(CustomDnsDotTlsHost)
                    ? addressOrHost
                    : CustomDnsDotTlsHost.Trim();

                if (IPAddress.TryParse(addressOrHost, out _)
                    && string.IsNullOrWhiteSpace(CustomDnsDotTlsHost))
                {
                    validationError = "DoT endpoints added by IP should also include the TLS host name used for certificate validation.";
                    return false;
                }

                server = DnsServerDefinition.CreateDot(addressOrHost, tlsHost, provider, CustomDnsPort);
                break;
            }

            default:
                validationError = "Select a supported DNS protocol.";
                return false;
        }

        server.IsPinned = CustomDnsPinOnAdd;
        server.IsCustom = true;
        return true;
    }

    private DnsProtocol GetSelectedCustomDnsProtocol()
    {
        if (IsCustomDnsDohSelected)
        {
            return DnsProtocol.Doh;
        }

        if (IsCustomDnsDotSelected)
        {
            return DnsProtocol.Dot;
        }

        return DnsProtocol.UdpTcp;
    }

    private static bool IsValidCustomPort(int port)
    {
        return port is >= 1 and <= 65535;
    }

    private IReadOnlyList<DnsServerDefinition> MergePersistedCustomServers(IReadOnlyList<DnsServerDefinition> localServers)
    {
        var combined = new List<DnsServerDefinition>(localServers.Count + _customServers.Count);
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (DnsServerDefinition server in localServers)
        {
            if (seenKeys.Add(BuildCustomDnsKey(server)))
            {
                combined.Add(server);
            }
        }

        foreach (DnsServerDefinition server in _customServers)
        {
            if (seenKeys.Add(BuildCustomDnsKey(server)))
            {
                combined.Add(server);
            }
        }

        return combined;
    }

    private void LoadPersistedCustomServers(IEnumerable<DnsServerDefinition>? servers)
    {
        _customServers.Clear();

        if (servers is null)
        {
            return;
        }

        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (DnsServerDefinition server in servers)
        {
            DnsServerDefinition clone = CloneCustomDnsServer(server);
            clone.IsCustom = true;

            if (seenKeys.Add(BuildCustomDnsKey(clone)))
            {
                _customServers.Add(clone);
            }
        }
    }

    private DnsServerDefinition[] SnapshotCustomServers()
    {
        return _customServers
            .Select(CloneCustomDnsServer)
            .ToArray();
    }

    private bool ForgetCustomServer(DnsServerDefinition server)
    {
        string key = BuildCustomDnsKey(server);
        int index = _customServers.FindIndex(existing =>
            string.Equals(BuildCustomDnsKey(existing), key, StringComparison.OrdinalIgnoreCase));

        if (index < 0)
        {
            return false;
        }

        _customServers.RemoveAt(index);
        return true;
    }

    private static DnsServerDefinition CloneCustomDnsServer(DnsServerDefinition server)
    {
        return new DnsServerDefinition
        {
            DisplayName = server.DisplayName,
            Provider = server.Provider,
            Protocol = server.Protocol,
            AddressOrHost = server.AddressOrHost,
            Port = server.Port,
            DohEndpoint = server.DohEndpoint,
            DotTlsHost = server.DotTlsHost,
            IsPinned = server.IsPinned,
            IsSidelined = server.IsSidelined,
            IsCustom = true,
        };
    }

    private static string BuildCustomDnsKey(DnsServerDefinition server)
    {
        return $"{server.Protocol}|{server.EndpointDisplay}";
    }
}

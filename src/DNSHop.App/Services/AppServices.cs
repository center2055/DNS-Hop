using DNSHop.App.Localization;

namespace DNSHop.App.Services;

internal sealed class AppServices
{
    public required ILocalizationService Localization { get; init; }

    public required AppSettingsService Settings { get; init; }

    public required IDnsBenchmarkService Benchmark { get; init; }

    public required DnsServerListService ServerList { get; init; }

    public required RecommendationService Recommendations { get; init; }

    public required ExportService Export { get; init; }

    public required AppReleaseService Releases { get; init; }

    public required SystemDnsSwitchService SystemDns { get; init; }

    public required CurrentDnsStatusService CurrentDns { get; init; }

    public required DnsProfileService Profiles { get; init; }

    public required ResolverMetadataService Metadata { get; init; }

    public required GeoLocationService Geo { get; init; }

    public required DnsLeakTestService LeakTest { get; init; }

    public required AppStateService AppState { get; init; }

    public INavigator? Navigator { get; set; }
}

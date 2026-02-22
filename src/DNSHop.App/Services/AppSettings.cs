namespace DNSHop.App.Services;

internal sealed class AppSettings
{
    public string Theme { get; init; } = "Dark";

    public int TimeoutMilliseconds { get; init; } = 2500;

    public int ConcurrencyLimit { get; init; } = 8;

    public int AttemptsPerProbe { get; init; } = 1;

    public bool AutoUpdateListOnStartup { get; init; } = true;

    public string OutboundProxyType { get; init; } = "None";

    public string OutboundProxyHost { get; init; } = string.Empty;

    public int OutboundProxyPort { get; init; } = 1080;
}

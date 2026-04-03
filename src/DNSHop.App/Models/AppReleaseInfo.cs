using System;
using System.Globalization;

namespace DNSHop.App.Models;

public sealed record AppReleaseInfo(
    string Tag,
    string Title,
    string Notes,
    bool IsPrerelease,
    DateTimeOffset? PublishedAt,
    string HtmlUrl,
    Version? ParsedVersion)
{
    public string DisplayTitle => string.IsNullOrWhiteSpace(Title) ? Tag : Title;

    public string ReleaseType => IsPrerelease ? "Pre-release" : "Release";

    public string PublishedText => PublishedAt.HasValue
        ? PublishedAt.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture)
        : "Unknown publish date";
}

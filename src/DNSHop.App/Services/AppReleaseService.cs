using DNSHop.App.Models;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DNSHop.App.Services;

internal sealed class AppReleaseService
{
    public const string RepositoryUrl = "https://github.com/center2055/DNS-Hop";
    public const string ReleasesUrl = "https://github.com/center2055/DNS-Hop/releases";
    public const string IssuesUrl = "https://github.com/center2055/DNS-Hop/issues";
    public const string DiscordUrl = "https://discord.gg/y3MVspPzKQ";
    public const string KoFiUrl = "https://ko-fi.com/center2055";

    private const string ReleasesApiUrl = "https://api.github.com/repos/center2055/DNS-Hop/releases?per_page=12";
    private static readonly Regex VersionRegex = new(
        @"(?<!\d)(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?",
        RegexOptions.Compiled);
    private static readonly HttpClient ReleasesHttpClient = CreateReleasesHttpClient();

    public AppReleaseService()
    {
        CurrentVersion = ResolveCurrentVersion();
        CurrentVersionText = BuildCurrentVersionText(CurrentVersion);
    }

    public Version CurrentVersion { get; }

    public string CurrentVersionText { get; }

    public async Task<AppReleaseSnapshot> GetReleaseSnapshotAsync(CancellationToken cancellationToken)
    {
        using var response = await ReleasesHttpClient
            .GetAsync(ReleasesApiUrl, cancellationToken)
            .ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        var releases = await JsonSerializer
            .DeserializeAsync(stream, AppReleaseJsonContext.Default.GitHubReleaseApiItemArray, cancellationToken)
            .ConfigureAwait(false)
            ?? [];

        var mapped = releases
            .Where(static release => !release.Draft)
            .Select(MapRelease)
            .ToArray();

        var latestStable = mapped.FirstOrDefault(static release => !release.IsPrerelease && release.ParsedVersion is not null)
            ?? mapped.FirstOrDefault(static release => !release.IsPrerelease)
            ?? mapped.FirstOrDefault();

        return new AppReleaseSnapshot(mapped, latestStable);
    }

    private static AppReleaseInfo MapRelease(GitHubReleaseApiItem release)
    {
        string tag = string.IsNullOrWhiteSpace(release.TagName)
            ? "untagged"
            : release.TagName.Trim();
        string title = string.IsNullOrWhiteSpace(release.Name)
            ? tag
            : release.Name.Trim();
        string notes = NormalizeNotes(release.Body);
        string htmlUrl = string.IsNullOrWhiteSpace(release.HtmlUrl)
            ? ReleasesUrl
            : release.HtmlUrl.Trim();
        DateTimeOffset? published = release.PublishedAt ?? release.CreatedAt;

        Version? parsedVersion = null;
        if (TryParseVersion(tag, out var tagVersion))
        {
            parsedVersion = tagVersion;
        }
        else if (TryParseVersion(title, out var titleVersion))
        {
            parsedVersion = titleVersion;
        }

        return new AppReleaseInfo(
            tag,
            title,
            notes,
            release.Prerelease,
            published,
            htmlUrl,
            parsedVersion);
    }

    private static string NormalizeNotes(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return "No changelog notes were provided for this release.";
        }

        return notes.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
    }

    private static Version ResolveCurrentVersion()
    {
        var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        string? informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (TryParseVersion(informationalVersion, out var informational))
        {
            return informational;
        }

        return assembly.GetName().Version ?? new Version(0, 0);
    }

    private static string BuildCurrentVersionText(Version version)
    {
        if (version.Revision > 0)
        {
            return version.ToString(4);
        }

        if (version.Build > 0)
        {
            return version.ToString(3);
        }

        return version.ToString(2);
    }

    private static HttpClient CreateReleasesHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(20),
        };
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        client.DefaultRequestHeaders.UserAgent.ParseAdd("DNSHop-App-Updates/1.2");
        return client;
    }

    internal static bool TryParseVersion(string? value, out Version version)
    {
        version = new Version(0, 0);

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        Match match = VersionRegex.Match(value);
        if (!match.Success)
        {
            return false;
        }

        int major = ParseGroup(match.Groups[1], fallback: 0);
        int minor = ParseGroup(match.Groups[2], fallback: 0);
        int build = ParseGroup(match.Groups[3], fallback: 0);
        int revision = ParseGroup(match.Groups[4], fallback: 0);

        version = new Version(major, minor, build, revision);
        return true;
    }

    private static int ParseGroup(Group group, int fallback)
    {
        return group.Success && int.TryParse(group.Value, out int parsed)
            ? parsed
            : fallback;
    }
}

internal sealed record AppReleaseSnapshot(AppReleaseInfo[] Releases, AppReleaseInfo? LatestStableRelease);

internal sealed class GitHubReleaseApiItem
{
    [JsonPropertyName("tag_name")]
    public string? TagName { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("body")]
    public string? Body { get; set; }

    [JsonPropertyName("html_url")]
    public string? HtmlUrl { get; set; }

    [JsonPropertyName("prerelease")]
    public bool Prerelease { get; set; }

    [JsonPropertyName("draft")]
    public bool Draft { get; set; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset? CreatedAt { get; set; }

    [JsonPropertyName("published_at")]
    public DateTimeOffset? PublishedAt { get; set; }
}

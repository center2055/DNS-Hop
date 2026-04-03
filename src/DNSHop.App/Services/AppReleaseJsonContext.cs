using System.Text.Json.Serialization;

namespace DNSHop.App.Services;

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(GitHubReleaseApiItem[]))]
internal partial class AppReleaseJsonContext : JsonSerializerContext
{
}

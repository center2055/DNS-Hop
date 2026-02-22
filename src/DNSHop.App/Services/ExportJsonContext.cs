using System.Text.Json.Serialization;

namespace DNSHop.App.Services;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(ExportRow[]))]
internal partial class ExportJsonContext : JsonSerializerContext
{
}

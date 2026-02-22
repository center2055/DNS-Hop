# DNSHop publish helper for a single-file self-contained Windows 64-bit build.
# Note: Avalonia/SukiUI emit trim-analysis warnings. If runtime trimming causes issues,
# set /p:PublishTrimmed=false while keeping single-file publish.
dotnet publish src/DNSHop.App/DNSHop.App.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  /p:PublishSingleFile=true `
  /p:PublishTrimmed=true `
  /p:TrimMode=partial `
  /p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts/publish-win-x64


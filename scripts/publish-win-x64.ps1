# DNSHop publish helper for a single-file self-contained Windows 64-bit build.
# If runtime trimming causes issues, set /p:PublishTrimmed=false while keeping
# single-file publish.
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $RepoRoot
try {
    dotnet publish src/DNSHop.App/DNSHop.App.csproj `
        -c Release `
        -r win-x64 `
        --self-contained true `
        /p:PublishSingleFile=true `
        /p:PublishTrimmed=true `
        /p:TrimMode=partial `
        /p:IncludeNativeLibrariesForSelfExtract=true `
        -o artifacts/publish-win-x64-release

    & (Join-Path $PSScriptRoot 'package-win-portable.ps1') `
        -PublishDir (Join-Path $RepoRoot 'artifacts\publish-win-x64-release') `
        -ProjectPath (Join-Path $RepoRoot 'src\DNSHop.App\DNSHop.App.csproj')
}
finally {
    Pop-Location
}

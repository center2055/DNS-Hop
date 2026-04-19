param(
    [string]$PublishDir = "artifacts\publish-win-x64-release",
    [string]$ProjectPath = "src\DNSHop.App\DNSHop.App.csproj",
    [string]$OutputZip = ""
)

$ErrorActionPreference = 'Stop'

function Get-PortableVersionLabel {
    param(
        [string]$ResolvedProjectPath
    )

    [xml]$projectXml = Get-Content -Path $ResolvedProjectPath

    $informationalVersion = $projectXml.Project.PropertyGroup.InformationalVersion |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -First 1

    if (-not [string]::IsNullOrWhiteSpace($informationalVersion)) {
        return $informationalVersion.Trim()
    }

    $version = $projectXml.Project.PropertyGroup.Version |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -First 1

    if (-not [string]::IsNullOrWhiteSpace($version)) {
        return $version.Trim()
    }

    throw "Unable to resolve app version from $ResolvedProjectPath."
}

$resolvedPublishDir = (Resolve-Path $PublishDir).Path
$resolvedProjectPath = (Resolve-Path $ProjectPath).Path

if (-not (Test-Path $resolvedPublishDir -PathType Container)) {
    throw "Publish directory not found: $resolvedPublishDir"
}

if ([string]::IsNullOrWhiteSpace($OutputZip)) {
    $versionLabel = Get-PortableVersionLabel -ResolvedProjectPath $resolvedProjectPath
    $OutputZip = Join-Path (Split-Path $resolvedPublishDir -Parent) "DNS-Hop-Portable-v$versionLabel.zip"
}

$resolvedOutputZip = [System.IO.Path]::GetFullPath($OutputZip)
$outputDirectory = Split-Path $resolvedOutputZip -Parent

if (-not (Test-Path $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

if (Test-Path $resolvedOutputZip) {
    Remove-Item $resolvedOutputZip -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$files = Get-ChildItem -Path $resolvedPublishDir -File -Recurse | Sort-Object FullName
$normalizedPublishRoot = $resolvedPublishDir.TrimEnd('\', '/')

if ($files.Count -eq 0) {
    throw "No files found in $resolvedPublishDir."
}

$archive = [System.IO.Compression.ZipFile]::Open($resolvedOutputZip, [System.IO.Compression.ZipArchiveMode]::Create)

try {
    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($normalizedPublishRoot.Length).TrimStart('\', '/').Replace('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $archive,
            $file.FullName,
            $relativePath,
            [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
}
finally {
    $archive.Dispose()
}

Write-Host "Built $resolvedOutputZip"

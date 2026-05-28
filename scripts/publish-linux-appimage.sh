#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGE_SCRIPT="$SCRIPT_DIR/package-linux-appimage.sh"
PUBLISH_DIR="$ROOT_DIR/artifacts/publish-linux-x64-appimage"
OUTPUT_APPIMAGE="$ROOT_DIR/artifacts/DNSHop-linux-x86_64.AppImage"
ICON_SOURCE="$ROOT_DIR/assets/DNSHopLogo.png"
mkdir -p "$PUBLISH_DIR"

dotnet publish "$ROOT_DIR/src/DNSHop.App/DNSHop.App.csproj" \
  -c Release \
  -r linux-x64 \
  --self-contained true \
  /p:PublishSingleFile=true \
  /p:IncludeNativeLibrariesForSelfExtract=true \
  -o "$PUBLISH_DIR"

"$PACKAGE_SCRIPT" "$PUBLISH_DIR" "$OUTPUT_APPIMAGE" "$ICON_SOURCE"

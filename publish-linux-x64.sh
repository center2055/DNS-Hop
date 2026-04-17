#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_PATH="$ROOT_DIR/src/DNSHop.App/DNSHop.App.csproj"
OUTPUT_PATH="$ROOT_DIR/artifacts/publish-linux-x64"

dotnet publish "$PROJECT_PATH" \
  -c Release \
  -r linux-x64 \
  --self-contained true \
  /p:PublishSingleFile=true \
  /p:IncludeNativeLibrariesForSelfExtract=true \
  -o "$OUTPUT_PATH"

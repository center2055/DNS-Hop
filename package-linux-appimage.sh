#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <publish-dir> <output-appimage> [icon-png]" >&2
  exit 1
fi

PUBLISH_DIR="$(cd "$1" && pwd)"
OUTPUT_APPIMAGE="$(mkdir -p "$(dirname "$2")" && cd "$(dirname "$2")" && pwd)/$(basename "$2")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICON_SOURCE="${3:-$SCRIPT_DIR/DNSHopLogo.png}"
TOOLS_DIR="$HOME/.cache/dnshop-appimage-tools"
APPIMAGETOOL="$TOOLS_DIR/appimagetool-x86_64.AppImage"
APPDIR="$(mktemp -d "${TMPDIR:-/tmp}/dnshop-appdir.XXXXXX")"
DESKTOP_ID="io.github.center2055.dnshop"
APPIMAGETOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"

cleanup() {
  rm -rf "$APPDIR"
}

trap cleanup EXIT

download_file() {
  local url="$1"
  local output="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$output" "$url"
    return
  fi

  echo "Either curl or wget is required to download AppImage tooling." >&2
  exit 1
}

mkdir -p "$TOOLS_DIR"

if [[ ! -f "$PUBLISH_DIR/DNSHop.App" ]]; then
  echo "Missing $PUBLISH_DIR/DNSHop.App" >&2
  exit 1
fi

if [[ ! -f "$PUBLISH_DIR/New Public DNS Resolvers.ini" ]]; then
  echo "Missing $PUBLISH_DIR/New Public DNS Resolvers.ini" >&2
  exit 1
fi

if [[ ! -f "$ICON_SOURCE" ]]; then
  echo "Missing icon: $ICON_SOURCE" >&2
  exit 1
fi

if [[ ! -f "$APPIMAGETOOL" ]]; then
  download_file "$APPIMAGETOOL_URL" "$APPIMAGETOOL"
  chmod +x "$APPIMAGETOOL"
fi

mkdir -p "$APPDIR/usr/bin" \
         "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
         "$APPDIR/usr/share/metainfo"

cp "$PUBLISH_DIR/DNSHop.App" "$APPDIR/usr/bin/DNSHop.App"
cp "$PUBLISH_DIR/New Public DNS Resolvers.ini" "$APPDIR/usr/bin/New Public DNS Resolvers.ini"
cp "$ICON_SOURCE" "$APPDIR/$DESKTOP_ID.png"
cp "$ICON_SOURCE" "$APPDIR/.DirIcon"
cp "$ICON_SOURCE" "$APPDIR/usr/share/icons/hicolor/256x256/apps/$DESKTOP_ID.png"

cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/usr/bin/DNSHop.App" "$@"
EOF
chmod +x "$APPDIR/AppRun" "$APPDIR/usr/bin/DNSHop.App"

cat > "$APPDIR/$DESKTOP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=DNS Hop
Comment=Modern DNS benchmark and resolver switcher
Exec=DNSHop.App
Icon=$DESKTOP_ID
Terminal=false
Categories=Network;Utility;
StartupNotify=true
EOF
cp "$APPDIR/$DESKTOP_ID.desktop" "$APPDIR/usr/share/applications/$DESKTOP_ID.desktop"

cat > "$APPDIR/usr/share/metainfo/$DESKTOP_ID.appdata.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>$DESKTOP_ID.desktop</id>
  <name>DNS Hop</name>
  <summary>Modern DNS benchmark and resolver switcher</summary>
  <metadata_license>FSFAP</metadata_license>
  <project_license>GPL-3.0-only</project_license>
  <url type="homepage">https://github.com/center2055/DNS-Hop</url>
  <description>
    <p>DNS Hop benchmarks DNS resolvers and can apply classic DNS endpoints as the system resolver.</p>
  </description>
  <launchable type="desktop-id">$DESKTOP_ID.desktop</launchable>
  <provides>
    <binary>DNSHop.App</binary>
  </provides>
</component>
EOF

ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL" "$APPDIR" "$OUTPUT_APPIMAGE"

echo "Built $OUTPUT_APPIMAGE"

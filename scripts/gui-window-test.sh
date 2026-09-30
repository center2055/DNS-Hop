#!/usr/bin/env bash
# Launch the AppImage and check that it actually puts a window on screen.
#
# The distro smoke tests extract the AppImage and run it with --smoke-test, so they
# prove the binary and its dependencies work but never mount the image and never open
# a window. AppImageHub, which decides whether the app is listed in the catalogue,
# does the opposite: it mounts the AppImage and requires a visible window. This covers
# that gap, in both the plain and the sandboxed form the catalogue uses.
set -uo pipefail

APPIMAGE="${1:?usage: gui-window-test.sh <appimage> [direct|firejail]}"
MODE="${2:-direct}"

if [[ ! -f "$APPIMAGE" ]]; then
  echo "No such AppImage: $APPIMAGE" >&2
  exit 2
fi

chmod +x "$APPIMAGE"

case "$MODE" in
  direct)
    "./$APPIMAGE" &
    ;;
  firejail)
    # The exact invocation AppImageHub uses while deciding whether to list an entry.
    firejail --quiet --noprofile --net=none --appimage "./$APPIMAGE" &
    ;;
  *)
    echo "Unknown mode '$MODE' (expected 'direct' or 'firejail')" >&2
    exit 2
    ;;
esac
APP_PID=$!

# Same test AppImageHub applies: any mapped top level window counts.
window_present() {
  timeout 5 xwininfo -tree -root 2>/dev/null | grep -qE '0x.*": \('
}

# Several seconds of grace first, because a toolkit can take a while to map its window.
sleep 10

for _ in $(seq 1 30); do
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    wait "$APP_PID" 2>/dev/null
    rc=$?
    echo "FAIL [$MODE]: the application exited before showing a window (exit $rc)"
    exit 1
  fi

  if window_present; then
    sleep 2 # let it finish drawing
    echo "PASS [$MODE]: a window appeared"
    timeout 5 xwininfo -tree -root 2>/dev/null | grep -E '0x.*": \(' | head -n 5
    kill "$APP_PID" 2>/dev/null
    exit 0
  fi

  sleep 1
done

echo "FAIL [$MODE]: the application is still running but never put a window on screen"
kill "$APP_PID" 2>/dev/null
exit 1

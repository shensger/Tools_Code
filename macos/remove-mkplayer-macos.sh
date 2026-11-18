#!/bin/bash
# remove-mkplayer-macos.sh
#
# Removes MKPlayer.app from a Mac. It bundles nginx 1.15.5
# (Contents/Resources/nginx/nginx), which the Detect-Nginx2Root-Mac scan flags
# as REVIEW.
#
# What it does
#   1. Quits MKPlayer and its bundled nginx if they are running.
#   2. Deletes MKPlayer.app from /Applications and from every user's
#      ~/Applications.
#   3. Confirms nothing is left and exits 1 if any copy remains.
#
# Not removed: the app's settings/caches in ~/Library (harmless without the app).
# If the app was deployed by Jamf/MDM it may be reinstalled - remove it from
# that policy too.
#
# Usage (NinjaOne runs macOS scripts as root): sudo ./remove-mkplayer-macos.sh

set -u
APP="MKPlayer.app"

targets=()
[ -d "/Applications/$APP" ] && targets+=("/Applications/$APP")
for home in /Users/*; do
  [ -d "$home/Applications/$APP" ] && targets+=("$home/Applications/$APP")
done

if [ ${#targets[@]} -eq 0 ]; then
  echo "NOT FOUND: no $APP on $(hostname -s)"
  exit 0
fi

for t in "${targets[@]}"; do
  echo "Found: $t ($(defaults read "$t/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo '?'))"
  # Quit anything running from inside the bundle (the app and its nginx)
  pids=$(ps -axo pid=,command= | awk -v p="$t/" 'index($0, p) { print $1 }')
  if [ -n "$pids" ]; then
    echo "  Stopping processes: $pids"
    kill $pids 2>/dev/null; sleep 3
    pids=$(ps -axo pid=,command= | awk -v p="$t/" 'index($0, p) { print $1 }')
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null
  fi
  rm -rf "$t" && echo "  Removed $t" || echo "  ERROR: could not remove $t"
done

left=0
for t in "${targets[@]}"; do [ -e "$t" ] && { echo "STILL PRESENT: $t"; left=1; }; done
[ "$left" = 0 ] && echo "DONE: $APP removed from $(hostname -s)"
exit $left

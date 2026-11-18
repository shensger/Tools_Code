#!/bin/bash
# remove-macos-app.sh
#
# Removes one app bundle from a Mac by name, e.g. "Slack" or "MKPlayer.app".
# Generic version of remove-mkplayer-macos.sh.
#
# What it does
#   1. Quits every process running from inside the bundle.
#   2. Deletes <name>.app from /Applications and from every user's ~/Applications.
#   3. Confirms nothing is left; exits 1 if a copy remains, 2 on bad input.
#
# Not removed: the app's settings/caches in ~/Library. Apple's own apps are
# refused (they live on the sealed system volume anyway). If the app was
# deployed by Jamf/MDM it may be reinstalled - remove it from that policy too.
#
# Usage (NinjaOne runs macOS scripts as root)
#   NinjaOne script variable (env): appName   e.g. Slack
#   or: sudo ./remove-macos-app.sh "Slack"

set -u
NAME="${appName:-${1:-}}"
NAME="${NAME%.app}"
if [ -z "$NAME" ] || [[ "$NAME" == */* ]] || [[ "$NAME" == .* ]]; then
  echo "ERROR: set appName to the app's name, e.g. Slack (no paths)"
  exit 2
fi
APP="$NAME.app"

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
  bid=$(defaults read "$t/Contents/Info" CFBundleIdentifier 2>/dev/null || echo '?')
  ver=$(defaults read "$t/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo '?')
  case "$bid" in com.apple.*) echo "REFUSED: $t is an Apple app ($bid)"; exit 2 ;; esac
  echo "Found: $t ($bid $ver)"
  pids=$(ps -axo pid=,command= | awk -v p="$t/" 'index($0, p) { print $1 }')
  if [ -n "$pids" ]; then
    echo "  Stopping processes: $(echo $pids)"
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

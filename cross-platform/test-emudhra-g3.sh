#!/bin/sh
# test-emudhra-g3.sh - macOS and Linux (any distro, POSIX sh).
#
# Equivalent of:
#   curl -sS https://dv-g3b-emudhra.we-have-a-problem.com/ ; echo "exit=$?"
#
# Hits the eMudhra G3 test host (chained to the compromised EM DV TLS CA - G3B)
# using the OS trust store. A TLS/certificate failure is the GOOD result: it means
# this machine no longer trusts the compromised chain.
#
# Uses curl if present, otherwise wget. Prints the tool output, "exit=N", and a
# one-line verdict.
#
# NinjaOne: when the Ninja agent's ninjarmm-cli is present (macOS or Linux agent),
# writes a one-line result to a device text custom field (default
# 'emudhraG3Status'), e.g.  OK | exit=60 | curl | 2026-10-22 09:20
# The first word is always OK, VULNERABLE or INCONCLUSIVE. Create the field as
# Text, device scope, Automations = Read/Write. Override the name with script
# variable ninjaField; "none" disables.
#
# Exit code: outside Ninja, the tool's own exit code. Under Ninja, the verdict
# instead - 0 OK, 1 VULNERABLE, 2 INCONCLUSIVE - so a good result doesn't show as
# a failed run.
#
# Usage:  sh test-emudhra-g3.sh [url]

URL="${1:-https://dv-g3b-emudhra.we-have-a-problem.com/}"
NINJA_FIELD="${ninjaField:-emudhraG3Status}"

NINJA_CLI=""
for c in /opt/NinjaRMMAgent/programdata/ninjarmm-cli \
         /Applications/NinjaRMMAgent/programdata/ninjarmm-cli; do
    [ -x "$c" ] && { NINJA_CLI="$c"; break; }
done

if command -v curl >/dev/null 2>&1; then
    TOOL=curl
    curl -sS --max-time 15 "$URL"
    rc=$?
    # curl: 0 = connected, 35 = TLS handshake fail, 51/58/60/77 = cert problems
    case $rc in
        0)              verdict="VULNERABLE: connected - this host still trusts the compromised chain" ;;
        35|51|58|60|77) verdict="OK: TLS/certificate rejected - compromised chain not trusted" ;;
        *)              verdict="INCONCLUSIVE: curl failed for a non-TLS reason (DNS/network/timeout?)" ;;
    esac
elif command -v wget >/dev/null 2>&1; then
    TOOL=wget
    wget -q -T 15 -O - "$URL"
    rc=$?
    # wget: 0 = connected, 5 = SSL verification failure
    case $rc in
        0) verdict="VULNERABLE: connected - this host still trusts the compromised chain" ;;
        5) verdict="OK: TLS/certificate rejected - compromised chain not trusted" ;;
        *) verdict="INCONCLUSIVE: wget failed for a non-TLS reason (DNS/network/timeout?)" ;;
    esac
else
    TOOL=none
    rc=127
    echo "ERROR: neither curl nor wget is installed" >&2
    verdict="INCONCLUSIVE: neither curl nor wget is installed"
fi

echo
echo "exit=$rc"
echo "[$(uname -s) / $TOOL] $verdict"

# --- NinjaOne custom field ---------------------------------------------------
status="${verdict%%:*}"
if [ -n "$NINJA_CLI" ] && [ -n "$NINJA_FIELD" ] && [ "$NINJA_FIELD" != "none" ]; then
    value="$status | exit=$rc | $TOOL | $(date '+%Y-%m-%d %H:%M')"
    if out=$("$NINJA_CLI" set "$NINJA_FIELD" "$value" 2>&1); then
        echo "Wrote to NinjaOne field '$NINJA_FIELD': $value"
    else
        echo "NinjaOne field write failed: $out. Check that text field '$NINJA_FIELD' exists, applies to this device, and has Automations = Write."
    fi
fi

if [ -n "$NINJA_CLI" ]; then
    case $status in
        OK)         exit 0 ;;
        VULNERABLE) exit 1 ;;
        *)          exit 2 ;;
    esac
fi
exit $rc

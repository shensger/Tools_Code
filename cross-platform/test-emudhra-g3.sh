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
# one-line verdict. The script exits with the tool's own exit code.
#
# Usage:  sh test-emudhra-g3.sh [url]

URL="${1:-https://dv-g3b-emudhra.we-have-a-problem.com/}"

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
    echo "ERROR: neither curl nor wget is installed" >&2
    echo "exit=127"
    exit 127
fi

echo
echo "exit=$rc"
echo "[$(uname -s) / $TOOL] $verdict"
exit $rc

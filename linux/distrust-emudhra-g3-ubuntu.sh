#!/usr/bin/env bash
# distrust-emudhra-g3-ubuntu.sh
#
# Ubuntu / Debian version of distrust-emudhra-g3.sh. Disables the compromised
# eMudhra root (emSign ECC Root CA - G3, October 2026 intermediate key
# compromise, Mozilla bug 2083449) in the system trust store by marking its
# line in /etc/ca-certificates.conf with "!" and rebuilding
# /etc/ssl/certs/ca-certificates.crt. Removing the root breaks every
# EM ... TLS CA - G3B/G3C chain, so no separate intermediate blocklist is needed.
#
# The root is identified by SHA-256 fingerprint, not by file name. Backs up
# ca-certificates.conf first. Safe to re-run.
#
# Usage:  sudo ./distrust-emudhra-g3-ubuntu.sh
# Verify: ../cross-platform/test-emudhra-g3.sh
#
# Exit codes: 0 = disabled (or already gone) and test host rejected
#             1 = error, nothing changed
#             2 = applied, but the test host is still accepted

set -euo pipefail

TEST_HOST="dv-g3b-emudhra.we-have-a-problem.com"
ROOT_FP="86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
CONF="/etc/ca-certificates.conf"
CERTDIR="/usr/share/ca-certificates"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
command -v update-ca-certificates >/dev/null || die "update-ca-certificates not found (not Ubuntu/Debian?)"
command -v openssl >/dev/null || die "openssl not found"
[[ -f "$CONF" ]] || die "$CONF not found"

# Find the cert file whose fingerprint matches the root
entry=""
while IFS= read -r line; do
    name="${line#!}"
    [[ -z "$name" || "$name" == \#* ]] && continue
    f="$CERTDIR/$name"
    [[ -f "$f" ]] || continue
    if [[ "$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')" == "$ROOT_FP" ]]; then
        entry="$line"; break
    fi
done < "$CONF"

if [[ -z "$entry" ]]; then
    log "emSign ECC Root CA - G3 is not in $CONF (package already updated?) - nothing to disable"
elif [[ "$entry" == !* ]]; then
    log "already disabled: $entry"
else
    cp -p "$CONF" "$CONF.bak.$(date +%Y%m%d%H%M%S)"
    # exact-line match, escape regex metacharacters in the file name
    esc=$(printf '%s' "$entry" | sed 's/[][\.*^$/]/\\&/g')
    sed -i "s/^${esc}\$/!${esc}/" "$CONF"
    grep -qxF "!$entry" "$CONF" || die "failed to mark $entry in $CONF"
    log "disabled: !$entry"
fi

update-ca-certificates --fresh >/dev/null
log "trust store rebuilt"

if out=$(curl -sS --max-time 15 "https://${TEST_HOST}/" 2>&1); then
    log "STILL CONNECTING: $out"
    log "dump the chain: openssl s_client -connect ${TEST_HOST}:443 -servername ${TEST_HOST} -showcerts </dev/null"
    exit 2
fi
log "OK: curl rejects the compromised chain (${out##*curl: })"
exit 0

#!/usr/bin/env bash
# distrust-emudhra-g3.sh
#
# Blocklists the compromised eMudhra trust path (October 2026 intermediate CA
# key compromise, Mozilla bug 2083449) in the RHEL-family system trust store:
#   - emSign ECC Root CA - G3   (root; removes it from ca-bundle.crt so OpenSSL/curl reject the chain)
#   - EM DV TLS CA - G3B       (intermediate served by the public test host)
#
# For hosts that can't get a fixed ca-certificates package (e.g. EOL CentOS
# Stream 8 / CentOS 8). Safe to re-run. Both certs are fingerprint-checked
# before anything is written; nothing is applied on a mismatch.
#
# Usage:  sudo ./distrust-emudhra-g3.sh            # apply + verify
#         sudo ./distrust-emudhra-g3.sh --check    # verify only, change nothing
#
# Exit codes: 0 = host rejects the test host (good)
#             1 = error / nothing applied
#             2 = applied, but the test host is still accepted (investigate the chain)
#             3 = --check: host is still vulnerable

set -euo pipefail

TEST_HOST="dv-g3b-emudhra.we-have-a-problem.com"
ROOT_CN="emSign ECC Root CA - G3"
ROOT_FP="86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
INT_CN="EM DV TLS CA - G3B"
INT_FP="42:C4:AC:CD:12:C4:F5:95:97:92:5E:1A:08:A7:A9:01:02:60:85:43:80:93:08:D5:0E:C4:27:E1:18:BA:14:93"
BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { log "ERROR: $*"; exit 1; }

fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }

# Returns 0 if curl rejects the test host (the result we want).
test_host_rejected() {
    local out
    if out=$(curl -sS --max-time 15 "https://${TEST_HOST}/" 2>&1); then
        log "curl CONNECTED: ${out}"
        return 1
    fi
    log "curl rejected the connection: ${out##*curl: }"
    return 0
}

[[ $EUID -eq 0 ]] || die "run as root"
command -v openssl >/dev/null        || die "openssl not found"
command -v update-ca-trust >/dev/null || die "update-ca-trust not found (not a RHEL-family host?)"

if [[ "${1:-}" == "--check" ]]; then
    trust list 2>/dev/null | grep -i -B2 -A4 -E 'emsign|EM DV TLS' || log "no emSign entries in trust list"
    test_host_rejected && { log "OK: host rejects the compromised chain"; exit 0; }
    log "VULNERABLE: host still trusts the compromised chain"; exit 3
fi

# RHEL 9+ renamed blacklist -> blocklist
if   [[ -d /etc/pki/ca-trust/source/blocklist ]]; then BL=/etc/pki/ca-trust/source/blocklist
elif [[ -d /etc/pki/ca-trust/source/blacklist ]]; then BL=/etc/pki/ca-trust/source/blacklist
else die "no ca-trust blocklist/blacklist directory found"; fi
log "blocklist dir: $BL"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# --- 1. Root: find emSign ECC Root CA - G3 in the bundle by subject, not by comment text
ROOT_OUT="$BL/emsign-ecc-root-ca-g3.pem"
if [[ -f "$ROOT_OUT" && "$(fp "$ROOT_OUT")" == "$ROOT_FP" ]]; then
    log "root already blocklisted"
else
    awk -v d="$WORK" '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("%s/c%04d.pem",d,n)} f{print > f} /-----END CERTIFICATE-----/{close(f); f=""}' "$BUNDLE"
    found=""
    for c in "$WORK"/c*.pem; do
        [[ "$(fp "$c")" == "$ROOT_FP" ]] && { found="$c"; break; }
    done
    if [[ -n "$found" ]]; then
        cp "$found" "$ROOT_OUT"
        log "root blocklisted: $(openssl x509 -in "$ROOT_OUT" -noout -subject)"
    else
        log "WARN: $ROOT_CN not present in $BUNDLE (already removed?) - skipping root"
    fi
fi

# --- 2. Intermediate: pull from the test host, verify fingerprint before writing
INT_OUT="$BL/em-dv-tls-ca-g3b.pem"
if [[ -f "$INT_OUT" && "$(fp "$INT_OUT")" == "$INT_FP" ]]; then
    log "intermediate already blocklisted"
else
    openssl s_client -connect "${TEST_HOST}:443" -servername "$TEST_HOST" -showcerts </dev/null 2>/dev/null \
        | awk '/BEGIN CERT/{n++} n==2' | sed '/END CERT/q' > "$WORK/int.pem" || true
    if [[ -s "$WORK/int.pem" && "$(fp "$WORK/int.pem")" == "$INT_FP" ]]; then
        cp "$WORK/int.pem" "$INT_OUT"
        log "intermediate blocklisted: $(openssl x509 -in "$INT_OUT" -noout -subject)"
    else
        log "WARN: could not fetch/verify $INT_CN from $TEST_HOST - skipping intermediate"
    fi
fi

[[ -f "$ROOT_OUT" || -f "$INT_OUT" ]] || die "nothing to apply"

# --- 3. Apply and verify
update-ca-trust extract
log "trust store re-extracted"

if grep -q "$ROOT_CN" "$BUNDLE"; then
    log "WARN: '$ROOT_CN' label still appears in $BUNDLE"
fi

if test_host_rejected; then
    log "DONE: host now rejects the compromised eMudhra chain"
    exit 0
fi
log "Still connecting - dump the chain with:"
log "  openssl s_client -connect ${TEST_HOST}:443 -servername ${TEST_HOST} -showcerts </dev/null"
log "It may be validating via the Sectigo cross-sign; do NOT blocklist Sectigo's AAA root blindly."
exit 2

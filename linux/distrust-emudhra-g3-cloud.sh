#!/bin/bash
# distrust-emudhra-g3-cloud.sh
#
# Amazon Linux / Azure Linux remediation for the October 2026 eMudhra G3
# intermediate CA key compromise (Mozilla bug 2083449). Cloud-distro version of
# distrust-emudhra-g3.sh (RHEL) and distrust-emudhra-g3-ubuntu.sh.
#
# Supported (all use p11-kit + update-ca-trust; tested in the official images)
#   Amazon Linux 2023   fix: ca-certificates-2025.2.76-1.0.amzn2023.0.4 (ALAS2023-2026-3306)
#                       NOTE: AL2023 repos are version-locked - the fix is only
#                       visible with --releasever=latest, which this script uses.
#   Amazon Linux 2      fix: ca-certificates-2025.2.76-1.amzn2.0.3 (ALAS2-2026-4037)
#   Azure Linux 3.0     ca-certificates(-base) 3.0.0-19 does not contain the root;
#                       the script just verifies.
#   CBL-Mariner 2.0     NO vendor fix - ca-certificates 2.0.0-25 still ships the
#                       root (Mariner 2.0 is EOL), so it is blocklisted locally.
#   Other p11-kit / RHEL-family distros work too (warning only).
#   AAA Certificate Services: Amazon Linux keeps it out of the TLS bundle
#   (non-TLS trust only), so the Sectigo cross-sign path is already closed there;
#   CBL-Mariner 2.0 trusts it for TLS - use --include-aaa on Mariner.
#
# What it does
#   1. Updates ca-certificates from the vendor repo (dnf / yum / tdnf).
#      Skip with --no-update (e.g. no repo access, change freeze).
#   2. Scans the extracted system bundle by SHA-256 fingerprint - not by label,
#      the distros label these roots differently. If emSign ECC Root CA - G3 is
#      still there, copies it into /etc/pki/ca-trust/source/blocklist (blacklist
#      on AL2) and runs update-ca-trust extract, so it stays out on re-extract.
#   3. --include-aaa also blocklists "AAA Certificate Services" (Comodo/Sectigo).
#      Sectigo cross-signed the same compromised keys under that root and the
#      Amazon fix leaves it trusted. Off by default because it can break CLI
#      access to legitimate Sectigo sites (same as the macOS script).
#   4. If a control site (aws.amazon.com / www.microsoft.com) worked before and
#      fails after, removes this run's blocklist files and re-extracts.
#   5. Live-tests https://dv-g3b-emudhra.we-have-a-problem.com/ (and the Sectigo
#      cross-sign host) with curl. On hosts with no egress the verdict comes from
#      the bundle scan.
#   6. Reports app-bundled CA files that still contain either root (AWS CLI v2,
#      Azure CLI, pip/certifi, /opt) - reported only, never modified.
#   7. Writes the NinjaOne field emudhraG3Status when the Ninja agent is
#      installed, in the detection script's format:  OK | exit=60 | curl | <date>
#
# Pure bash + coreutils: no openssl or awk needed (the AL images have no
# openssl, the Azure Linux images have no awk).
#
# Usage (as root)
#   distrust-emudhra-g3-cloud.sh                  update + blocklist + verify
#   distrust-emudhra-g3-cloud.sh --include-aaa    also distrust AAA Certificate Services
#   distrust-emudhra-g3-cloud.sh --no-update      don't touch packages, blocklist only
#   distrust-emudhra-g3-cloud.sh --check          report only, change nothing
#   distrust-emudhra-g3-cloud.sh --rollback       remove the blocklist files this script added
#   NinjaOne script variables: ninjaField (default emudhraG3Status, "none"
#   disables), includeAaa, noUpdate (true/false). Arguments work too.
#   Rollback does not downgrade the package (dnf/yum downgrade ca-certificates).
#
# Exit codes (same as the macOS script):
#   0 = OK   1 = VULNERABLE or error   2 = INCONCLUSIVE   3 = not run as root

set -u

TEST_URL="https://dv-g3b-emudhra.we-have-a-problem.com/"
AAA_TEST_URL="https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
ROOT_CN="emSign ECC Root CA - G3"
ROOT_FP="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"
AAA_CN="AAA Certificate Services"
AAA_FP="D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4"

BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
STATE_DIR="/var/lib/emudhra-g3"
NINJA_FIELD="${ninjaField:-emudhraG3Status}"
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

MODE=apply; INCLUDE_AAA=false; DO_UPDATE=true
case "${includeAaa:-}" in true|TRUE|True|1|yes) INCLUDE_AAA=true ;; esac
case "${noUpdate:-}"   in true|TRUE|True|1|yes) DO_UPDATE=false ;; esac
for a in "$@"; do
    case "$a" in
        --check)       MODE=check ;;
        --rollback)    MODE=rollback ;;
        --include-aaa) INCLUDE_AAA=true ;;
        --no-update)   DO_UPDATE=false ;;
        -h|--help)     sed -n '2,57p' "$0"; exit 0 ;;
        *)             echo "Unknown argument: $a"; exit 1 ;;
    esac
done

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root."; exit 3; }
for c in update-ca-trust base64 sha256sum curl; do
    command -v "$c" >/dev/null 2>&1 || { log "$c not found"; [ "$c" = curl ] || exit 1; }
done

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

. /etc/os-release 2>/dev/null
OS="${ID:-unknown} ${VERSION_ID:-}"
case "${ID:-}" in
    amzn)               CONTROL_URL="https://aws.amazon.com/" ;;
    azurelinux|mariner) CONTROL_URL="https://www.microsoft.com/" ;;
    *)                  CONTROL_URL="https://www.microsoft.com/"
                        log "WARN: $OS is not Amazon/Azure Linux - continuing as a generic p11-kit distro" ;;
esac

if   [ -d /etc/pki/ca-trust/source/blocklist ]; then BL=/etc/pki/ca-trust/source/blocklist
elif [ -d /etc/pki/ca-trust/source/blacklist ]; then BL=/etc/pki/ca-trust/source/blacklist
else log "no ca-trust blocklist/blacklist directory"; exit 1; fi

# ---- helpers ------------------------------------------------------------------
fp() { sed '/-----/d' "$1" | base64 -d 2>/dev/null | sha256sum | cut -c1-64 | tr 'a-f' 'A-F'; }

split_bundle() {  # split_bundle <bundle> <dir>  -> <dir>/1.pem ...  (no awk)
    local n=0 f="" l
    while IFS= read -r l || [ -n "$l" ]; do
        case "$l" in *"-----BEGIN CERTIFICATE-----"*) n=$((n + 1)); f="$2/$n.pem" ;; esac
        [ -n "$f" ] && printf '%s\n' "$l" >> "$f"
        case "$l" in *"-----END CERTIFICATE-----"*) f="" ;; esac
    done < "$1"
}

find_in() {  # find_in <bundle> <fp> [copy-to]  -> 0 if present
    local d c rc=1
    d=$(mktemp -d -p "$WORK") || return 1
    split_bundle "$1" "$d"
    for c in "$d"/*.pem; do
        [ -e "$c" ] || continue
        if [ "$(fp "$c")" = "$2" ]; then
            [ -n "${3:-}" ] && cp "$c" "$3"
            rc=0; break
        fi
    done
    rm -rf "$d"; return $rc
}

classify() {  # curl exit code -> OK / VULNERABLE / INCONCLUSIVE
    case "$1" in
        0)              echo VULNERABLE ;;
        35|51|58|60|77) echo OK ;;
        *)              echo INCONCLUSIVE ;;
    esac
}

probe() { curl -sS -o /dev/null --max-time 15 "$1" >/dev/null 2>&1; echo $?; }

store_state() {  # sets ROOT_IN, AAA_IN (yes/no) from the extracted bundle
    ROOT_IN=no; AAA_IN=no
    find_in "$BUNDLE" "$ROOT_FP" && ROOT_IN=yes
    find_in "$BUNDLE" "$AAA_FP"  && AAA_IN=yes
    log "System bundle: $ROOT_CN: $ROOT_IN | $AAA_CN: $AAA_IN ($(grep -c 'BEGIN CERTIFICATE' "$BUNDLE") certs)"
}

pkg_ver() { rpm -q --qf '%{VERSION}-%{RELEASE}\n' ca-certificates 2>/dev/null | head -1 | sed 's/^package .*/not installed/'; }

update_pkg() {
    local before after
    before=$(pkg_ver)
    if ! rpm -q ca-certificates >/dev/null 2>&1; then
        log "ca-certificates not installed (only ca-certificates-base?) - skipping package update"; return
    fi
    log "Updating ca-certificates (installed: $before)"
    case "${ID:-}" in
        amzn) if [ "${VERSION_ID:-}" = 2023 ]; then
                  dnf -q -y upgrade --releasever=latest ca-certificates >"$WORK/pkg.log" 2>&1
              else
                  yum -q -y update ca-certificates >"$WORK/pkg.log" 2>&1
              fi ;;
        *)    if   command -v tdnf >/dev/null 2>&1; then tdnf -q -y update ca-certificates >"$WORK/pkg.log" 2>&1
              elif command -v dnf  >/dev/null 2>&1; then dnf  -q -y upgrade ca-certificates >"$WORK/pkg.log" 2>&1
              else yum -q -y update ca-certificates >"$WORK/pkg.log" 2>&1; fi ;;
    esac || log "WARN: package update failed (no repo access?): $(tail -1 "$WORK/pkg.log")"
    after=$(pkg_ver)
    [ "$before" = "$after" ] && log "ca-certificates unchanged ($after)" || log "ca-certificates $before -> $after"
}

blocklist() {  # blocklist <fp> <file name> <label>
    local out="$BL/$2"
    if [ -f "$out" ] && [ "$(fp "$out")" = "$1" ]; then log "$3 already blocklisted ($out)"; return 0; fi
    if find_in "$BUNDLE" "$1" "$WORK/cert.pem"; then
        cp "$WORK/cert.pem" "$out" && chmod 644 "$out" || { log "could not write $out"; return 1; }
        mkdir -p "$STATE_DIR" && echo "$out" >> "$STATE_DIR/added"
        echo "$out" >> "$WORK/added-this-run"
        log "Blocklisted $3 -> $out"
        CHANGED=true
    fi
}

app_bundles() {  # report-only scan of app-bundled CA files
    local f hits=0
    if command -v find >/dev/null 2>&1; then
        find /usr/local/aws-cli /usr/lib64/az /opt/az /usr/lib/python3* /usr/lib64/python3* \
             /usr/local/lib/python3* /usr/local/lib64/python3* /opt /root/.local /home/*/.local \
             -xdev -type f \( -name cacert.pem -o -name 'ca-bundle.crt' -o -name 'cacerts.pem' \) \
             2>/dev/null | sort -u > "$WORK/apps"
    else  # minimal images (AL2023) have no findutils - use bash globstar
        ( shopt -s globstar nullglob
          for f in /usr/local/aws-cli/**/cacert.pem /usr/lib*/az/**/cacert.pem /opt/**/cacert.pem \
                   /opt/**/ca-bundle.crt /usr/lib*/python3*/site-packages/**/cacert.pem \
                   /usr/local/lib*/python3*/site-packages/**/cacert.pem \
                   /root/.local/**/cacert.pem /home/*/.local/**/cacert.pem; do
              [ -f "$f" ] && echo "$f"
          done ) | sort -u > "$WORK/apps"
    fi
    while IFS= read -r f; do
        case "$f" in /etc/pki/*) continue ;; esac
        if find_in "$f" "$ROOT_FP"; then log "  CONTAINS $ROOT_CN: $f"; hits=$((hits + 1))
        elif [ "$INCLUDE_AAA" = true ] && find_in "$f" "$AAA_FP"; then log "  CONTAINS $AAA_CN: $f"; hits=$((hits + 1)); fi
    done < "$WORK/apps"
    [ "$hits" -eq 0 ] && log "  none of $(wc -l < "$WORK/apps") app CA files contain the root" \
                      || log "  -> update those apps (AWS CLI / az / pip install -U certifi); this script doesn't edit them"
}

finish() {
    local rc status value cli out
    rc=$(probe "$TEST_URL"); status=$(classify "$rc")
    log "Live test: $TEST_URL -> exit=$rc ($status)"
    if [ "$status" = INCONCLUSIVE ]; then
        if [ "$ROOT_IN" = no ]; then status=OK; log "No egress? Verdict from the bundle scan: root not trusted."
        else status=VULNERABLE; fi
    elif [ "$status" = OK ] && [ "$ROOT_IN" = yes ]; then
        log "WARN: test host rejected but the root is still in the bundle"; status=VULNERABLE
    fi
    arc=$(probe "$AAA_TEST_URL")
    if [ "$(classify "$arc")" = VULNERABLE ]; then
        log "WARN: Sectigo cross-sign path still connects ($AAA_TEST_URL exit=$arc)."
        [ "$INCLUDE_AAA" = true ] || log "      Re-run with --include-aaa (or includeAaa=true) to close it."
    else
        log "Sectigo cross-sign path: exit=$arc ($(classify "$arc"))"
    fi
    value="$status | exit=$rc | curl | $(date '+%Y-%m-%d %H:%M')"
    log "Result: $value"
    if [ -n "$NINJA_FIELD" ] && [ "$NINJA_FIELD" != none ]; then
        cli=/opt/NinjaRMMAgent/programdata/ninjarmm-cli
        if [ -x "$cli" ]; then
            if out=$("$cli" set "$NINJA_FIELD" "$value" 2>&1); then log "Wrote to NinjaOne field '$NINJA_FIELD'"
            else log "NinjaOne field write failed: $out"; fi
        fi
    fi
    case "$status" in OK) exit 0 ;; INCONCLUSIVE) exit 2 ;; *) exit 1 ;; esac
}

# ---- rollback -----------------------------------------------------------------
if [ "$MODE" = rollback ]; then
    [ -s "$STATE_DIR/added" ] || { log "Nothing to roll back ($STATE_DIR/added is empty)"; exit 0; }
    sort -u "$STATE_DIR/added" | while IFS= read -r f; do rm -f "$f" && log "Removed $f"; done
    : > "$STATE_DIR/added"
    update-ca-trust extract && log "update-ca-trust extract done"
    log "Package version left as is ($(pkg_ver)) - downgrade with dnf/yum if needed."
    exit 0
fi

# ---- main ---------------------------------------------------------------------
log "$OS | ca-certificates $(pkg_ver) | mode: $MODE | include AAA: $INCLUDE_AAA | update: $DO_UPDATE"
log "Blocklist dir: $BL"
store_state

if [ "$MODE" = check ]; then
    log "App-bundled CA files:"; app_bundles
    log "Check only - no changes made."; finish
fi

CHANGED=false
crc=$(probe "$CONTROL_URL"); CTRL_BEFORE=$([ "$crc" -eq 0 ] && echo true || echo false)
log "Control site $CONTROL_URL before: exit=$crc"

[ "$DO_UPDATE" = true ] && { update_pkg; store_state; }

[ "$ROOT_IN" = yes ] && blocklist "$ROOT_FP" emsign-ecc-root-ca-g3.pem "$ROOT_CN"
[ "$INCLUDE_AAA" = true ] && [ "$AAA_IN" = yes ] && blocklist "$AAA_FP" aaa-certificate-services.pem "$AAA_CN"

if [ "$CHANGED" = true ]; then
    update-ca-trust extract && log "update-ca-trust extract done"
    if [ "$CTRL_BEFORE" = true ]; then
        crc=$(probe "$CONTROL_URL")
        if [ "$crc" -ne 0 ]; then
            log "Control site failed after the change (exit=$crc) - removing this run's blocklist files"
            while IFS= read -r f; do rm -f "$f"; grep -vxF "$f" "$STATE_DIR/added" > "$WORK/a"; cat "$WORK/a" > "$STATE_DIR/added"; done < "$WORK/added-this-run"
            update-ca-trust extract
        else
            log "Control site still OK"
        fi
    else
        log "Control site unreachable before the change - skipping the control check"
    fi
    store_state
else
    log "No blocklist changes needed."
fi

log "App-bundled CA files:"; app_bundles
finish

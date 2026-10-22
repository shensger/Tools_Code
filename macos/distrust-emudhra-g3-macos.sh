#!/bin/bash
# distrust-emudhra-g3-macos.sh
#
# macOS remediation for the October 2026 eMudhra G3 intermediate CA key
# compromise (Mozilla bug 2083449 / CVE-2026-111943).
#
# Why this is needed on a Mac
#   Apple blocked the eight compromised G3B/G3C intermediates at the OS level on
#   2026-10-19, so Safari and apps that use the macOS trust APIs are protected.
#   The built-in /usr/bin/curl (and git, python3, perl, ruby, openssl) validate
#   against the flat bundle /etc/ssl/cert.pem with no revocation check, so they
#   still accept the compromised chain. macOS version doesn't matter: in our
#   fleet VULNERABLE Macs range from 15.1 to 27.0.1.
#
# What it does
#   1. Tests https://dv-g3b-emudhra.we-have-a-problem.com/ with curl's default
#      trust (same check as cross-platform/test-emudhra-g3.sh).
#   2. Backs up /etc/ssl/cert.pem (-> /private/etc/ssl/cert.pem.emudhra-bak.<ts>).
#   3. Rewrites the bundle without emSign ECC Root CA - G3, matched by SHA-256
#      fingerprint (same fingerprint as linux/distrust-emudhra-g3*.sh).
#      With --include-aaa it also removes "AAA Certificate Services"
#      (Comodo/Sectigo), per the published macOS workaround at
#      https://emudhra.we-have-a-problem.com/#macos-curl - that root carries the
#      Sectigo cross-signs of the same intermediates, but removing it can break
#      CLI access to legitimate Sectigo sites, so it is off by default.
#   4. Confirms a normal HTTPS site still works; restores the backup if not.
#   5. Re-tests and writes the result to the NinjaOne field emudhraG3Status in
#      the detection script's format:  OK | exit=60 | curl | 2026-10-22 13:45
#      Also tests the Sectigo cross-sign host (dv-g3b-aaa-emudhra...) and logs a
#      warning if it still connects.
#
# Notes
#   - Idempotent. macOS updates can restore /etc/ssl/cert.pem, so run it on a
#     schedule (e.g. daily) until Apple ships a fixed bundle.
#   - Removing the root breaks all G3B/G3C chains for CLI tools, including any
#     legitimate sites under emSign ECC Root CA - G3 (Chrome drops that root
#     from its store on 2026-10-27 anyway).
#   - Not covered: Homebrew (brew upgrade ca-certificates), pip/certifi copies,
#     Java keystores, other app-bundled CA stores.
#
# Usage (as root; NinjaOne runs macOS scripts as root)
#   distrust-emudhra-g3-macos.sh                  apply + verify
#   distrust-emudhra-g3-macos.sh --include-aaa    also remove AAA Certificate Services
#   distrust-emudhra-g3-macos.sh --check          verify only, change nothing
#   distrust-emudhra-g3-macos.sh --rollback       restore the most recent backup
#   NinjaOne script variables: ninjaField (default emudhraG3Status, "none"
#   disables), includeAaa (true/false). Arguments work too.
#
# Exit codes (match the detection script under Ninja):
#   0 = OK (compromised chain rejected)   1 = VULNERABLE or error
#   2 = INCONCLUSIVE (network / no result) 3 = not run as root

set -u

TEST_URL="https://dv-g3b-emudhra.we-have-a-problem.com/"
AAA_TEST_URL="https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
CONTROL_URL="https://www.apple.com/"
ROOT_CN="emSign ECC Root CA - G3"
ROOT_FP="86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
AAA_SUBJECT_RE='CN ?= ?AAA Certificate Services'
AAA_ORG_RE='O ?= ?Comodo CA Limited'

BUNDLE="${EMUDHRA_BUNDLE:-/etc/ssl/cert.pem}"   # override only for testing
CURL="${EMUDHRA_CURL:-/usr/bin/curl}"           # override only for testing
OPENSSL="/usr/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL="$(command -v openssl)"
NINJA_FIELD="${ninjaField:-emudhraG3Status}"

MODE="apply"; INCLUDE_AAA="false"
case "${includeAaa:-}" in true|TRUE|True|1|yes) INCLUDE_AAA="true" ;; esac
for a in "$@"; do
  case "$a" in
    --check) MODE="check" ;; --rollback) MODE="rollback" ;; --include-aaa) INCLUDE_AAA="true" ;;
    *) echo "Unknown argument: $a"; exit 1 ;;
  esac
done

# In test mode only, point curl at the test bundle (real runs use curl's default trust)
CACERT_ARGS=(); [ -n "${EMUDHRA_BUNDLE:-}" ] && CACERT_ARGS=(--cacert "$BUNDLE")

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# ---- helpers ----------------------------------------------------------------
# curl: 0 = connected (VULNERABLE); 35/51/58/60/77 = TLS/cert rejected (OK);
# anything else = network/DNS/timeout (INCONCLUSIVE). Same mapping as detection.
classify() {
  case "$1" in
    0) echo VULNERABLE ;;
    35|51|58|60|77) echo OK ;;
    *) echo INCONCLUSIVE ;;
  esac
}

probe() {  # probe <url>  -> prints curl exit code
  "$CURL" -sS -o /dev/null --max-time 15 ${CACERT_ARGS[@]+"${CACERT_ARGS[@]}"} "$1" 2>/dev/null
  echo $?
}

fp() { "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr 'a-f' 'A-F'; }

split_bundle() {  # write each PEM block (BEGIN..END only) to <dir>/0001.pem ...
  awk -v d="$2" '/-----BEGIN CERTIFICATE-----/{i++; f=sprintf("%s/%04d.pem",d,i); inb=1}
                 inb{print >> f}
                 /-----END CERTIFICATE-----/{inb=0; close(f)}' "$1"
}

is_target() {  # is_target <pemfile> -> prints a label and returns 0 if it should be removed
  if [ "$(fp "$1")" = "$ROOT_FP" ]; then echo "$ROOT_CN (fingerprint match)"; return 0; fi
  if [ "$INCLUDE_AAA" = "true" ]; then
    local s; s=$("$OPENSSL" x509 -noout -subject -in "$1" 2>/dev/null)
    if echo "$s" | grep -Eq "$AAA_SUBJECT_RE" && echo "$s" | grep -Eq "$AAA_ORG_RE"; then
      echo "AAA Certificate Services"; return 0
    fi
  fi
  return 1
}

count_targets() {
  local dir n=0 f
  dir=$(mktemp -d) || { echo 0; return; }
  split_bundle "$1" "$dir"
  for f in "$dir"/*.pem; do [ -e "$f" ] && is_target "$f" >/dev/null && n=$((n+1)); done
  rm -rf "$dir"; echo "$n"
}

finish() {  # finish <rc>  - writes the Ninja field and exits by verdict
  local rc="$1" status value cli out
  status=$(classify "$rc")
  value="$status | exit=$rc | curl | $(date '+%Y-%m-%d %H:%M')"
  log "Result: $value"
  if [ -n "$NINJA_FIELD" ] && [ "$NINJA_FIELD" != "none" ]; then
    for cli in /Applications/NinjaRMMAgent/programdata/ninjarmm-cli \
               /Applications/NinjaRMMAgent/programfiles/ninjarmm-cli; do
      [ -x "$cli" ] || continue
      if out=$("$cli" set "$NINJA_FIELD" "$value" 2>&1); then
        log "Wrote to NinjaOne field '$NINJA_FIELD'"
      else
        log "NinjaOne field write failed: $out"
      fi
      break
    done
  fi
  case "$status" in OK) exit 0 ;; INCONCLUSIVE) exit 2 ;; *) exit 1 ;; esac
}

aaa_note() {
  local rc; rc=$(probe "$AAA_TEST_URL")
  if [ "$(classify "$rc")" = "VULNERABLE" ]; then
    log "WARN: Sectigo cross-sign path still connects ($AAA_TEST_URL exit=$rc)."
    [ "$INCLUDE_AAA" = "true" ] || log "      Re-run with --include-aaa (or includeAaa=true) to close it."
  else
    log "Sectigo cross-sign path: exit=$rc ($(classify "$rc"))"
  fi
}

# ---- preflight --------------------------------------------------------------
if [ "$(id -u)" -ne 0 ] && [ -z "${EMUDHRA_BUNDLE:-}" ]; then echo "Run as root."; exit 3; fi
[ -n "$OPENSSL" ] || { log "openssl not found"; exit 1; }
[ -f "$BUNDLE" ] || { log "$BUNDLE not found"; exit 1; }
BUNDLE_REAL="$(cd "$(dirname "$BUNDLE")" && pwd -P)/$(basename "$BUNDLE")"   # /etc -> /private/etc
BACKUP_DIR="$(dirname "$BUNDLE_REAL")"

if [ "$MODE" = "rollback" ]; then
  latest=$(ls -1 "$BACKUP_DIR"/cert.pem.emudhra-bak.* 2>/dev/null | sort | tail -n1)
  [ -n "$latest" ] || { log "No backup found in $BACKUP_DIR"; exit 1; }
  cp -p "$latest" "$BUNDLE_REAL" || { log "Restore failed"; exit 1; }
  log "Restored $latest -> $BUNDLE_REAL"; exit 0
fi

log "macOS $(sw_vers -productVersion 2>/dev/null || echo '?') | $BUNDLE_REAL | include AAA: $INCLUDE_AAA"
present=$(count_targets "$BUNDLE_REAL")
log "Target roots in bundle: $present"
rc=$(probe "$TEST_URL"); log "Before: $TEST_URL -> exit=$rc ($(classify "$rc"))"

if [ "$MODE" = "check" ]; then aaa_note; log "Check only - no changes made."; finish "$rc"; fi
if [ "$present" -eq 0 ]; then
  log "Nothing to remove."
  [ "$(classify "$rc")" = "VULNERABLE" ] && log "Still VULNERABLE with the root gone - check 'which curl' and the served chain."
  aaa_note; finish "$rc"
fi

# ---- apply ------------------------------------------------------------------
backup="$BACKUP_DIR/cert.pem.emudhra-bak.$(date '+%Y%m%d-%H%M%S')"
cp -p "$BUNDLE_REAL" "$backup" || { log "Backup failed - nothing changed"; finish "$rc"; }
log "Backup: $backup"

work=$(mktemp -d) || { log "mktemp failed - nothing changed"; finish "$rc"; }
trap 'rm -rf "$work"' EXIT
split_bundle "$BUNDLE_REAL" "$work"
total=0; removed=0; : > "$work/new.pem"
for f in "$work"/[0-9]*.pem; do
  [ -e "$f" ] || continue
  total=$((total+1))
  if label=$(is_target "$f"); then removed=$((removed+1)); log "Removing: $label"
  else cat "$f" >> "$work/new.pem"; fi
done
kept=$(grep -c -- '-----BEGIN CERTIFICATE-----' "$work/new.pem")

if [ "$removed" -eq 0 ] || [ "$kept" -ne $((total - removed)) ] || [ "$kept" -lt 50 ]; then
  log "Sanity check failed (total=$total removed=$removed kept=$kept) - nothing changed"
  rm -f "$backup"; finish "$rc"
fi

# Overwrite in place so owner/permissions are unchanged
if ! cat "$work/new.pem" > "$BUNDLE_REAL"; then
  cp -p "$backup" "$BUNDLE_REAL"; log "Write failed - backup restored"; finish "$rc"
fi
log "Bundle rewritten: $total -> $kept certificates"

crc=$(probe "$CONTROL_URL")
if [ "$crc" -ne 0 ]; then
  cp -p "$backup" "$BUNDLE_REAL"
  log "Control site $CONTROL_URL failed (exit=$crc) - backup restored, nothing changed"
  finish "$rc"
fi
log "Control site OK"

rc=$(probe "$TEST_URL"); log "After: $TEST_URL -> exit=$rc ($(classify "$rc"))"
[ "$(classify "$rc")" = "VULNERABLE" ] && log "Still VULNERABLE - check 'which curl' and the served chain."
aaa_note
finish "$rc"

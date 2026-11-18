#!/bin/bash
# detect-java4shell-macos.sh
#
# macOS detection for Java4Shell (CVE-2026-114938) - memory corruption in the
# x86-64 HotSpot JVM Base64 intrinsic. Mac counterpart of
# ninjaone/Detect-Java4Shell.ps1: same status values, same NinjaOne fields.
#
# Exposure needs all three:
#   1. An OpenJDK-based runtime >= 17.0.6 (incl. 21, 25, 27), or Oracle 8
#      Enterprise Performance Pack 8u511b33-perf, without the Nov 2026 fix.
#   2. An Intel Mac whose CPU has AVX-512 VBMI. Read straight from
#      sysctl machdep.cpu.leaf7_features - no guessing. In practice this is the
#      2020 Ice Lake MacBook Air / 13" MacBook Pro (4 Thunderbolt ports).
#      Apple Silicon is never affected: native Java is arm64, and Rosetta 2
#      does not emulate AVX-512, so x86_64 Java under Rosetta can't hit it.
#   3. No -XX:-UseBASE64Intrinsics / -XX:UseAVX=0-2 on the running JVM.
#
# What it does (read-only, no downloads, no changes)
#   - Finds java binaries under /Library/Java, /Applications, /Users, /opt,
#     /usr/local (JDK installs, Homebrew, SDKMAN, IDEs and app-bundled JREs).
#   - Reads each runtime's release file (vendor/version), falls back to
#     java -version.
#   - Checks running java processes for the mitigation flags.
#   - Writes java4shellStatus (one line) and java4shellDetail (one line per
#     runtime) via ninjarmm-cli.
#
# Status values: VULNERABLE, VULNERABLE-CPU?, CHECK-VENDOR, MITIGATED-FLAG,
#   AFFECTED-VERSION, UNKNOWN-VERSION, NOT-AFFECTED-ARM64, NOT-AFFECTED
#   (see the Windows script header for definitions).
#
# Usage (NinjaOne runs macOS scripts as root)
#   sudo ./detect-java4shell-macos.sh [--quick]
#   NinjaOne script variables (env vars): skipDiskScan (Checkbox), scanPaths
#   (String, comma-separated), statusField / detailField (String).
#
# Exit codes: 0 = not at risk, 1 = VULNERABLE / VULNERABLE-CPU? / CHECK-VENDOR
#
# Fixed versions: Oracle Nov 2026 CPU / Qualys 2026-11-18. Update as vendors publish.

set -u
PATH=$PATH:/usr/bin:/bin:/usr/sbin:/sbin

STATUS_FIELD="${statusField:-java4shellStatus}"
DETAIL_FIELD="${detailField:-java4shellDetail}"
QUICK=0
[ "${skipDiskScan:-false}" = "true" ] && QUICK=1
[ "${1:-}" = "--quick" ] && QUICK=1

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------
# norm_ver "1.8.0_511" -> "8.0.511" ; "21.0.13+11" -> "21.0.13" ; "17.0.21.1.2" kept
norm_ver() {
  echo "$1" | sed -E 's/^1\.8\.0_/8.0./; s/[+_-].*$//; s/[^0-9.].*$//'
}
# ver_cmp a b -> prints -1 / 0 / 1 (any number of dotted parts)
ver_cmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) { p = (i <= na) ? x[i] + 0 : 0; q = (i <= nb) ? y[i] + 0 : 0
      if (p < q) { print -1; exit } if (p > q) { print 1; exit } }
    print 0 }'
}
major_of() { echo "$1" | cut -d. -f1; }

# fixed_for <vendor> <major> -> min fixed version, or empty if not published
fixed_for() {
  case "$1" in
    *Oracle*)
      case "$2" in 17) echo 17.0.21.1;; 21) echo 21.0.13.1;; 25) echo 25.0.5.1;; 27) echo 27.0.1.1;; esac ;;
    *Amazon*|*Corretto*)
      case "$2" in 17) echo 17.0.21.1.2;; esac ;;
  esac
}

# ---------------------------------------------------------------------------
# Host CPU
# ---------------------------------------------------------------------------
CPU_NAME=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then
  HOST_ARCH=arm64; VBMI=False; VBMI_SRC="Apple Silicon"
else
  HOST_ARCH=x86_64
  feats=$(sysctl -n machdep.cpu.leaf7_features 2>/dev/null)
  if [ -z "$feats" ]; then VBMI=UNKNOWN; VBMI_SRC="sysctl unavailable"
  elif echo " $feats " | grep -qi ' AVX512VBMI '; then VBMI=True; VBMI_SRC="sysctl leaf7"
  else VBMI=False; VBMI_SRC="sysctl leaf7"; fi
fi

# ---------------------------------------------------------------------------
# Find java binaries
# ---------------------------------------------------------------------------
if [ -n "${scanPaths:-}" ]; then
  ROOTS=$(echo "$scanPaths" | tr ',' '\n' | sed 's/^ *//; s/ *$//')
elif [ "$QUICK" = "1" ]; then
  ROOTS="/Library/Java
/Applications
/opt/homebrew
/usr/local"
else
  ROOTS="/Library/Java
/Applications
/Users
/opt
/usr/local"
fi

LIST=$(mktemp "${TMPDIR:-/tmp}/j4s.XXXXXX") || exit 2
trap 'rm -f "$LIST" "$LIST.r"' EXIT
echo "$ROOTS" | while IFS= read -r root; do
  [ -d "$root" ] || continue
  find "$root" \( -name .Trash -o -name 'Containers' -o -name '.Spotlight-V100' -o -name 'node_modules' \) -prune \
       -o -type f -name java -path '*/bin/java' -perm -u+x -print 2>/dev/null
done | sort -u > "$LIST"

# Add executables of running java processes (outside the roots)
ps -axo comm= 2>/dev/null | grep -E '/bin/java$' | sort -u >> "$LIST"
sort -u "$LIST" -o "$LIST"

PROCS=$(ps -axww -o command= 2>/dev/null | grep -E '(^|/)java( |$)' | grep -v grep)
MIT_RX='-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]([^0-9]|$)'

STAMP=$(date '+%Y-%m-%d %H:%M')

# ---------------------------------------------------------------------------
# Classify each runtime
# ---------------------------------------------------------------------------
: > "$LIST.r"
while IFS= read -r j; do
  [ -n "$j" ] || continue
  jhome=$(dirname "$(dirname "$j")")
  # JRE inside a JDK: .../jre/bin/java -> release file is one level higher
  rel="$jhome/release"; [ -f "$rel" ] || rel="$(dirname "$jhome")/release"
  vendor=""; ver=""; impl=""
  if [ -f "$rel" ]; then
    vendor=$(sed -n 's/^IMPLEMENTOR="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$rel" | head -1)
    ver=$(sed -n 's/^JAVA_VERSION="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$rel" | head -1)
    impl=$(sed -n 's/^IMPLEMENTOR_VERSION="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$rel" | head -1)
  fi
  if [ -z "$ver" ]; then
    out=$(perl -e 'alarm 15; exec @ARGV' "$j" -version 2>&1)
    ver=$(echo "$out" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
    [ -z "$vendor" ] && vendor=$(echo "$out" | grep -oE 'Oracle|Corretto|Temurin|Adoptium|Zulu|Microsoft|Red Hat|IBM|Semeru|Liberica|BellSoft|SapMachine|GraalVM' | head -1)
    echo "$out" | grep -q -- '-perf' && impl="$impl perf"
  fi

  archs=$(lipo -archs "$j" 2>/dev/null || file -b "$j" | grep -oE 'x86_64|arm64' | sort -u | tr '\n' ' ')
  [ -z "$archs" ] && archs=unknown
  running=0; echo "$PROCS" | grep -qF "$j" && running=1

  nv=$(norm_ver "$ver"); maj=$(major_of "$nv")
  status=""
  if [ "$HOST_ARCH" = "arm64" ] || ! echo "$archs" | grep -qE 'x86_64|unknown'; then
    status="NOT-AFFECTED-ARM64"
  elif [ -z "$nv" ] || [ -z "$maj" ]; then
    status="UNKNOWN-VERSION"
  else
    perf8=0
    [ "$maj" = "8" ] && echo "$impl $ver" | grep -q perf && perf8=1
    vendor_unknown=0
    if [ "$perf8" = "1" ]; then
      build=$(echo "$nv" | cut -d. -f3)
      [ "${build:-0}" -ge 513 ] && status="NOT-AFFECTED"
    elif [ "$maj" -lt 17 ] || [ "$(ver_cmp "$nv" 17.0.6)" = "-1" ]; then
      status="NOT-AFFECTED"
    else
      fx=$(fixed_for "$vendor $impl" "$maj")
      if [ -n "$fx" ]; then
        cmpv="$nv"
        case "$impl" in Corretto-*) cmpv=$(echo "$impl" | sed 's/^Corretto-//') ;; esac
        [ "$(ver_cmp "$cmpv" "$fx")" != "-1" ] && status="NOT-AFFECTED"
      else
        case "$maj" in 17|21|25|27) echo "$vendor" | grep -q Oracle || vendor_unknown=1 ;; esac
      fi
    fi
    if [ -z "$status" ]; then
      if echo "$PROCS" | grep -F "$jhome" | grep -qE -- "$MIT_RX" || \
         echo "${JAVA_TOOL_OPTIONS:-} ${JDK_JAVA_OPTIONS:-}" | grep -qE -- "$MIT_RX"; then
        status="MITIGATED-FLAG"
      elif [ "$VBMI" = "False" ]; then status="AFFECTED-VERSION"
      elif [ "$vendor_unknown" = "1" ]; then status="CHECK-VENDOR"
      elif [ "$VBMI" = "True" ]; then status="VULNERABLE"
      else status="VULNERABLE-CPU?"; fi
    fi
  fi
  vdisp="$ver"; [ -n "$impl" ] && vdisp="$ver ($impl)"
  arun=""; [ "$running" = "1" ] && arun=" | RUNNING"
  echo "$status|$vendor $vdisp | $(echo $archs | tr ' ' '/')$arun | $j" >> "$LIST.r"
done < "$LIST"

# ---------------------------------------------------------------------------
# Summarize, sort worst-first, write Ninja fields
# ---------------------------------------------------------------------------
rank() {
  case "$1" in VULNERABLE) echo 1;; "VULNERABLE-CPU?") echo 2;; CHECK-VENDOR) echo 3;;
    MITIGATED-FLAG) echo 4;; AFFECTED-VERSION) echo 5;; UNKNOWN-VERSION) echo 6;;
    NOT-AFFECTED-ARM64) echo 7;; *) echo 9;; esac
}
total=$(grep -c . "$LIST.r")
if [ "$total" -eq 0 ]; then
  overall="NOT-AFFECTED"
  STATUS="NOT-AFFECTED | no Java found | $STAMP"
  DETAIL="No java found in: $(echo "$ROOTS" | tr '\n' ' ')
CPU: $CPU_NAME ($HOST_ARCH)"
else
  SORTED=$(while IFS= read -r l; do echo "$(rank "${l%%|*}")|$l"; done < "$LIST.r" | sort -t'|' -k1,1n -k5 | cut -d'|' -f2-)
  worst=$(echo "$SORTED" | head -1 | cut -d'|' -f1)
  case "$worst" in NOT-AFFECTED*) overall="NOT-AFFECTED";; *) overall="$worst";; esac
  atrisk=$(echo "$SORTED" | cut -d'|' -f1 | grep -vc '^NOT-AFFECTED')
  STATUS="$overall | $atrisk of $total runtimes flagged | VBMI=$VBMI | $STAMP"
  DETAIL="Scan: $STAMP  CPU: $CPU_NAME ($HOST_ARCH)  AVX-512 VBMI: $VBMI ($VBMI_SRC)
$(echo "$SORTED" | sed 's/|/ | /')"
fi

echo "Java4Shell (CVE-2026-114938) scan - $(hostname -s) - $STAMP"
echo "$DETAIL"
echo
echo "$STATUS"

CLI=""
for c in /Applications/NinjaRMMAgent/programdata/ninjarmm-cli /Applications/NinjaRMMAgent/programfiles/ninjarmm-cli; do
  [ -x "$c" ] && CLI="$c" && break
done
if [ -n "$CLI" ]; then
  [ ${#DETAIL} -gt 9000 ] && DETAIL="${DETAIL:0:8985}
...(truncated)"
  if "$CLI" set "$STATUS_FIELD" "${STATUS:0:200}" >/dev/null 2>&1; then echo "Wrote Ninja field '$STATUS_FIELD'"
  else echo "WARNING: could not write Ninja field '$STATUS_FIELD' - check it exists and has Automation write access"; fi
  if printf '%s' "$DETAIL" | "$CLI" set --stdin "$DETAIL_FIELD" >/dev/null 2>&1; then echo "Wrote Ninja field '$DETAIL_FIELD'"
  else echo "WARNING: could not write Ninja field '$DETAIL_FIELD'"; fi
fi

case "$overall" in VULNERABLE|"VULNERABLE-CPU?"|CHECK-VENDOR) exit 1 ;; *) exit 0 ;; esac

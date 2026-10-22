#!/usr/bin/ksh
# distrust-emudhra-g3-aix.sh
#
# AIX remediation for the October 2026 eMudhra G3 intermediate CA key
# compromise (Mozilla bug 2083449). AIX equivalent of
# linux/distrust-emudhra-g3*.sh and macos/distrust-emudhra-g3-macos.sh.
#
# Why AIX needs its own script
#   AIX has no single system trust store. Depending on what's installed:
#     - IBM openssl.base (/usr/bin/openssl)  -> OPENSSLDIR /var/ssl
#                                               (cert.pem + certs/ hash dir)
#     - AIX Toolbox (RPM, /opt/freeware)     -> curl/openssl/ca-certificates,
#                                               sometimes p11-kit + update-ca-trust
#     - IBM Java cacerts (WebSphere, etc.)   -> separate JKS keystores
#   So this script discovers every trust store it can find instead of assuming
#   one path, and removes emSign ECC Root CA - G3 from each, matched by SHA-256
#   fingerprint (same fingerprint as the Linux/macOS scripts). Removing the root
#   breaks every EM ... TLS CA - G3B/G3C chain, so no intermediate blocklist is
#   needed for flat bundles.
#
# What it does
#   1. Live test of https://dv-g3b-emudhra.we-have-a-problem.com/ with every
#      client it finds: each curl (rc 0 = VULNERABLE, 35/51/58/60/77 = OK) and
#      each openssl's default store via s_client ("Verify return code: 0" =
#      VULNERABLE). curl's -v output also tells it which CAfile/CApath curl uses.
#   2. Discovers PEM bundles (OPENSSLDIR/cert.pem from every openssl, curl's
#      CAfile/CApath, plus the usual /var/ssl and /opt/freeware paths) and
#      OpenSSL hash directories, and checks every certificate's fingerprint.
#      This offline check is what matters on servers with no internet egress.
#   3. Applies (default mode), all backed up under /var/adm/emudhra-g3/<ts>/
#      with a manifest so --rollback can undo it:
#        - if update-ca-trust (p11-kit) is present: drops the root into the
#          ca-trust blocklist dir and re-extracts, so it stays out on re-extract
#        - rewrites every bundle that still contains the root, in place
#          (owner/permissions kept)
#        - moves hash-dir entries (e.g. /var/ssl/certs/xxxxxxxx.0) for the root
#          into the backup dir
#        - IBM Java cacerts: reported only; --include-java deletes the alias
#          with keytool (storepass changeit, or JAVA_STOREPASS) after a backup
#   4. If a control site (www.ibm.com) worked before the change and fails after,
#      restores everything from this run. Skipped on hosts with no egress.
#   5. Re-tests and prints a one-line result in the same format as the other
#      eMudhra scripts:  OK | <client>=<code> | stores=0 | 2026-10-22 16:05
#
# Notes
#   - Written for AIX ksh (ksh88/ksh93); no bash needed. Run as root.
#   - Idempotent. AIX Toolbox ca-certificates updates and openssl.base updates
#     can put the root back - run it from cron until fixed bundles ship.
#   - A host with no curl and an empty /var/ssl/cert.pem (stock AIX) trusts
#     nothing via OpenSSL and reports OK.
#   - Not covered: IBM GSKit .kdb stores (IHS, MQ, Db2, TSM/ISP - check with
#     gsk8capicmd_64 -cert -list -db <kdb> -stashed), app-bundled CA files,
#     Python certifi. NinjaOne has no AIX agent, so no custom field is written.
#
# Usage (as root)
#   distrust-emudhra-g3-aix.sh                  apply + verify
#   distrust-emudhra-g3-aix.sh --include-java   also remove it from IBM Java cacerts
#   distrust-emudhra-g3-aix.sh --check          report only, change nothing
#   distrust-emudhra-g3-aix.sh --rollback       undo the most recent apply
#
# Exit codes (same as the macOS script):
#   0 = OK (root gone from every store found, compromised chain rejected)
#   1 = VULNERABLE or error   3 = not run as root
#   (no egress: an unreachable test host falls back to the trust store scan)

TEST_HOST="dv-g3b-emudhra.we-have-a-problem.com"
CONTROL_HOST="www.ibm.com"
ROOT_CN="emSign ECC Root CA - G3"
ROOT_FP="86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
BACKUP_ROOT="${EMUDHRA_BACKUP_ROOT:-/var/adm/emudhra-g3}"
JAVA_STOREPASS="${JAVA_STOREPASS:-changeit}"
TS=$(date '+%Y%m%d-%H%M%S')

PATH=/usr/bin:/usr/sbin:/bin:/opt/freeware/bin:$PATH
export PATH

MODE=apply
INCLUDE_JAVA=false
for a in "$@"; do
    case "$a" in
        --check)        MODE=check ;;
        --rollback)     MODE=rollback ;;
        --include-java) INCLUDE_JAVA=true ;;
        -h|--help)      sed -n '2,64p' "$0"; exit 0 ;;
        *)              echo "Unknown argument: $a"; exit 1 ;;
    esac
done

findcmd() { command -v "$1" 2>/dev/null || whence "$1" 2>/dev/null; }
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

if [ "$(id -u)" -ne 0 ] && [ -z "${EMUDHRA_BUNDLES:-}" ]; then
    echo "Run as root."; exit 3
fi

WORK="/tmp/emudhra-g3.$$"
rm -rf "$WORK"; mkdir -m 700 "$WORK" || { log "cannot create $WORK"; exit 1; }
trap 'rm -rf "$WORK"' EXIT INT TERM
: > "$WORK/bundles"; : > "$WORK/capaths"; : > "$WORK/clients"

# ---- clients ------------------------------------------------------------------
add_client() {  # add_client curl|openssl <path>
    [ -n "$2" ] && [ -x "$2" ] || return 0
    grep -qxF "$1 $2" "$WORK/clients" || echo "$1 $2" >> "$WORK/clients"
}
for c in /opt/freeware/bin/curl /usr/bin/curl /usr/local/bin/curl $(findcmd curl); do
    add_client curl "$c"
done
for o in /usr/bin/openssl /opt/freeware/bin/openssl $(findcmd openssl); do
    add_client openssl "$o"
done
OSSL=$(awk '$1=="openssl"{print $2; exit}' "$WORK/clients")
[ -n "$OSSL" ] || { log "No openssl found - can't fingerprint certificates."; exit 1; }

# ---- helpers ------------------------------------------------------------------
fp() { "$OSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr 'abcdef' 'ABCDEF'; }

resolve() {  # print the physical path of a file, following symlinks
    _rp=$1; _rn=0
    while [ -h "$_rp" ] && [ $_rn -lt 10 ]; do
        _rt=$(ls -l "$_rp" | sed 's/.* -> //')
        case "$_rt" in /*) _rp=$_rt ;; *) _rp=$(dirname "$_rp")/$_rt ;; esac
        _rn=$((_rn + 1))
    done
    [ -e "$_rp" ] || return 1
    _rd=$(cd "$(dirname "$_rp")" 2>/dev/null && pwd -P) || return 1
    echo "$_rd/$(basename "$_rp")"
}

add_bundle() {
    _ab=$(resolve "$1") || return 0
    [ -f "$_ab" ] && [ -s "$_ab" ] || return 0
    grep -q -- '-----BEGIN .*CERTIFICATE-----' "$_ab" || return 0
    grep -qxF "$_ab" "$WORK/bundles" || echo "$_ab" >> "$WORK/bundles"
}

add_capath() {
    [ -d "$1" ] || return 0
    _ac=$(cd "$1" 2>/dev/null && pwd -P) || return 0
    grep -qxF "$_ac" "$WORK/capaths" || echo "$_ac" >> "$WORK/capaths"
}

split_bundle() {  # split_bundle <bundle> <dir>  -> <dir>/0001.pem ...
    awk -v d="$2" '/-----BEGIN .*CERTIFICATE-----/{i++; f=sprintf("%s/%04d.pem",d,i); inb=1}
                   inb{print >> f}
                   /-----END .*CERTIFICATE-----/{if (inb) close(f); inb=0}' "$1"
}

bundle_hits() {  # number of certs in <bundle> matching ROOT_FP; saves a copy to $WORK/root.pem
    _bd="$WORK/split.$$"; rm -rf "$_bd"; mkdir "$_bd"
    split_bundle "$1" "$_bd"
    _bh=0
    for _bf in "$_bd"/*.pem; do
        [ -e "$_bf" ] || continue
        if [ "$(fp "$_bf")" = "$ROOT_FP" ]; then
            _bh=$((_bh + 1))
            [ -s "$WORK/root.pem" ] || cp "$_bf" "$WORK/root.pem"
        fi
    done
    rm -rf "$_bd"
    echo $_bh
}

run_to() {  # run_to <secs> <cmd...>  - AIX has no timeout(1)
    _rs=$1; shift
    "$@" &
    _rpid=$!
    ( sleep "$_rs"; kill "$_rpid" 2>/dev/null ) >/dev/null 2>&1 &
    _rwd=$!
    wait "$_rpid"; _rrc=$?
    kill "$_rwd" 2>/dev/null
    return $_rrc
}

# probe <kind> <path> <host>  -> sets P_STATUS (OK/VULNERABLE/INCONCLUSIVE), P_CODE
probe() {
    P_STATUS=INCONCLUSIVE; P_CODE="?"
    if [ "$1" = curl ]; then
        "$2" -sv -o /dev/null --max-time 15 "https://$3/" > "$WORK/probe.out" 2>&1
        P_CODE="rc$?"
        case "$P_CODE" in
            rc0)                          P_STATUS=VULNERABLE ;;
            rc35|rc51|rc58|rc60|rc77)     P_STATUS=OK ;;
        esac
        _cf=$(sed -n 's/^\* *CAfile: *//p' "$WORK/probe.out" | head -1)
        _cp=$(sed -n 's/^\* *CApath: *//p' "$WORK/probe.out" | head -1)
        if [ -z "${EMUDHRA_BUNDLES:-}" ]; then   # testing override: only the given bundles
            [ -n "$_cf" ] && [ "$_cf" != none ] && add_bundle "$_cf"
            [ -n "$_cp" ] && [ "$_cp" != none ] && add_capath "$_cp"
        fi
    else
        run_to 20 "$2" s_client -connect "$3:443" -servername "$3" \
            </dev/null > "$WORK/probe.out" 2>&1
        _vc=$(sed -n 's/.*Verify return code: *\([0-9][0-9]*\).*/\1/p' "$WORK/probe.out" | tail -1)
        if [ -n "$_vc" ]; then
            P_CODE="verify$_vc"
            if [ "$_vc" -eq 0 ]; then P_STATUS=VULNERABLE; else P_STATUS=OK; fi
        else
            P_CODE="noconnect"
        fi
    fi
}

live_test() {  # tests TEST_HOST with every client -> LIVE, LIVE_DETAIL
    LIVE=INCONCLUSIVE; LIVE_DETAIL=""
    while read -r _k _p; do
        probe "$_k" "$_p" "$TEST_HOST"
        log "  $_p -> $P_CODE ($P_STATUS)"
        LIVE_DETAIL="$LIVE_DETAIL $(basename "$(dirname "$(dirname "$_p")")")/$_k=$P_CODE"
        case "$P_STATUS" in
            VULNERABLE) LIVE=VULNERABLE ;;
            OK) [ "$LIVE" = VULNERABLE ] || LIVE=OK ;;
        esac
    done < "$WORK/clients"
}

control_ok() {  # 0 if the first client can reach the control site with a valid chain
    read -r _ck _cp < "$WORK/clients"
    probe "$_ck" "$_cp" "$CONTROL_HOST"
    [ "$P_STATUS" = VULNERABLE ]   # "connected and trusted" = control works
}

discover() {
    if [ -n "${EMUDHRA_BUNDLES:-}" ]; then   # testing only
        for _b in $EMUDHRA_BUNDLES; do add_bundle "$_b"; done
        return
    fi
    while read -r _k _p; do
        [ "$_k" = openssl ] || continue
        _od=$("$_p" version -d 2>/dev/null | sed -n 's/^OPENSSLDIR: *"\(.*\)"/\1/p')
        [ -n "$_od" ] || continue
        add_bundle "$_od/cert.pem"
        add_capath "$_od/certs"
    done < "$WORK/clients"
    for _b in /var/ssl/cert.pem /var/ssl/certs/ca-bundle.crt /var/ssl/certs/ca-bundle.trust.crt \
              /var/ssl/certs/ca-certificates.crt \
              /opt/freeware/ssl/cert.pem /opt/freeware/etc/ssl/cert.pem \
              /opt/freeware/etc/ssl/certs/ca-bundle.crt /opt/freeware/etc/ssl/certs/ca-certificates.crt \
              /opt/freeware/etc/pki/tls/certs/ca-bundle.crt \
              /opt/freeware/etc/pki/tls/certs/ca-bundle.trust.crt \
              /opt/freeware/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
              /opt/freeware/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt \
              /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-bundle.crt; do
        add_bundle "$_b"
    done
    for _d in /var/ssl/certs /opt/freeware/ssl/certs /opt/freeware/etc/ssl/certs /opt/freeware/etc/pki/tls/certs; do
        add_capath "$_d"
    done
}

scan_stores() {  # -> $WORK/bundle_hits ("<n> <path>"), $WORK/hash_hits, STORE_HITS
    : > "$WORK/bundle_hits"; : > "$WORK/hash_hits"; STORE_HITS=0
    while read -r _b; do
        _n=$(bundle_hits "$_b")
        _t=$(grep -c -- '-----BEGIN .*CERTIFICATE-----' "$_b")
        if [ "$_n" -gt 0 ]; then
            log "  CONTAINS ROOT  $_b ($_t certs)"
            echo "$_n $_b" >> "$WORK/bundle_hits"; STORE_HITS=$((STORE_HITS + _n))
        else
            log "  clean          $_b ($_t certs)"
        fi
    done < "$WORK/bundles"
    while read -r _d; do
        for _f in "$_d"/*.[0-9]; do
            [ -f "$_f" ] || continue
            if [ "$(fp "$_f")" = "$ROOT_FP" ]; then
                log "  CONTAINS ROOT  $_f (hash dir entry)"
                echo "$_f" >> "$WORK/hash_hits"; STORE_HITS=$((STORE_HITS + 1))
                [ -s "$WORK/root.pem" ] || cp "$_f" "$WORK/root.pem"
            fi
        done
    done < "$WORK/capaths"
    [ -s "$WORK/bundles" ] || log "  (no PEM bundles found)"
}

java_scan() {  # -> $WORK/java_hits ("<keytool>|<keystore>|<alias>"), JAVA_HITS
    : > "$WORK/java_hits"; JAVA_HITS=0
    for _ks in /usr/java*/jre/lib/security/cacerts /usr/java*/lib/security/cacerts \
               /opt/IBM/*/java*/jre/lib/security/cacerts /opt/IBM/*/java*/lib/security/cacerts \
               /opt/IBM/WebSphere/*/java/*/jre/lib/security/cacerts \
               /opt/IBM/WebSphere/*/java/*/lib/security/cacerts; do
        [ -f "$_ks" ] || continue
        _kt=$(dirname "$_ks")/../../bin/keytool
        [ -x "$_kt" ] || _kt=$(findcmd keytool)
        [ -n "$_kt" ] && [ -x "$_kt" ] || { log "  $_ks: no keytool - skipped"; continue; }
        "$_kt" -list -v -keystore "$_ks" -storepass "$JAVA_STOREPASS" > "$WORK/ks.out" 2>/dev/null \
            || { log "  $_ks: keytool could not open it (storepass?) - skipped"; continue; }
        _al=$(awk -v cn="$ROOT_CN" '/^Alias name:/{a=$0; sub(/^Alias name: */,"",a)}
                                    /^Owner:/ && index($0, "CN=" cn ",") {print a}' "$WORK/ks.out")
        if [ -n "$_al" ]; then
            echo "$_al" > "$WORK/ks.alias"
            while read -r _a; do   # aliases can contain spaces, e.g. "emsigneccrootcag3 [jdk]"
                log "  CONTAINS ROOT  $_ks (alias $_a)"
                echo "$_kt|$_ks|$_a" >> "$WORK/java_hits"; JAVA_HITS=$((JAVA_HITS + 1))
            done < "$WORK/ks.alias"
        else
            log "  clean          $_ks"
        fi
    done
}

find_uct() {  # update-ca-trust + its blocklist dir, if this host has p11-kit
    UCT=""; UCT_BL=""
    for _u in /opt/freeware/bin/update-ca-trust /usr/bin/update-ca-trust $(findcmd update-ca-trust); do
        [ -x "$_u" ] && { UCT=$_u; break; }
    done
    [ -n "$UCT" ] || return 0
    for _d in /opt/freeware/etc/pki/ca-trust/source/blocklist /opt/freeware/etc/pki/ca-trust/source/blacklist \
              /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist; do
        [ -d "$_d" ] && { UCT_BL=$_d; break; }
    done
}

finish() {
    if [ "$LIVE" = VULNERABLE ] || [ "$STORE_HITS" -gt 0 ]; then VERDICT=VULNERABLE
    elif [ "$LIVE" = OK ]; then VERDICT=OK
    else VERDICT=OK; log "Live test inconclusive (no egress?) - verdict based on the trust store scan only."
    fi
    if [ "$JAVA_HITS" -gt 0 ]; then
        log "WARN: $JAVA_HITS IBM Java keystore entr(y/ies) still trust the root - re-run with --include-java, or:"
        while IFS='|' read -r _kt _ks _a; do
            log "      $_kt -delete -alias '$_a' -keystore $_ks -storepass <pass>"
        done < "$WORK/java_hits"
    fi
    log "Result: $VERDICT |$LIVE_DETAIL | stores=$STORE_HITS java=$JAVA_HITS | $(date '+%Y-%m-%d %H:%M')"
    case "$VERDICT" in OK) exit 0 ;; *) exit 1 ;; esac
}

rollback_dir() {  # rollback_dir <backup dir>  - undo one run from its manifest
    _m="$1/manifest"
    [ -f "$_m" ] || { log "No manifest in $1"; return 1; }
    _rerun_uct=false
    while IFS='|' read -r _type _orig _bak; do
        case "$_type" in
            file) cp -p "$_bak" "$_orig" && log "Restored $_orig" ;;
            move) mv "$_bak" "$_orig"    && log "Restored $_orig" ;;
            new)  rm -f "$_orig"         && log "Removed $_orig"; _rerun_uct=true ;;
        esac
    done < "$_m"
    if [ "$_rerun_uct" = true ]; then find_uct; [ -n "$UCT" ] && "$UCT" extract && log "update-ca-trust extract re-run"; fi
    return 0
}

# ---- rollback -----------------------------------------------------------------
if [ "$MODE" = rollback ]; then
    latest=$(ls -1d "$BACKUP_ROOT"/2* 2>/dev/null | sort | tail -1)
    [ -n "$latest" ] || { log "No backups under $BACKUP_ROOT"; exit 1; }
    log "Rolling back $latest"
    rollback_dir "$latest" || exit 1
    mv "$latest" "$latest.rolledback"
    exit 0
fi

# ---- scan ---------------------------------------------------------------------
log "AIX $(oslevel -s 2>/dev/null || uname -v) | mode: $MODE | include Java: $INCLUDE_JAVA"
log "Clients: $(awk '{printf "%s ", $2}' "$WORK/clients")"
log "Live test before ($TEST_HOST):"
live_test
discover
log "Trust stores:"
scan_stores
log "IBM Java keystores:"
java_scan
[ "$JAVA_HITS" -gt 0 ] || [ -n "$(ls /usr/java* 2>/dev/null)" ] || log "  (none found)"

if [ "$MODE" = check ]; then log "Check only - no changes made."; finish; fi
if [ "$STORE_HITS" -eq 0 ] && { [ "$INCLUDE_JAVA" != true ] || [ "$JAVA_HITS" -eq 0 ]; }; then
    log "Nothing to remove."
    [ "$LIVE" = VULNERABLE ] && log "Still VULNERABLE with the root gone from every store found - dump the chain with: openssl s_client -connect $TEST_HOST:443 -servername $TEST_HOST -showcerts </dev/null"
    finish
fi

# ---- apply --------------------------------------------------------------------
BK="$BACKUP_ROOT/$TS"
mkdir -p "$BK" && chmod 700 "$BK" || { log "Cannot create $BK - nothing changed"; finish; }
MAN="$BK/manifest"; : > "$MAN"
log "Backups: $BK"

CTRL_BEFORE=false
control_ok && CTRL_BEFORE=true
log "Control site $CONTROL_HOST before change: $P_CODE"

# 1. p11-kit blocklist, so update-ca-trust extract keeps it out
find_uct
if [ -n "$UCT" ] && [ -n "$UCT_BL" ] && [ -s "$WORK/root.pem" ]; then
    _blf="$UCT_BL/emsign-ecc-root-ca-g3.pem"
    if [ -f "$_blf" ] && [ "$(fp "$_blf")" = "$ROOT_FP" ]; then
        log "Root already in $UCT_BL"
    else
        cp "$WORK/root.pem" "$_blf" && chmod 644 "$_blf" && echo "new|$_blf|" >> "$MAN"
        log "Blocklisted root in $UCT_BL"
    fi
    # back up bundles before extract rewrites them
    _i=0
    while read -r _b; do
        _i=$((_i + 1)); cp -p "$_b" "$BK/pre-uct.$_i" && echo "file|$_b|$BK/pre-uct.$_i" >> "$MAN"
    done < "$WORK/bundles"
    "$UCT" extract && log "update-ca-trust extract done"
fi

# 2. rewrite bundles that still contain the root
_i=0
while read -r _b; do
    _i=$((_i + 1))
    _sd="$WORK/rw.$_i"; mkdir "$_sd"; split_bundle "$_b" "$_sd"
    _tot=0; _rem=0; : > "$_sd/new"
    for _f in "$_sd"/[0-9]*.pem; do
        [ -e "$_f" ] || continue
        _tot=$((_tot + 1))
        if [ "$(fp "$_f")" = "$ROOT_FP" ]; then _rem=$((_rem + 1)); else cat "$_f" >> "$_sd/new"; fi
    done
    [ "$_rem" -gt 0 ] || { rm -rf "$_sd"; continue; }
    _kept=$(grep -c -- '-----BEGIN .*CERTIFICATE-----' "$_sd/new")
    if [ "$_kept" -ne $((_tot - _rem)) ] || [ "$_kept" -eq 0 ]; then
        log "Sanity check failed for $_b (total=$_tot removed=$_rem kept=$_kept) - left unchanged"
        rm -rf "$_sd"; continue
    fi
    if ! grep -qF "|$_b|" "$MAN"; then
        cp -p "$_b" "$BK/bundle.$_i" || { log "Backup of $_b failed - left unchanged"; rm -rf "$_sd"; continue; }
        echo "file|$_b|$BK/bundle.$_i" >> "$MAN"
    fi
    if cat "$_sd/new" > "$_b"; then
        log "Rewrote $_b: $_tot -> $_kept certs"
    else
        log "Write to $_b failed - restoring"; cp -p "$BK/bundle.$_i" "$_b"
    fi
    rm -rf "$_sd"
done < "$WORK/bundles"

# 3. hash-dir entries
_i=0
while read -r _f; do
    _i=$((_i + 1))
    [ -e "$_f" ] || [ -h "$_f" ] || continue
    mv "$_f" "$BK/hash.$_i" && echo "move|$_f|$BK/hash.$_i" >> "$MAN" && log "Moved hash entry $_f"
done < "$WORK/hash_hits"

# 4. IBM Java keystores (opt-in)
if [ "$INCLUDE_JAVA" = true ]; then
    _i=0
    while IFS='|' read -r _kt _ks _a; do
        _i=$((_i + 1))
        if ! grep -qF "|$_ks|" "$MAN"; then
            cp -p "$_ks" "$BK/cacerts.$_i" && echo "file|$_ks|$BK/cacerts.$_i" >> "$MAN" \
                || { log "Backup of $_ks failed - skipped"; continue; }
        fi
        "$_kt" -delete -alias "$_a" -keystore "$_ks" -storepass "$JAVA_STOREPASS" \
            && log "Deleted alias $_a from $_ks" || log "keytool -delete failed for $_ks"
    done < "$WORK/java_hits"
fi

# 5. control check - roll back this run if we broke normal TLS
if [ "$CTRL_BEFORE" = true ]; then
    if control_ok; then
        log "Control site still OK"
    else
        log "Control site $CONTROL_HOST failed after change ($P_CODE) - rolling back this run"
        rollback_dir "$BK"; mv "$BK" "$BK.rolledback"
        LIVE=INCONCLUSIVE; LIVE_DETAIL=" rolled-back"; STORE_HITS=1; JAVA_HITS=0
        finish
    fi
else
    log "Control site unreachable before the change - skipping the control check"
fi

# 6. re-verify
log "Live test after:"
live_test
log "Trust stores after:"
scan_stores
log "IBM Java keystores after:"
java_scan
finish

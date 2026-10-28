#!/bin/sh
# find-php.sh - find PHP on a Linux / macOS host and flag versions affected by the Oct 2026
# "PHP2Shell" RCE bugs (CVE-2026-109618 / CVE-2026-109619). Read-only. POSIX sh.
#
# Host-side complement to network/Find-PHPExposure.ps1 and ninjaone/Find-PHPInstalled.ps1.
#
# Finds:  php / php-cgi / php-fpm binaries on PATH and in the usual places (distro, Remi,
#         cPanel EA-PHP, Plesk, Bitnami, Homebrew, MAMP), distro packages (dpkg / rpm / apk),
#         Apache mod_php, and running php-fpm / php-cgi processes.
# Verdict per binary (fixed releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35):
#   VULNERABLE        below the fix, not from a distro package
#   BELOW_FIX_DISTRO  below the upstream fix but installed from a distro package - distros
#                     backport fixes without changing the version, so check the package
#                     version against your distro's advisory (shown in the output)
#   UNSUPPORTED       PHP 8.1 or older (no upstream fix; distro/LTS backports possible)
#   PATCHED           at or above the fix
#
# NinjaOne: when ninjarmm-cli is present, writes "<WORST> | <timestamp> | <details>" to the
# device text field phpStatus (script variable ninjaField overrides, "none" disables).
#
# Exit codes: 0 = no PHP or all PATCHED, 1 = anything else found, 2 = error.
# Usage: sh find-php.sh

NINJA_FIELD="${ninjaField:-phpStatus}"
NINJA_CLI=""
for c in /opt/NinjaRMMAgent/programdata/ninjarmm-cli \
         /Applications/NinjaRMMAgent/programdata/ninjarmm-cli; do
    [ -x "$c" ] && { NINJA_CLI="$c"; break; }
done

TS=$(date '+%Y-%m-%d %H:%M')
HOST=$(hostname 2>/dev/null || uname -n)
TMP=$(mktemp -d 2>/dev/null || echo "/tmp/find-php.$$")
mkdir -p "$TMP" || exit 2
trap 'rm -rf "$TMP"' EXIT INT TERM

set_field() {
    [ -n "$NINJA_CLI" ] && [ -n "$NINJA_FIELD" ] && [ "$NINJA_FIELD" != "none" ] || return 0
    if out=$("$NINJA_CLI" set "$NINJA_FIELD" "$1" 2>&1); then
        echo "Wrote result to custom field '$NINJA_FIELD'."
    else
        echo "WARNING: could not write custom field '$NINJA_FIELD': $out"
    fi
}

# verdict <version> <distro:0|1>
verdict() {
    v=$1
    maj=$(echo "$v" | cut -d. -f1); min=$(echo "$v" | cut -d. -f2)
    pat=$(echo "$v" | cut -d. -f3 | sed 's/[^0-9].*//')
    case "$maj.$min" in *[!0-9.]*|.|*.) echo UNKNOWN; return ;; esac
    [ -z "$pat" ] && { echo UNKNOWN; return; }
    if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -le 1 ]; }; then echo UNSUPPORTED; return; fi
    fix=""
    case "$maj.$min" in
        8.2) fix=35 ;; 8.3) fix=36 ;; 8.4) fix=27 ;; 8.5) fix=12 ;;
        8.6) case "$v" in *[Rr][Cc][0-3]|*[Rr][Cc][0-3][!0-9]*|*alpha*|*beta*|*dev*) fix=999 ;; esac ;;
    esac
    if [ -n "$fix" ] && [ "$pat" -lt "$fix" ]; then
        if [ "$2" = 1 ]; then echo BELOW_FIX_DISTRO; else echo VULNERABLE; fi
        return
    fi
    echo PATCHED
}

# owning package of a file (empty if none)
owner_pkg() {
    if command -v dpkg-query >/dev/null 2>&1; then
        p=$(dpkg-query -S "$1" 2>/dev/null | head -1 | cut -d: -f1)
        [ -n "$p" ] && { echo "$p $(dpkg-query -W -f='${Version}' "$p" 2>/dev/null)"; return; }
    fi
    if command -v rpm >/dev/null 2>&1; then
        p=$(rpm -qf "$1" 2>/dev/null | grep -v 'not owned' | head -1)
        [ -n "$p" ] && { echo "$p"; return; }
    fi
    if command -v apk >/dev/null 2>&1; then
        p=$(apk info -W "$1" 2>/dev/null | sed -n 's/.* is owned by //p' | head -1)
        [ -n "$p" ] && { echo "$p"; return; }
    fi
    if command -v brew >/dev/null 2>&1; then
        case "$1" in */Cellar/*|*/opt/homebrew/*|/usr/local/opt/*) echo "homebrew"; return ;; esac
    fi
}

# ---------------------------------------------------------------- candidate binaries
: > "$TMP/cands"
for n in php php-cgi php-fpm; do command -v "$n" >> "$TMP/cands" 2>/dev/null; done
for g in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
         /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
         /opt/rh/*php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php \
         /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
         /opt/bitnami/php/bin/php /opt/bitnami/php/sbin/php-fpm /opt/lampp/bin/php \
         /usr/local/opt/php*/bin/php /opt/homebrew/opt/php*/bin/php /opt/homebrew/opt/php*/sbin/php-fpm \
         /Applications/MAMP/bin/php/php*/bin/php /Applications/XAMPP/xamppfiles/bin/php; do
    [ -f "$g" ] && [ -x "$g" ] && echo "$g" >> "$TMP/cands"
done
# running php-fpm / php-cgi processes
if [ -d /proc ]; then
    for p in /proc/[0-9]*; do
        e=$(readlink "$p/exe" 2>/dev/null) || continue
        case "$(basename "$e")" in php*) echo "$e" >> "$TMP/cands" ;; esac
    done
fi

# keep only real PHP executables (not php-config, phpize, phar...), dedupe by resolved path
: > "$TMP/bins"
sort -u "$TMP/cands" | while read -r b; do
    [ -n "$b" ] || continue
    case "$(basename "$b")" in
        php|php[0-9]*|php-cgi*|php-fpm*|php-cli*) ;;
        *) continue ;;
    esac
    case "$(basename "$b")" in *config*|*ize*|*.dpkg*) continue ;; esac
    r=$(readlink -f "$b" 2>/dev/null || echo "$b")
    echo "$r"
done | sort -u > "$TMP/bins"

# ---------------------------------------------------------------- inspect each binary
: > "$TMP/results"
while read -r b; do
    [ -n "$b" ] || continue
    out=$("$b" -n -v 2>/dev/null | head -1)
    case "$out" in PHP\ *) ;; *) continue ;; esac
    ver=$(echo "$out" | awk '{print $2}')
    pkg=$(owner_pkg "$b")
    distro=0
    case "$pkg" in ""|homebrew) ;; *) distro=1 ;; esac
    st=$(verdict "$ver" "$distro")
    sapi="cli"
    case "$out" in *"(fpm-fcgi)"*) sapi="fpm" ;; *"(cgi-fcgi)"*) sapi="cgi" ;; esac
    echo "$st|$ver|$sapi|$b|$pkg" >> "$TMP/results"
done < "$TMP/bins"

# ---------------------------------------------------------------- context
: > "$TMP/notes"
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
        | awk '$1 ~ /^ii/ && $2 ~ /^(php[0-9.]*-(cli|fpm|cgi|common)|libapache2-mod-php)/ {print "package: " $2 " " $3}' >> "$TMP/notes"
fi
if command -v rpm >/dev/null 2>&1; then
    rpm -qa 2>/dev/null | grep -E '^(ea-)?php[0-9]*-(cli|fpm|common|php)-|^php-(cli|fpm|common)-|^mod_php' \
        | sed 's/^/package: /' >> "$TMP/notes"
fi
if command -v apk >/dev/null 2>&1; then
    apk info -v 2>/dev/null | grep -E '^php[0-9]*-(cli|fpm|common|apache2)?' | sed 's/^/package: /' >> "$TMP/notes"
fi
for m in /etc/apache2/mods-enabled/php*.load /etc/httpd/conf.modules.d/*php*.conf; do
    [ -f "$m" ] && echo "Apache mod_php enabled: $m" >> "$TMP/notes"
done
for c in apache2ctl apachectl httpd; do
    if command -v "$c" >/dev/null 2>&1; then
        "$c" -M 2>/dev/null | grep -i php | sed "s/^ */Apache module loaded ($c): /" >> "$TMP/notes"
        break
    fi
done
if command -v ps >/dev/null 2>&1; then
    ps -eo comm= 2>/dev/null | grep -E '^php' | sort | uniq -c | awk '{print "running: " $2 " x" $1}' >> "$TMP/notes"
fi

# ---------------------------------------------------------------- report
echo "PHP2Shell host check (CVE-2026-109618 / CVE-2026-109619) - $HOST - $TS"
echo "Fixed in: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"
echo

if [ ! -s "$TMP/results" ]; then
    echo "No PHP found on this host."
    if [ -s "$TMP/notes" ]; then echo; echo "Related:"; sort -u "$TMP/notes" | sed 's/^/  /'; fi
    set_field "NO_PHP | $TS"
    exit 0
fi

printf '%-17s %-22s %-4s %-40s %s\n' STATUS VERSION SAPI BINARY PACKAGE
sort "$TMP/results" | while IFS='|' read -r st ver sapi b pkg; do
    printf '%-17s %-22s %-4s %-40s %s\n' "$st" "$ver" "$sapi" "$b" "${pkg:--}"
done
if [ -s "$TMP/notes" ]; then echo; echo "Related:"; sort -u "$TMP/notes" | sed 's/^/  /'; fi

worst=PATCHED
for s in VULNERABLE BELOW_FIX_DISTRO UNSUPPORTED UNKNOWN; do
    if grep -q "^$s|" "$TMP/results"; then worst=$s; break; fi
done

echo
case "$worst" in
    VULNERABLE)       echo "ACTION: upgrade to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later, then restart php-fpm / Apache." ;;
    BELOW_FIX_DISTRO) echo "ACTION: distro package below the upstream version - update it (apt/dnf/yum/apk) and compare the package version to the distro's advisory for CVE-2026-109618/109619, then restart php-fpm / Apache." ;;
    UNSUPPORTED)      echo "ACTION: PHP 8.1 or older - upgrade to a supported branch, or confirm your distro/LTS vendor shipped a backport." ;;
    UNKNOWN)          echo "ACTION: PHP found but the version could not be parsed - check it manually." ;;
    *)                echo "All PHP binaries found are at or above the fixed release." ;;
esac

detail=$(sort "$TMP/results" | awk -F'|' '{printf "%s%s %s %s [%s]", (NR>1?"; ":""), $1, $2, $4, ($5==""?"no pkg":$5)}')
set_field "$worst | $TS | $detail"
[ "$worst" = PATCHED ] && exit 0
exit 1

#!/bin/bash
# =============================================================================
# Detect-Nginx2Root-Mac.sh  (macOS edition of Detect-Nginx2Root.sh)
# Detects exposure to the "nginx2root" NGINX vulnerabilities disclosed 2026-11-18:
#
#   CVE-2026-123007  HTTP/2 flow-control integer underflow -> RCE   (1.9.5  - 1.31.8)  needs: HTTP/2 enabled
#   CVE-2026-123633  HTTP/2 use-after-free (proxying)       -> RCE   (1.19.7 - 1.31.8)  needs: HTTP/2 + upstream *_pass
#   CVE-2026-123634  Resolver use-after-free                         (0.6.18 - 1.31.8)  needs: resolver + variable proxy_pass + subrequest (mirror/ssi)
#   CVE-2026-121810  HTTP/3 (QUIC) use-after-free           -> RCE   (1.25.0 - 1.31.8)  needs: quic/http3 + upstream *_pass
#   CVE-2026-113425  Mail proxy use-after-free                       (0.5.33 - 1.31.8)  needs: mail { proxy on; auth_http }
#
# Fixed upstream in nginx 1.30.7 (stable) and 1.31.9 (mainline).
#
# macOS specifics:
#   - Runs on the stock /bin/bash 3.2 and BSD userland (no GNU tools, no /proc).
#   - Finds nginx from Homebrew (Apple Silicon + Intel), MacPorts, OpenResty, MAMP,
#     Laravel Herd/Valet, Local (Flywheel), ServBay, and any running master process.
#   - Containers: Docker Desktop, OrbStack, Colima and Rancher Desktop sockets for every user.
#   - nginx -v/-V/-T are run AS THE USER that owns the install (or runs the master), so a
#     root scan never creates root-owned log/pid files inside a user's nginx setup.
#
# Usage:  sudo ./Detect-Nginx2Root-Mac.sh [--json] [--no-docker] [--no-probe] [--ninja-field <name>]
# NinjaOne: writes "<OVERALL> | <timestamp> | details" to device field nginx2rootStatus
#           (script variable ninjaField overrides, "none" disables).
# Exit:   0 = not vulnerable / no nginx   1 = VULNERABLE (exposed)   2 = in range, review needed
#         3 = script error
# Safe:   read-only. Runs nginx -v / -V / -T only (no reload, no restart).
# =============================================================================

export LC_ALL=C
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/opt/local/bin:/opt/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin:/Applications/Docker.app/Contents/Resources/bin:$PATH"

FIX_STABLE="1.30.7"
FIX_MAINLINE="1.31.9"
CVES="CVE-2026-123007 CVE-2026-123633 CVE-2026-123634 CVE-2026-121810 CVE-2026-113425"

first_for() {
  case "$1" in
    CVE-2026-123007) echo "1.9.5" ;;  CVE-2026-123633) echo "1.19.7" ;;
    CVE-2026-123634) echo "0.6.18" ;; CVE-2026-121810) echo "1.25.0" ;;
    CVE-2026-113425) echo "0.5.33" ;;
  esac
}
desc_for() {
  case "$1" in
    CVE-2026-123007) echo "HTTP/2 flow-control underflow (RCE, public PoC)" ;;
    CVE-2026-123633) echo "HTTP/2 use-after-free when proxying (RCE)" ;;
    CVE-2026-123634) echo "Resolver use-after-free (resolver+var proxy_pass+mirror/ssi)" ;;
    CVE-2026-121810) echo "HTTP/3 QUIC use-after-free when proxying (RCE)" ;;
    CVE-2026-113425) echo "Mail proxy auth_http use-after-free" ;;
  esac
}

OPT_JSON=0; OPT_DOCKER=1; OPT_PROBE=1; NINJA_FIELD="${ninjaField:-nginx2rootStatus}"
while [ $# -gt 0 ]; do
  case "$1" in
    --json) OPT_JSON=1 ;;
    --no-docker) OPT_DOCKER=0 ;;
    --no-probe) OPT_PROBE=0 ;;
    --ninja-field) NINJA_FIELD="${2:-}"; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 3 ;;
  esac
  shift
done

RANK=0           # 0 clean, 1 review, 2 vulnerable
SUMMARY=()
JSON_ITEMS=()
NSUM=0

log() { [ $OPT_JSON -eq 1 ] || printf '%b\n' "$*"; }

# ver_ge A B -> true if A >= B (numeric, dot separated; no sort -V on older macOS)
ver_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN{n=split(a,x,".");m=split(b,y,".");k=(n>m)?n:m
    for(i=1;i<=k;i++){if((x[i]+0)>(y[i]+0))exit 0;if((x[i]+0)<(y[i]+0))exit 1};exit 0}'
}
fixed_for() { if ver_ge "$1" "1.31.0"; then echo "$FIX_MAINLINE"; else echo "$FIX_STABLE"; fi; }
json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r'; }

# Run a command with a time limit (no coreutils timeout on macOS; perl alarm survives exec)
with_timeout() {
  local secs="$1"; shift
  if command -v perl >/dev/null 2>&1; then perl -e 'alarm shift; exec @ARGV or exit 127' "$secs" "$@"; else "$@"; fi
}

# Resolve symlinks without GNU readlink -f (missing before macOS 12.3)
realp() {
  local p="$1" i=0 d l
  while [ -L "$p" ] && [ $i -lt 20 ]; do
    l=$(readlink "$p"); case "$l" in /*) p="$l" ;; *) p="$(dirname "$p")/$l" ;; esac; i=$((i+1))
  done
  d=$(cd "$(dirname "$p")" 2>/dev/null && pwd -P) || { echo "$1"; return; }
  echo "$d/$(basename "$p")"
}

file_owner() { ls -ld "$1" 2>/dev/null | awk '{print $3}'; }

# run_as <user> <timeout> <cmd...> : run (time-limited) as that user when we are root and
# the user is a normal account, so nginx never creates root-owned files in a user's setup
run_as() {
  local u="$1" secs="$2"; shift 2
  if [ "$EUID" -eq 0 ] && [ -n "$u" ] && [ "$u" != "root" ] && id "$u" >/dev/null 2>&1; then
    with_timeout "$secs" sudo -n -u "$u" -- "$@"
  else
    with_timeout "$secs" "$@"
  fi
}

pkg_note() {
  case "$1" in
    /opt/homebrew/*|/usr/local/Cellar/*|/usr/local/opt/*) echo "PKG:Homebrew ($(echo "$1" | sed -n 's#.*/Cellar/\([^/]*\)/\([^/]*\)/.*#\1 \2#p'))" ;;
    /opt/local/*) echo "PKG:MacPorts" ;;
    /Applications/MAMP*) echo "PKG:MAMP (update MAMP to a release bundling nginx >= $FIX_STABLE)" ;;
    *"/Herd/"*) echo "PKG:Laravel Herd (update Herd)" ;;
    *"/Local/lightning-services/"*) echo "PKG:Local by Flywheel (update the nginx lightning service)" ;;
    *ServBay*) echo "PKG:ServBay (update nginx package in ServBay)" ;;
    *) echo "PKG:none (source build or unknown - version string is authoritative)" ;;
  esac
}

# analyze <label> <nginx -v output> <nginx -V output> <nginx -T output|""> <pkg lines> <extra notes>
analyze() {
  local label="$1" vout="$2" Vout="$3" conf="$4" bp="$5" notes="$6"
  local ver plus="" rank=0 openresty=""
  ver=$(echo "$vout" | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d/ -f2)
  if [ -z "$ver" ]; then
    openresty=$(echo "$vout$Vout" | grep -oE 'openresty/[0-9]+(\.[0-9]+)+' | head -n1 | cut -d/ -f2)
    [ -n "$openresty" ] && ver=$(echo "$openresty" | cut -d. -f1-3)
  fi
  plus=$(echo "$vout$Vout" | grep -oiE 'nginx-plus-r[0-9]+(-p[0-9]+)?' | head -n1)
  [ -z "$plus" ] && echo "$vout$Vout" | grep -qi 'nginx-plus' && plus="nginx-plus"

  log "\n=================================================================="
  log " $label"
  log "=================================================================="
  local orn=""; [ -n "$openresty" ] && orn=" (nginx core of OpenResty $openresty - fix needs an OpenResty release on nginx >= $FIX_STABLE)"
  local pn=""; [ -n "$plus" ] && pn=" ($plus)"
  log " Version     : ${ver:-UNKNOWN}$pn$orn"
  log " Package     : $(echo "$bp" | grep '^PKG:' | cut -d: -f2-)"
  [ -n "$notes" ] && log " NOTE        : $notes"

  local has_h2mod=0 has_h3mod=0 has_mailmod=0
  echo "$Vout" | grep -q -- '--with-http_v2_module' && has_h2mod=1
  echo "$Vout" | grep -q -- '--with-http_v3_module' && has_h3mod=1
  echo "$Vout" | grep -qE -- '--with-mail(=dynamic)?( |$)' && has_mailmod=1

  local c="" conf_known=0
  if [ -n "$conf" ] && echo "$conf" | grep -q 'test is successful'; then
    conf_known=1
    # strip comments, then one statement per line (split after { } ;) - BSD awk safe
    c=$(echo "$conf" | awk '{sub(/#.*/,""); gsub(/[{};]/,"&\n"); print}')
  fi
  local S='[[:space:]]' E='([[:space:];]|$)'
  local h2=0 h3=0 upstream=0 resolver=0 varpass=0 subreq=0 mail=0 mailproxy=0 authhttp=0 h2off=0
  if [ $conf_known -eq 1 ]; then
    echo "$c" | grep -qE "^$S*listen${S}[^;]*${S}http2$E" && h2=1
    echo "$c" | grep -qE "^$S*http2$S+on$S*;" && h2=1
    echo "$c" | grep -qE "^$S*http2$S+off$S*;" && h2off=1
    echo "$c" | grep -qE "^$S*listen${S}[^;]*${S}quic$E" && h3=1
    echo "$c" | grep -qE "^$S*http3$S+on$S*;" && h3=1
    echo "$c" | grep -qE "^$S*(proxy|fastcgi|grpc|uwsgi|scgi|memcached)_pass$S" && upstream=1
    echo "$c" | grep -qE "^$S*resolver$S" && resolver=1
    echo "$c" | grep -qE "^$S*proxy_pass${S}[^;]*\\\$" && varpass=1
    echo "$c" | grep -qE "^$S*(mirror$S+[^o;]|ssi$S+on$S*;)" && subreq=1
    echo "$c" | grep -qE "^$S*mail$S*\{" && mail=1
    echo "$c" | grep -qE "^$S*proxy$S+on$S*;" && mailproxy=1
    echo "$c" | grep -qE "^$S*auth_http$S" && authhttp=1
  fi

  log " Build       : http_v2_module=$has_h2mod  http_v3_module=$has_h3mod  mail=$has_mailmod"
  if [ $conf_known -eq 1 ]; then
    log " Config      : http2=$h2 http3/quic=$h3 upstream_pass=$upstream resolver=$resolver var_proxy_pass=$varpass mirror/ssi=$subreq mail=$mail(proxy=$mailproxy auth_http=$authhttp)"
    [ $h2off -eq 1 ] && [ $h2 -eq 1 ] && log " WARNING     : 'http2 off;' present but http2 is still enabled elsewhere"
  else
    log " Config      : COULD NOT READ (nginx -T failed) - exposure unknown"
  fi

  # ---- ALPN probe for live HTTP/2 (host instances only)
  local alpn_h2=""
  case "$label" in docker:*) ;; *)
  if [ $OPT_PROBE -eq 1 ] && [ $conf_known -eq 1 ] && command -v openssl >/dev/null 2>&1; then
    local targets t host port r
    targets=$(echo "$c" | grep -E "^$S*listen$S" | grep -E "$S(ssl|http2)$E|[:[:space:]]443$E" | awk '{print $2}' | tr -d ';' | sort -u)
    for t in $targets; do
      host="127.0.0.1"; port=""
      # no [[ =~ ]] here: bash 3.2.0-3.2.x parse regex parentheses inconsistently
      case "$t" in
        \[*\]:*)  port="${t##*:}"; host="::1" ;;
        \*:*)     port="${t##*:}" ;;
        *.*.*.*:*) host="${t%:*}"; port="${t##*:}"; [ "$host" = "0.0.0.0" ] && host="127.0.0.1" ;;
        *[!0-9]*|"") continue ;;
        *)        port="$t" ;;
      esac
      case "$port" in ""|*[!0-9]*) continue ;; esac
      r=$(with_timeout 5 openssl s_client -connect "$host:$port" -alpn h2 </dev/null 2>/dev/null | grep -m1 '^ALPN protocol:')
      case "$r" in *h2*) alpn_h2="$alpn_h2$host:$port " ;; esac
    done
    if [ -n "$alpn_h2" ]; then log " ALPN probe  : h2 NEGOTIATED on ${alpn_h2}"; h2=1; else log " ALPN probe  : no h2 negotiated on local TLS listeners"; fi
  fi ;; esac

  log ""
  local hdr line cve status detail inrange exposed fv first jc=""
  printf -v hdr " %-16s %-22s %s" "CVE" "STATUS" "DETAIL"; log "$hdr"
  for cve in $CVES; do
    inrange=0; exposed=0; first=$(first_for "$cve")
    if echo "$bp" | grep -q "^FIX:$cve\$"; then
      status="PATCHED(backport)"; detail="package notes reference $cve"
    elif [ -n "$plus" ]; then
      inrange=2; status="REVIEW(NGINX Plus)"; detail="verify $plus against F5 advisory"
    elif [ -z "$ver" ]; then
      inrange=2; status="REVIEW"; detail="version could not be determined"
    elif ! ver_ge "$ver" "$first"; then
      status="NOT AFFECTED"; detail="older than first affected $first"
    else
      fv=$(fixed_for "$ver")
      if ver_ge "$ver" "$fv"; then status="PATCHED"; detail=">= $fv"; else inrange=1; detail="needs >= $fv"; fi
    fi

    if [ $inrange -ne 0 ]; then
      case "$cve" in
        CVE-2026-123007) [ $has_h2mod -eq 1 ] && [ $h2 -eq 1 ] && exposed=1; [ $has_h2mod -eq 0 ] && [ -n "$Vout" ] && exposed=-1 ;;
        CVE-2026-123633) [ $has_h2mod -eq 1 ] && [ $h2 -eq 1 ] && [ $upstream -eq 1 ] && exposed=1; [ $has_h2mod -eq 0 ] && [ -n "$Vout" ] && exposed=-1 ;;
        CVE-2026-123634) [ $resolver -eq 1 ] && [ $varpass -eq 1 ] && [ $subreq -eq 1 ] && exposed=1
                         [ $resolver -eq 1 ] && [ $varpass -eq 1 ] && [ $subreq -eq 0 ] && detail="$detail; resolver+var proxy_pass present (other subrequests may reach bug)" ;;
        CVE-2026-121810) [ $h3 -eq 1 ] && [ $upstream -eq 1 ] && exposed=1; [ $has_h3mod -eq 0 ] && [ -n "$Vout" ] && exposed=-1 ;;
        CVE-2026-113425) [ $mail -eq 1 ] && [ $mailproxy -eq 1 ] && [ $authhttp -eq 1 ] && exposed=1; [ $has_mailmod -eq 0 ] && [ -n "$Vout" ] && [ $mail -eq 0 ] && exposed=-1 ;;
      esac
      if [ $exposed -eq 1 ]; then status="VULNERABLE"; rank=2
      elif [ $exposed -eq -1 ]; then status="IN RANGE-not built"; detail="$detail; module not compiled in"
      elif [ $conf_known -eq 0 ]; then status="IN RANGE-cfg unknown"; [ $rank -lt 1 ] && rank=1
      else status="IN RANGE-not exposed"; detail="$detail; vulnerable feature not enabled in config"; [ $rank -lt 1 ] && rank=1
      fi
      if [ $inrange -eq 2 ] && [ $exposed -eq 1 ]; then
        if [ -n "$plus" ]; then status="VULNERABLE?(Plus)"; else status="VULNERABLE?(ver unknown)"; fi
      fi
    fi
    printf -v line " %-16s %-22s %s" "$cve" "$status" "$detail"; log "$line"
    case "$status" in VULNERABLE*) log "                  -> $(desc_for "$cve")" ;; esac
    [ -n "$jc" ] && jc="$jc,"
    jc="$jc{\"cve\":\"$cve\",\"status\":\"$(json_esc "$status")\",\"detail\":\"$(json_esc "$detail")\"}"
  done
  [ -n "$notes" ] && [ $rank -lt 1 ] && rank=1

  local verdict="CLEAN"; [ $rank -eq 1 ] && verdict="REVIEW"; [ $rank -eq 2 ] && verdict="VULNERABLE"
  log "\n RESULT      : $verdict"
  if [ $rank -eq 2 ]; then
    log " ACTION      : Upgrade to nginx $FIX_STABLE/$FIX_MAINLINE (brew upgrade nginx / update the bundling app)."
    log "               Stopgap for 123007/123633: remove 'http2' from listen lines AND set 'http2 off;', nginx -t, then RESTART."
  fi
  [ $rank -gt $RANK ] && RANK=$rank
  local ors=""; [ -n "$openresty" ] && ors=" (openresty $openresty)"
  SUMMARY[$NSUM]="$verdict | $label | ${ver:-?}${plus:+ $plus}$ors"
  JSON_ITEMS[$NSUM]="{\"target\":\"$(json_esc "$label")\",\"version\":\"${ver:-}\",\"plus\":\"$(json_esc "$plus")\",\"verdict\":\"$verdict\",\"notes\":\"$(json_esc "$notes")\",\"cves\":[$jc]}"
  NSUM=$((NSUM+1))
}

# =============================================================================
# Discover host nginx instances  (parallel arrays - bash 3.2 has no assoc arrays)
# =============================================================================
[ "$EUID" -ne 0 ] && log "WARNING: not running as root - other users' installs and configs may be missed."

B_PATH=(); B_CONF=(); B_PFX=(); B_USER=(); B_NOTE=(); B_FOUND=(); NB=0
bin_index() {  # echo index of realpath $1 or -1
  local i=0; while [ $i -lt $NB ]; do [ "${B_PATH[$i]}" = "$1" ] && { echo $i; return; }; i=$((i+1)); done; echo -1
}
add_bin() {  # add_bin <realpath> <conf> <prefix> <user> <note> <found_by_search 0|1>
  local idx; idx=$(bin_index "$1")
  if [ "$idx" -lt 0 ]; then
    B_PATH[$NB]="$1"; B_CONF[$NB]="$2"; B_PFX[$NB]="$3"; B_USER[$NB]="$4"; B_NOTE[$NB]="$5"; B_FOUND[$NB]="$6"; NB=$((NB+1))
  fi
}

# Running master processes (authoritative: what is actually serving). Docker Desktop
# containers run inside a VM and never show up here, so no double counting.
while read -r pid puser args; do
  [ -z "$pid" ] && continue
  rest="${args#nginx: master process }"
  bin=$(echo "$rest" | awk '{for(i=1;i<=NF;i++) if($i ~ /\/nginx$/ || $i=="nginx"){print $i; exit}}')
  if [ -z "$bin" ] || [ "$bin" = "nginx" ]; then
    bin=$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -n1)
  fi
  [ -z "$bin" ] && continue
  # -c / -p values may contain spaces ("Application Support"): take text up to the next " -x " flag
  confarg=$(echo " $rest" | sed -n 's/.* -c \(.*\)$/\1/p' | sed 's/ -[a-zA-Z] .*$//; s/ -[a-zA-Z]$//')
  pfxarg=$(echo " $rest" | sed -n 's/.* -p \(.*\)$/\1/p' | sed 's/ -[a-zA-Z] .*$//; s/ -[a-zA-Z]$//')
  note=""
  [ -e "$bin" ] || note="Master PID $pid runs $bin which no longer exists on disk - upgraded but NOT restarted. Restart nginx."
  add_bin "$(realp "$bin")" "$confarg" "$pfxarg" "$puser" "$note" 0
done < <(ps -axo pid=,user=,args= 2>/dev/null | grep -E 'nginx: master process' | grep -v grep)

# Known install locations
for b in "$(command -v nginx 2>/dev/null)" \
         /opt/homebrew/bin/nginx /opt/homebrew/opt/nginx/bin/nginx /opt/homebrew/Cellar/nginx/*/bin/nginx \
         /opt/homebrew/opt/openresty/nginx/sbin/nginx /opt/homebrew/Cellar/openresty/*/nginx/sbin/nginx \
         /usr/local/bin/nginx /usr/local/sbin/nginx /usr/local/opt/nginx/bin/nginx /usr/local/Cellar/nginx/*/bin/nginx \
         /usr/local/opt/openresty/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx /usr/local/nginx/sbin/nginx \
         /opt/local/sbin/nginx /opt/local/bin/nginx /opt/nginx/sbin/nginx \
         /Applications/MAMP/Library/bin/nginx /Applications/MAMP\ PRO*/Library/bin/nginx \
         /Users/*/Library/Application\ Support/Herd/bin/nginx \
         /Users/*/.config/herd/bin/nginx; do
  [ -n "$b" ] && [ -f "$b" ] && [ -x "$b" ] || continue
  rp=$(realp "$b"); add_bin "$rp" "" "" "$(file_owner "$rp")" "" 0
done

# Bounded search for app-bundled copies (Local, ServBay, MAMP variants, dev tool bundles)
while IFS= read -r b; do
  [ -n "$b" ] || continue
  case "$b" in /Applications/NinjaRMMAgent/*) continue ;; esac
  rp=$(realp "$b"); add_bin "$rp" "" "" "$(file_owner "$rp")" "" 1
done < <(with_timeout 120 find /Applications /opt /Users/*/Library/Application\ Support /Users/*/Applications \
            -maxdepth 8 -type f -name nginx -perm -100 2>/dev/null)

i=0
while [ $i -lt $NB ]; do
  rp="${B_PATH[$i]}"; u="${B_USER[$i]}"; note="${B_NOTE[$i]}"
  if [ ! -x "$rp" ]; then
    analyze "host:$rp" "" "" "" "PKG:unknown" "${note:-binary not executable/present}"; i=$((i+1)); continue
  fi
  vout=$(run_as "$u" 15 "$rp" -v 2>&1); Vout=$(run_as "$u" 15 "$rp" -V 2>&1)
  # search hits that are not actually nginx (wrapper scripts, other tools) are skipped
  if [ "${B_FOUND[$i]}" = "1" ] && ! echo "$vout" | grep -qE 'nginx/|openresty/'; then i=$((i+1)); continue; fi
  targs=(-T)
  [ -n "${B_PFX[$i]}" ] && targs=("${targs[@]}" -p "${B_PFX[$i]}")
  [ -n "${B_CONF[$i]}" ] && targs=("${targs[@]}" -c "${B_CONF[$i]}")
  conf=$(run_as "$u" 30 "$rp" "${targs[@]}" 2>&1)
  echo "$conf" | grep -q 'test is successful' || conf=""
  label="host:$rp"; [ -n "${B_PFX[$i]}" ] && label="$label (-p ${B_PFX[$i]})"; [ -n "${B_CONF[$i]}" ] && label="$label (-c ${B_CONF[$i]})"
  [ -n "$u" ] && [ "$u" != "root" ] && label="$label [user $u]"
  analyze "$label" "$vout" "$Vout" "$conf" "$(pkg_note "$rp")" "$note"
  i=$((i+1))
done

# =============================================================================
# Containers: Docker Desktop / OrbStack / Colima / Rancher Desktop (per user socket)
# =============================================================================
if [ $OPT_DOCKER -eq 1 ] && command -v docker >/dev/null 2>&1; then
  SEEN=" "
  for sock in /var/run/docker.sock /Users/*/.docker/run/docker.sock /Users/*/.orbstack/run/docker.sock \
              /Users/*/.colima/*/docker.sock /Users/*/.rd/docker.sock; do
    [ -S "$sock" ] || continue
    export DOCKER_HOST="unix://$sock"
    with_timeout 15 docker info >/dev/null 2>&1 || continue
    while read -r cid cname cimage; do
      [ -z "$cid" ] && continue
      case "$SEEN" in *" $cid "*) continue ;; esac; SEEN="$SEEN$cid "
      vout=$(with_timeout 20 docker exec "$cid" sh -c 'nginx -v 2>&1' 2>/dev/null) || continue
      echo "$vout" | grep -qE 'nginx|openresty' || continue
      Vout=$(with_timeout 20 docker exec "$cid" sh -c 'nginx -V 2>&1' 2>/dev/null)
      conf=$(with_timeout 30 docker exec "$cid" sh -c 'nginx -T 2>&1' 2>/dev/null)
      echo "$conf" | grep -q 'test is successful' || conf=""
      bp="PKG:image $cimage"
      cl=$(with_timeout 20 docker exec "$cid" sh -c 'for f in /usr/share/doc/nginx*/changelog.Debian.gz; do [ -f "$f" ] && zcat "$f"; done; rpm -q --changelog nginx 2>/dev/null' 2>/dev/null)
      for cv in $CVES; do echo "$cl" | grep -q "$cv" && bp="$bp
FIX:$cv"; done
      analyze "docker:$cname ($cimage)" "$vout" "$Vout" "$conf" "$bp" ""
    done < <(with_timeout 20 docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null)
  done
  unset DOCKER_HOST
fi

# =============================================================================
# Summary / output
# =============================================================================
HOST=$(scutil --get ComputerName 2>/dev/null || hostname 2>/dev/null)
OVERALL="CLEAN"; EXITC=0
[ $NSUM -eq 0 ] && OVERALL="NO NGINX FOUND"
[ $RANK -eq 1 ] && { OVERALL="REVIEW"; EXITC=2; }
[ $RANK -eq 2 ] && { OVERALL="VULNERABLE"; EXITC=1; }

joined() { local sep="$1" out="" k=0; shift; while [ $k -lt $NSUM ]; do [ $k -gt 0 ] && out="$out$sep"; eval "out=\"\$out\${$1[$k]}\""; k=$((k+1)); done; printf '%s' "$out"; }

if [ $OPT_JSON -eq 1 ]; then
  echo "{\"host\":\"$(json_esc "$HOST")\",\"scanned\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"overall\":\"$OVERALL\",\"instances\":[$(joined , JSON_ITEMS)]}"
else
  printf '\n######## nginx2root SUMMARY - %s - %s ########\n' "$HOST" "$(date '+%Y-%m-%d %H:%M:%S')"
  [ $NSUM -eq 0 ] && echo " No nginx binaries, processes, or containers found."
  k=0; while [ $k -lt $NSUM ]; do echo " ${SUMMARY[$k]}"; k=$((k+1)); done
  echo " OVERALL: $OVERALL"
fi

# NinjaOne custom field (macOS agent CLI)
NCLI=""
for n in /Applications/NinjaRMMAgent/programdata/ninjarmm-cli /Applications/NinjaRMMAgent/ninjarmm-cli; do
  [ -x "$n" ] && { NCLI="$n"; break; }
done
if [ -n "$NCLI" ] && [ -n "$NINJA_FIELD" ] && [ "$NINJA_FIELD" != "none" ]; then
  val="$OVERALL | $(date '+%Y-%m-%d %H:%M:%S') | $(joined ';' SUMMARY)"
  if "$NCLI" set "$NINJA_FIELD" "${val:0:1000}" >/dev/null 2>&1; then
    [ $OPT_JSON -eq 1 ] || echo "Wrote result to custom field '$NINJA_FIELD'."
  else echo "WARNING: could not write custom field '$NINJA_FIELD'" >&2; fi
fi

exit $EXITC

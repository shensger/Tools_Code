#!/usr/bin/env bash
# =============================================================================
# Detect-Nginx2Root.sh
# Detects exposure to the "nginx2root" NGINX vulnerabilities disclosed 2026-11-18:
#
#   CVE-2026-123007  HTTP/2 flow-control integer underflow -> RCE   (1.9.5  - 1.31.8)  needs: HTTP/2 enabled
#   CVE-2026-123633  HTTP/2 use-after-free (proxying)       -> RCE   (1.19.7 - 1.31.8)  needs: HTTP/2 + upstream *_pass
#   CVE-2026-123634  Resolver use-after-free                         (0.6.18 - 1.31.8)  needs: resolver + variable proxy_pass + subrequest (mirror/ssi)
#   CVE-2026-121810  HTTP/3 (QUIC) use-after-free           -> RCE   (1.25.0 - 1.31.8)  needs: quic/http3 + upstream *_pass
#   CVE-2026-113425  Mail proxy use-after-free                       (0.5.33 - 1.31.8)  needs: mail { proxy on; auth_http }
#
# Fixed upstream in nginx 1.30.7 (stable) and 1.31.9 (mainline).
# NGINX Plus: see F5 K000163926 / K000163928 / K000163925 / K000163927 / K000163931.
#
# Checks: every nginx binary on disk + every running master process, distro
# package changelog for backported fixes, the live config (nginx -T), a local
# ALPN h2 probe, running Docker containers, and "binary replaced but not restarted".
#
# Usage:  sudo ./Detect-Nginx2Root.sh [--json] [--no-docker] [--no-probe] [--ninja-field <name>]
# NinjaOne: writes "<OVERALL> | <timestamp> | details" to device text field nginx2rootStatus when the
#           agent is present (script variable ninjaField overrides, "none" disables).
# Exit:   0 = not vulnerable / no nginx   1 = VULNERABLE (exposed)   2 = in vulnerable version range, review needed
#         3 = script error
# Safe:   read-only. Runs nginx -v / -V / -T only (no reload, no restart).
# =============================================================================

set -u
export LC_ALL=C

FIX_STABLE="1.30.7"
FIX_MAINLINE="1.31.9"
CVES=(CVE-2026-123007 CVE-2026-123633 CVE-2026-123634 CVE-2026-121810 CVE-2026-113425)
declare -A FIRST=(
  [CVE-2026-123007]="1.9.5"
  [CVE-2026-123633]="1.19.7"
  [CVE-2026-123634]="0.6.18"
  [CVE-2026-121810]="1.25.0"
  [CVE-2026-113425]="0.5.33"
)
declare -A DESC=(
  [CVE-2026-123007]="HTTP/2 flow-control underflow (RCE, public PoC)"
  [CVE-2026-123633]="HTTP/2 use-after-free when proxying (RCE)"
  [CVE-2026-123634]="Resolver use-after-free (resolver+var proxy_pass+mirror/ssi)"
  [CVE-2026-121810]="HTTP/3 QUIC use-after-free when proxying (RCE)"
  [CVE-2026-113425]="Mail proxy auth_http use-after-free"
)

OPT_JSON=0; OPT_DOCKER=1; OPT_PROBE=1; NINJA_FIELD="${ninjaField:-nginx2rootStatus}"
while [[ $# -gt 0 ]]; do
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

log() { [[ $OPT_JSON -eq 1 ]] || echo -e "$*"; }

# ver_ge A B -> true if A >= B
ver_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

fixed_for() {  # fixed version for the branch the given version is on
  if ver_ge "$1" "1.31.0"; then echo "$FIX_MAINLINE"; else echo "$FIX_STABLE"; fi
}

json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r'; }

# Pull CVE mentions from the distro package changelog for the package owning a binary
backport_hits() {
  local bin="$1" pkg out=""
  if command -v dpkg-query >/dev/null 2>&1 && pkg=$(dpkg -S "$bin" 2>/dev/null | head -n1 | cut -d: -f1) && [[ -n "$pkg" ]]; then
    local src; src=$(dpkg-query -W -f='${source:Package}' "$pkg" 2>/dev/null); src=${src:-nginx}
    for f in /usr/share/doc/"$pkg"/changelog.Debian.gz /usr/share/doc/"$src"/changelog.Debian.gz /usr/share/doc/nginx*/changelog.Debian.gz; do
      [[ -f "$f" ]] && out+=$(zcat "$f" 2>/dev/null)
    done
    echo "PKG:$pkg $(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
  elif command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$bin" 2>/dev/null) && [[ $? -eq 0 && "$pkg" != *"not owned"* ]]; then
    out=$(rpm -q --changelog "$pkg" 2>/dev/null)
    echo "PKG:$pkg"
  elif command -v apk >/dev/null 2>&1 && pkg=$(apk info --who-owns "$bin" 2>/dev/null | awk '{print $NF}') && [[ -n "$pkg" ]]; then
    echo "PKG:$pkg (Alpine - no changelog; compare with Alpine secdb)"
  else
    echo "PKG:none (source build or unknown - version string is authoritative)"
  fi
  for c in "${CVES[@]}"; do grep -aq "$c" <<<"$out" && echo "FIX:$c"; done
}

# analyze <label> <nginx -v output> <nginx -V output> <nginx -T output|""> <backport lines> <extra notes>
analyze() {
  local label="$1" vout="$2" Vout="$3" conf="$4" bp="$5" notes="$6"
  local ver plus="" rank=0
  ver=$(grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' <<<"$vout" | head -n1 | cut -d/ -f2)
  # OpenResty (nginx-proxy-manager, Kong, etc.) prints openresty/1.27.1.2 - first 3 parts = nginx core
  local openresty=""
  if [[ -z "$ver" ]] && openresty=$(grep -oE 'openresty/[0-9]+(\.[0-9]+)+' <<<"$vout$Vout" | head -n1 | cut -d/ -f2) && [[ -n "$openresty" ]]; then
    ver=$(cut -d. -f1-3 <<<"$openresty")
  fi
  grep -qiE 'nginx-plus|plus-r[0-9]+' <<<"$vout$Vout" && plus=$(grep -oiE 'nginx-plus-r[0-9]+(-p[0-9]+)?' <<<"$vout$Vout" | head -n1)
  [[ -n "$plus" ]] || grep -qi 'nginx-plus' <<<"$vout$Vout" && plus=${plus:-"nginx-plus"}

  log "\n=================================================================="
  log " $label"
  log "=================================================================="
  log " Version     : ${ver:-UNKNOWN}${plus:+ ($plus)}${openresty:+ (nginx core of OpenResty $openresty - fix needs an OpenResty/image release on nginx >= $FIX_STABLE)}"
  local pkgline; pkgline=$(grep '^PKG:' <<<"$bp" | cut -d: -f2-)
  log " Package     : ${pkgline:-n/a}"
  [[ -n "$notes" ]] && log " NOTE        : $notes"

  # ---- Build capabilities
  local has_h2mod=0 has_h3mod=0 has_mailmod=0
  grep -q -- '--with-http_v2_module' <<<"$Vout" && has_h2mod=1
  grep -q -- '--with-http_v3_module' <<<"$Vout" && has_h3mod=1
  grep -qE -- '--with-mail(=dynamic)?( |$)' <<<"$Vout" && has_mailmod=1

  # ---- Config exposure (comments stripped)
  local c="" conf_known=0
  if [[ -n "$conf" ]] && grep -q 'test is successful' <<<"$conf"; then
    conf_known=1
    # strip comments, then one statement per line (split after { } ;)
    c=$(sed -e 's/#.*$//' -e 's/\([{};]\)/\1\n/g' <<<"$conf")
  fi
  local h2=0 h3=0 upstream=0 resolver=0 varpass=0 subreq=0 mail=0 mailproxy=0 authhttp=0 h2off=0
  if [[ $conf_known -eq 1 ]]; then
    grep -qE '^\s*listen\s[^;]*\bhttp2\b' <<<"$c" && h2=1
    grep -qE '^\s*http2\s+on\s*;' <<<"$c" && h2=1
    grep -qE '^\s*http2\s+off\s*;' <<<"$c" && h2off=1
    grep -qE '^\s*listen\s[^;]*\bquic\b' <<<"$c" && h3=1
    grep -qE '^\s*http3\s+on\s*;' <<<"$c" && h3=1
    grep -qE '^\s*(proxy|fastcgi|grpc|uwsgi|scgi|memcached)_pass\s' <<<"$c" && upstream=1
    grep -qE '^\s*resolver\s' <<<"$c" && resolver=1
    grep -qE '^\s*proxy_pass\s[^;]*\$' <<<"$c" && varpass=1
    grep -qE '^\s*(mirror\s+[^o;]|ssi\s+on\s*;)' <<<"$c" && subreq=1
    grep -qE '^\s*mail\s*\{' <<<"$c" && mail=1
    grep -qE '^\s*proxy\s+on\s*;' <<<"$c" && mailproxy=1
    grep -qE '^\s*auth_http\s' <<<"$c" && authhttp=1
  fi

  log " Build       : http_v2_module=$has_h2mod  http_v3_module=$has_h3mod  mail=$has_mailmod"
  if [[ $conf_known -eq 1 ]]; then
    log " Config      : http2=$h2 http3/quic=$h3 upstream_pass=$upstream resolver=$resolver var_proxy_pass=$varpass mirror/ssi=$subreq mail=$mail(proxy=$mailproxy auth_http=$authhttp)"
    [[ $h2off -eq 1 && $h2 -eq 1 ]] && log " WARNING     : 'http2 off;' present but http2 is still enabled elsewhere (listen ... http2 overrides http2 off)"
  else
    log " Config      : COULD NOT READ (run as root, or nginx -T failed) - exposure unknown"
  fi

  # ---- ALPN probe for live HTTP/2
  local alpn_h2=""
  if [[ $OPT_PROBE -eq 1 && $conf_known -eq 1 && "$label" != docker:* ]] && command -v openssl >/dev/null 2>&1; then
    local targets
    targets=$(grep -E '^\s*listen\s' <<<"$c" | grep -E '\b(ssl|http2)\b|:443\b|\s443\b' \
      | awk '{print $2}' | tr -d ';' | sort -u)
    for t in $targets; do
      local host="127.0.0.1" port
      if [[ "$t" =~ ^\[.*\]:([0-9]+)$ ]]; then port="${BASH_REMATCH[1]}"; host="::1"
      elif [[ "$t" =~ ^([0-9.]+):([0-9]+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; [[ "$host" == "0.0.0.0" ]] && host="127.0.0.1"
      elif [[ "$t" =~ ^\*:([0-9]+)$ ]]; then port="${BASH_REMATCH[1]}"
      elif [[ "$t" =~ ^[0-9]+$ ]]; then port="$t"
      else continue; fi
      local r; r=$(timeout 5 openssl s_client -connect "$host:$port" -alpn h2 </dev/null 2>/dev/null | grep -m1 '^ALPN protocol:')
      if [[ "$r" == *"h2"* ]]; then alpn_h2+="$host:$port "; fi
    done
    [[ -n "$alpn_h2" ]] && { log " ALPN probe  : h2 NEGOTIATED on ${alpn_h2}"; h2=1; } || log " ALPN probe  : no h2 negotiated on local TLS listeners"
  fi

  # ---- Per-CVE verdict
  log ""
  printf -v hdr " %-16s %-22s %s" "CVE" "STATUS" "DETAIL"; log "$hdr"
  local jc=()
  for cve in "${CVES[@]}"; do
    local status detail inrange=0 exposed=0
    if grep -q "^FIX:$cve$" <<<"$bp"; then
      status="PATCHED(backport)"; detail="distro changelog references $cve"
    elif [[ -n "$plus" ]]; then
      inrange=2; status="REVIEW(NGINX Plus)"; detail="verify $plus against F5 advisory"
    elif [[ -z "$ver" ]]; then
      inrange=2; status="REVIEW"; detail="version could not be determined"
    elif ! ver_ge "$ver" "${FIRST[$cve]}"; then
      status="NOT AFFECTED"; detail="older than first affected ${FIRST[$cve]}"
    elif ver_ge "$ver" "$(fixed_for "$ver")"; then
      status="PATCHED"; detail=">= $(fixed_for "$ver")"
    else
      inrange=1; detail="needs >= $(fixed_for "$ver")"
    fi

    if [[ $inrange -ne 0 ]]; then
      case "$cve" in
        CVE-2026-123007) [[ $has_h2mod -eq 1 && $h2 -eq 1 ]] && exposed=1; [[ $has_h2mod -eq 0 && -n "$Vout" ]] && exposed=-1 ;;
        CVE-2026-123633) [[ $has_h2mod -eq 1 && $h2 -eq 1 && $upstream -eq 1 ]] && exposed=1; [[ $has_h2mod -eq 0 && -n "$Vout" ]] && exposed=-1 ;;
        CVE-2026-123634) [[ $resolver -eq 1 && $varpass -eq 1 && $subreq -eq 1 ]] && exposed=1
                         [[ $resolver -eq 1 && $varpass -eq 1 && $subreq -eq 0 ]] && detail+="; resolver+var proxy_pass present (other subrequests may reach bug)" ;;
        CVE-2026-121810) [[ $h3 -eq 1 && $upstream -eq 1 ]] && exposed=1; [[ $has_h3mod -eq 0 && -n "$Vout" ]] && exposed=-1 ;;
        CVE-2026-113425) [[ $mail -eq 1 && $mailproxy -eq 1 && $authhttp -eq 1 ]] && exposed=1; [[ $has_mailmod -eq 0 && -n "$Vout" && $mail -eq 0 ]] && exposed=-1 ;;
      esac
      if [[ $exposed -eq 1 ]]; then status="VULNERABLE"; rank=2
      elif [[ $exposed -eq -1 ]]; then status="IN RANGE-not built"; detail+="; module not compiled in"
      elif [[ $conf_known -eq 0 ]]; then status="IN RANGE-cfg unknown"; [[ $rank -lt 1 ]] && rank=1
      else status="IN RANGE-not exposed"; detail+="; vulnerable feature not enabled in config"; [[ $rank -lt 1 ]] && rank=1
      fi
      [[ $inrange -eq 2 && $exposed -eq 1 ]] && { [[ -n "$plus" ]] && status="VULNERABLE?(Plus)" || status="VULNERABLE?(ver unknown)"; }
    fi
    printf -v line " %-16s %-22s %s" "$cve" "$status" "$detail"; log "$line"
    [[ "$status" == VULNERABLE* ]] && log "                  -> ${DESC[$cve]}"
    jc+=("{\"cve\":\"$cve\",\"status\":\"$(json_esc "$status")\",\"detail\":\"$(json_esc "$detail")\"}")
  done
  [[ -n "$notes" && $rank -lt 1 ]] && rank=1

  local verdict="CLEAN"; [[ $rank -eq 1 ]] && verdict="REVIEW"; [[ $rank -eq 2 ]] && verdict="VULNERABLE"
  log "\n RESULT      : $verdict"
  if [[ $rank -eq 2 ]]; then
    log " ACTION      : Upgrade to nginx $FIX_STABLE/$FIX_MAINLINE (or patched distro pkg). Stopgap for 123007/123633:"
    log "               remove 'http2' from listen lines AND set 'http2 off;' per server, nginx -t, then RESTART (not reload)."
  fi
  [[ $rank -gt $RANK ]] && RANK=$rank
  SUMMARY+=("$verdict | $label | ${ver:-?}${plus:+ $plus}${openresty:+ (openresty $openresty)}")
  JSON_ITEMS+=("{\"target\":\"$(json_esc "$label")\",\"version\":\"${ver:-}\",\"plus\":\"$(json_esc "$plus")\",\"verdict\":\"$verdict\",\"notes\":\"$(json_esc "$notes")\",\"cves\":[$(IFS=,; echo "${jc[*]}")]}")
}

# =============================================================================
# Discover host nginx instances
# =============================================================================
[[ $EUID -ne 0 ]] && log "WARNING: not running as root - nginx -T and /proc checks may be incomplete."

declare -A BINS=()     # realpath -> conf arg (may be empty)
declare -A NOTES=()
declare -A PFX=()      # realpath -> -p prefix (may be empty)

# Running master processes (authoritative: what is actually serving)
while read -r pid args; do
  [[ -z "$pid" ]] && continue
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
  bin=$(awk '{for(i=1;i<=NF;i++) if($i ~ /\/nginx$/ || $i=="nginx"){print $i; exit}}' <<<"${args#nginx: master process }")
  [[ -z "$bin" || "$bin" == "nginx" ]] && bin=${exe% (deleted)}
  [[ -z "$bin" ]] && continue
  confarg=$(grep -oE '\s-c\s+\S+' <<<" $args" | awk '{print $2}')
  pfxarg=$(grep -oE '\s-p\s+\S+' <<<" $args" | awk '{print $2}')   # e.g. GitLab: -p /var/opt/gitlab/nginx
  # Skip container processes (handled via docker exec) - compare mount namespace
  if [[ -r /proc/$pid/ns/mnt && -r /proc/self/ns/mnt && "$(readlink /proc/$pid/ns/mnt)" != "$(readlink /proc/self/ns/mnt)" ]]; then continue; fi
  if [[ "$exe" == *"(deleted)"* ]]; then
    # Package upgraded but nginx never restarted: the OLD binary is still serving.
    # It can still be executed via /proc/PID/exe to read its real version.
    rp="/proc/$pid/exe"
    NOTES["$rp"]="Master PID $pid is running a binary DELETED on disk (${exe% (deleted)}) - upgraded but NOT restarted. Version below is the code actually serving traffic. RESTART nginx."
  else
    rp=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
  fi
  BINS["$rp"]="$confarg"; PFX["$rp"]="$pfxarg"
done < <(ps -eo pid=,args= 2>/dev/null | grep -E 'nginx: master process' | grep -v grep)

# Binaries on disk
for b in "$(command -v nginx 2>/dev/null)" /usr/sbin/nginx /usr/bin/nginx /usr/local/sbin/nginx /usr/local/bin/nginx \
         /usr/local/nginx/sbin/nginx /opt/nginx/sbin/nginx /opt/*/sbin/nginx /opt/*/nginx/sbin/nginx /opt/*/embedded/sbin/nginx /usr/local/openresty/nginx/sbin/nginx; do
  [[ -n "$b" && -x "$b" && -f "$b" ]] || continue
  rp=$(readlink -f "$b")
  [[ -n "${BINS[$rp]+x}" ]] || BINS["$rp"]=""
  # GitLab Omnibus nginx only parses its config with its own prefix
  [[ "$rp" == /opt/gitlab/embedded/* && -z "${PFX[$rp]:-}" && -d /var/opt/gitlab/nginx ]] && PFX["$rp"]=/var/opt/gitlab/nginx
done

for rp in "${!BINS[@]}"; do
  [[ -x "$rp" ]] || { analyze "host:$rp" "" "" "" "PKG:unknown" "${NOTES[$rp]:-binary not executable/present}"; continue; }
  vout=$("$rp" -v 2>&1); Vout=$("$rp" -V 2>&1)
  targs=(-T); [[ -n "${PFX[$rp]:-}" ]] && targs+=(-p "${PFX[$rp]}"); [[ -n "${BINS[$rp]}" ]] && targs+=(-c "${BINS[$rp]}")
  conf=$("$rp" "${targs[@]}" 2>&1)
  grep -q 'test is successful' <<<"$conf" || conf=""
  bp=$(backport_hits "$rp")
  label="host:$rp"; [[ -n "${PFX[$rp]:-}" ]] && label+=" (-p ${PFX[$rp]})"; [[ -n "${BINS[$rp]}" ]] && label+=" (-c ${BINS[$rp]})"
  analyze "$label" "$vout" "$Vout" "$conf" "$bp" "${NOTES[$rp]:-}"
done

# =============================================================================
# Docker containers
# =============================================================================
if [[ $OPT_DOCKER -eq 1 ]] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  while read -r cid cname cimage; do
    [[ -z "$cid" ]] && continue
    vout=$(docker exec "$cid" sh -c 'nginx -v 2>&1' 2>/dev/null) || continue
    grep -q 'nginx' <<<"$vout" || continue
    Vout=$(docker exec "$cid" sh -c 'nginx -V 2>&1' 2>/dev/null)
    conf=$(docker exec "$cid" sh -c 'nginx -T 2>&1' 2>/dev/null)
    grep -q 'test is successful' <<<"$conf" || conf=""
    bp="PKG:image $cimage"
    cl=$(docker exec "$cid" sh -c 'for f in /usr/share/doc/nginx*/changelog.Debian.gz; do [ -f "$f" ] && zcat "$f"; done; rpm -q --changelog nginx 2>/dev/null' 2>/dev/null)
    for c in "${CVES[@]}"; do grep -q "$c" <<<"$cl" && bp+=$'\n'"FIX:$c"; done
    analyze "docker:$cname ($cimage)" "$vout" "$Vout" "$conf" "$bp" ""
  done < <(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null)
fi

# Kubernetes ingress-nginx hint (cannot be fixed by upgrade - project EOL)
if command -v kubectl >/dev/null 2>&1; then
  ing=$(kubectl get pods -A -l app.kubernetes.io/name=ingress-nginx --no-headers 2>/dev/null | wc -l)
  [[ "$ing" -gt 0 ]] && { log "\nNOTE: $ing ingress-nginx pod(s) found. Community ingress-nginx is unmaintained and will not get this fix."
                          log "      Stopgap: set use-http2: \"false\" in the controller ConfigMap; plan migration."; [[ $RANK -lt 1 ]] && RANK=1
                          SUMMARY+=("REVIEW | kubernetes ingress-nginx ($ing pods) | unmaintained"); }
fi

# =============================================================================
# Summary / output
# =============================================================================
HOST=$(hostname 2>/dev/null)
OVERALL="CLEAN"; EXITC=0
[[ ${#SUMMARY[@]} -eq 0 ]] && OVERALL="NO NGINX FOUND"
[[ $RANK -eq 1 ]] && { OVERALL="REVIEW"; EXITC=2; }
[[ $RANK -eq 2 ]] && { OVERALL="VULNERABLE"; EXITC=1; }

if [[ $OPT_JSON -eq 1 ]]; then
  echo "{\"host\":\"$(json_esc "$HOST")\",\"scanned\":\"$(date -u +%FT%TZ)\",\"overall\":\"$OVERALL\",\"instances\":[$(IFS=,; echo "${JSON_ITEMS[*]}")]}"
else
  echo -e "\n######## nginx2root SUMMARY - $HOST - $(date '+%F %T') ########"
  [[ ${#SUMMARY[@]} -eq 0 ]] && echo " No nginx binaries, processes, or containers found."
  for s in "${SUMMARY[@]}"; do echo " $s"; done
  echo " OVERALL: $OVERALL"
fi

# NinjaOne custom field (Linux agent CLI) - only when the agent is installed
NCLI=/opt/NinjaRMMAgent/programdata/ninjarmm-cli
if [[ -x "$NCLI" && -n "$NINJA_FIELD" && "$NINJA_FIELD" != "none" ]]; then
  val="$OVERALL | $(date '+%F %T') | $(IFS=';'; echo "${SUMMARY[*]}")"
  if "$NCLI" set "$NINJA_FIELD" "${val:0:1000}" >/dev/null 2>&1; then
    [[ $OPT_JSON -eq 1 ]] || echo "Wrote result to custom field '$NINJA_FIELD'."
  else echo "WARNING: could not write custom field '$NINJA_FIELD'" >&2; fi
fi

exit $EXITC

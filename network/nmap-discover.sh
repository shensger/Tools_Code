#!/usr/bin/env bash
# =============================================================================
# nmap-discover.sh — phased network discovery ("find everything")
#
#   Phase 1  Host discovery     ICMP echo/timestamp + TCP SYN/ACK + UDP probes
#   Phase 2  TCP port sweep     all 65535 ports on every live host
#   Phase 3  Service/OS detect  -sV -sC -O against only the open ports found
#   Phase 4  UDP (optional)     top N UDP ports (DNS, SNMP, NTP, NetBIOS, ...)
#   Phase 5  Reports            CSV of host/port/service + HTML from nmap XML
#
# Only scan networks you are authorized to scan.
#
# Usage:
#   sudo ./nmap-discover.sh -t "10.10.0.0/24 10.10.7.0/24"
#   sudo ./nmap-discover.sh -f targets.txt -u -r 2000 -x 10.10.0.1
#
# Options:
#   -t "targets"   Space-separated targets (CIDR, ranges, hosts)
#   -f file        File of targets, one per line (# comments OK)
#   -x "excludes"  Comma-separated hosts/CIDRs to skip (e.g. firewalls, prod DBs)
#   -o dir         Output directory (default: ./nmap-YYYYmmdd-HHMMSS)
#   -r rate        --min-rate packets/sec for port sweep (default: 1000)
#   -u             Include UDP scan (slow)
#   -n num         Number of top UDP ports (default: 100)
#   -T time        Per-host timeout for phases 3-4 (default: 30m)
#   -P             Skip host discovery; treat every target as up (-Pn).
#                  Use when hosts block ping/probes — much slower on big ranges.
#   -h             Help
# =============================================================================
set -euo pipefail

TARGETS=""; TARGET_FILE=""; EXCLUDES=""; OUTDIR=""
RATE=1000; DO_UDP=0; UDP_TOP=100; SKIP_DISCOVERY=0; HOST_TIMEOUT=30m

usage() { sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":t:f:x:o:r:n:T:uPh" opt; do
  case $opt in
    t) TARGETS="$OPTARG" ;;
    f) TARGET_FILE="$OPTARG" ;;
    x) EXCLUDES="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    r) RATE="$OPTARG" ;;
    u) DO_UDP=1 ;;
    n) UDP_TOP="$OPTARG" ;;
    T) HOST_TIMEOUT="$OPTARG" ;;
    P) SKIP_DISCOVERY=1 ;;
    h) usage 0 ;;
    *) echo "Unknown option: -$OPTARG" >&2; usage 1 ;;
  esac
done

command -v nmap >/dev/null || { echo "nmap not found in PATH" >&2; exit 1; }
[[ -z "$TARGETS" && -z "$TARGET_FILE" ]] && { echo "Need -t or -f" >&2; usage 1; }
[[ -n "$TARGET_FILE" && ! -r "$TARGET_FILE" ]] && { echo "Can't read $TARGET_FILE" >&2; exit 1; }

OUTDIR="${OUTDIR:-./nmap-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/run.log"

# Root gets SYN scan + OS detection; non-root falls back to connect scan.
if [[ $EUID -eq 0 ]]; then
  TCP_SCAN="-sS"; OS_OPTS="-O --osscan-guess"
else
  echo "[!] Not root: using -sT, no OS detection, no UDP." | tee -a "$LOG"
  TCP_SCAN="-sT"; OS_OPTS=""; DO_UDP=0
fi

# Build target args
TARGET_ARGS=()
[[ -n "$TARGETS" ]] && read -r -a TARGET_ARGS <<< "$TARGETS"
if [[ -n "$TARGET_FILE" ]]; then
  CLEAN_TARGETS="$OUTDIR/targets.clean.txt"
  grep -vE '^\s*(#|$)' "$TARGET_FILE" > "$CLEAN_TARGETS"
  TARGET_ARGS+=(-iL "$CLEAN_TARGETS")
fi
EXCLUDE_ARGS=()
[[ -n "$EXCLUDES" ]] && EXCLUDE_ARGS=(--exclude "$EXCLUDES")

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

LIVE="$OUTDIR/live-hosts.txt"

# ---------------------------------------------------------------- Phase 1
if [[ $SKIP_DISCOVERY -eq 1 ]]; then
  log "Phase 1 skipped (-P): listing all targets as live"
  nmap -sL -n "${TARGET_ARGS[@]}" "${EXCLUDE_ARGS[@]}" -oG - \
    | awk '/^Host:/{print $2}' | sort -uV > "$LIVE"
else
  log "Phase 1: host discovery"
  DISC_PROBES=(-PE -PP -PS21,22,23,25,53,80,88,110,135,139,143,389,443,445,636,993,1433,3306,3389,5900,5985,8080,8443
               -PA80,443,3389 -PU53,123,137,161)
  [[ $EUID -ne 0 ]] && DISC_PROBES=()   # unprivileged: let nmap use its connect-based default
  nmap -sn "${DISC_PROBES[@]}" -R --reason \
       "${TARGET_ARGS[@]}" "${EXCLUDE_ARGS[@]}" \
       -oA "$OUTDIR/1-discovery" >>"$LOG" 2>&1
  awk '/Status: Up/{print $2}' "$OUTDIR/1-discovery.gnmap" | sort -uV > "$LIVE"
fi

LIVE_COUNT=$(wc -l < "$LIVE" | tr -d ' ')
log "Live hosts: $LIVE_COUNT  ->  $LIVE"
[[ "$LIVE_COUNT" -eq 0 ]] && { log "Nothing up. Try -P if hosts drop probes."; exit 0; }

# ---------------------------------------------------------------- Phase 2
log "Phase 2: full TCP port sweep ($TCP_SCAN -p- --min-rate $RATE)"
nmap -Pn $TCP_SCAN -p- --min-rate "$RATE" -T4 --max-retries 2 --open \
     -iL "$LIVE" "${EXCLUDE_ARGS[@]}" \
     -oA "$OUTDIR/2-tcp-ports" >>"$LOG" 2>&1

# Union of every open TCP port across all hosts
TCP_PORTS=$(grep -oE '[0-9]+/open/tcp' "$OUTDIR/2-tcp-ports.gnmap" \
            | cut -d/ -f1 | sort -un | paste -sd, - || true)
# Hosts with at least one open port
grep -E 'Ports: .*open' "$OUTDIR/2-tcp-ports.gnmap" | awk '{print $2}' \
  | sort -uV > "$OUTDIR/hosts-with-tcp.txt" || true
log "Open TCP ports found: ${TCP_PORTS:-none}"

# ---------------------------------------------------------------- Phase 3
if [[ -n "$TCP_PORTS" ]]; then
  log "Phase 3: service/version/OS detection + default scripts"
  nmap -Pn $TCP_SCAN -sV -sC $OS_OPTS --traceroute \
       -p "$TCP_PORTS" --open -T4 \
       --host-timeout "$HOST_TIMEOUT" --script-timeout 2m \
       -iL "$OUTDIR/hosts-with-tcp.txt" "${EXCLUDE_ARGS[@]}" \
       -oA "$OUTDIR/3-tcp-services" >>"$LOG" 2>&1
else
  log "Phase 3 skipped: no open TCP ports"
fi

# ---------------------------------------------------------------- Phase 4
if [[ $DO_UDP -eq 1 ]]; then
  log "Phase 4: UDP top $UDP_TOP ports"
  nmap -Pn -sU --top-ports "$UDP_TOP" -sV --version-intensity 0 \
       --max-retries 1 -T4 --open --host-timeout "$HOST_TIMEOUT" \
       -iL "$LIVE" "${EXCLUDE_ARGS[@]}" \
       -oA "$OUTDIR/4-udp" >>"$LOG" 2>&1
fi

# ---------------------------------------------------------------- Phase 5
log "Phase 5: building reports"

# HTML via nmap's bundled stylesheet (if xsltproc is installed)
if command -v xsltproc >/dev/null; then
  for x in "$OUTDIR"/3-tcp-services.xml "$OUTDIR"/4-udp.xml; do
    [[ -f "$x" ]] && xsltproc "$x" -o "${x%.xml}.html" 2>>"$LOG" || true
  done
fi

# CSV inventory: ip, hostname, mac, vendor, os, proto, port, state, service, product, version, extra
if command -v python3 >/dev/null; then
python3 - "$OUTDIR" <<'PY'
import csv, os, sys, xml.etree.ElementTree as ET
out = sys.argv[1]
J = lambda n: os.path.join(out, n)
hosts = {}   # ip -> {"meta": [hostname, mac, vendor, os], "ports": {(proto, port): [state, svc, product, version, extra]}}

def load(fname, detailed):
    if not os.path.exists(fname): return
    try: root = ET.parse(fname).getroot()
    except ET.ParseError: return
    for h in root.findall("host"):
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"): ip = a.get("addr")
            elif a.get("addrtype") == "mac": mac, vendor = a.get("addr"), a.get("vendor", "")
        e = hosts.setdefault(ip, {"meta": ["", "", "", ""], "ports": {}})
        hn = h.find("hostnames/hostname"); om = h.find("os/osmatch")
        for i, v in enumerate([hn.get("name") if hn is not None else "", mac, vendor,
                               f'{om.get("name")} ({om.get("accuracy")}%)' if om is not None else ""]):
            if v: e["meta"][i] = v
        for p in h.findall("ports/port"):
            st = p.find("state"); sv = p.find("service")
            g = lambda k: sv.get(k, "") if sv is not None else ""
            row = [st.get("state") if st is not None else "", g("name"),
                   g("product") if detailed else "", g("version") if detailed else "", g("extrainfo") if detailed else ""]
            e["ports"][(p.get("protocol"), p.get("portid"))] = row   # later (detailed) files overwrite baseline

load(J("2-tcp-ports.xml"), False)     # baseline: every open port found
load(J("3-tcp-services.xml"), True)   # overlay: versions/OS where detection finished
load(J("4-udp.xml"), True)
if os.path.exists(J("live-hosts.txt")):
    for ip in open(J("live-hosts.txt")).read().split():
        hosts.setdefault(ip, {"meta": ["", "", "", ""], "ports": {}})

def ipkey(ip):
    try: return tuple(int(x) for x in ip.split("."))
    except ValueError: return (999, ip)
rows = []
for ip in sorted(hosts, key=ipkey):
    e = hosts[ip]
    if not e["ports"]:
        rows.append([ip, *e["meta"], "", "", "no open ports found", "", "", "", ""]); continue
    for (proto, port) in sorted(e["ports"], key=lambda k: (k[0], int(k[1]))):
        rows.append([ip, *e["meta"], proto, port, *e["ports"][(proto, port)]])
with open(J("inventory.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["ip","hostname","mac","vendor","os_guess","proto","port","state","service","product","version","extra"])
    w.writerows(rows)
print(f"inventory.csv: {len(hosts)} hosts, {len(rows)} rows")
PY
fi | tee -a "$LOG"

log "Done. Results in $OUTDIR"
ls -1 "$OUTDIR" | sed 's/^/    /' | tee -a "$LOG"

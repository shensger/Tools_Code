#!/usr/bin/env bash
# =============================================================================
# vuln-assess.sh — non-destructive vulnerability assessment (phase after discovery)
#
# Pairs with nmap-discover.sh. Takes targets (or reuses a discovery
# inventory.csv) and runs SAFE, non-intrusive checks against the open ports:
#   - nmap NSE "vuln" + "safe" categories, plus service-specific scripts
#   - TLS assessment on HTTPS/SSL ports (testssl.sh if present, else nmap ssl-*)
#   - version -> known-CVE notes for detected service versions
#   - findings.csv + findings.html + per-host nmap output
#
# This does NOT exploit, brute-force, or DoS. It identifies and reports.
# Only run against hosts you own or are explicitly authorized to test.
#
# Usage:
#   ./vuln-assess.sh -t 66.160.197.230
#   ./vuln-assess.sh -i ./nmap-20261028-110918/inventory.csv
#   ./vuln-assess.sh -t host -p 22,53,80,443 -o assess-out
#
# Options:
#   -t "targets"   Space-separated hosts (CIDR/range/host)
#   -i inventory   Reuse a discovery inventory.csv (hosts + open ports from it)
#   -f file        File of targets, one per line
#   -p ports       Explicit port list (default: discover/reuse, else top-1000)
#   -o dir         Output dir (default: ./assess-YYYYmmdd-HHMMSS)
#   -T time        Per-host timeout (default: 30m)
#   -s             Safe only: drop the nmap "vuln" category (safe category only)
#   -h             Help
# =============================================================================
set -euo pipefail

TARGETS=""; INVENTORY=""; TARGET_FILE=""; PORTS=""; OUTDIR=""
HOST_TIMEOUT=30m; SAFE_ONLY=0

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":t:i:f:p:o:T:sh" opt; do
  case $opt in
    t) TARGETS="$OPTARG" ;;
    i) INVENTORY="$OPTARG" ;;
    f) TARGET_FILE="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    T) HOST_TIMEOUT="$OPTARG" ;;
    s) SAFE_ONLY=1 ;;
    h) usage 0 ;;
    *) echo "Unknown option: -$OPTARG" >&2; usage 1 ;;
  esac
done

command -v nmap >/dev/null || { echo "nmap not found in PATH" >&2; exit 1; }
[[ -z "$TARGETS" && -z "$INVENTORY" && -z "$TARGET_FILE" ]] && { echo "Need -t, -i, or -f" >&2; usage 1; }

OUTDIR="${OUTDIR:-./assess-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/run.log"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

[[ $EUID -ne 0 ]] && log "[!] Not root: using -sT connect scan (fine for assessment; slightly slower)."
SCAN=$([[ $EUID -eq 0 ]] && echo "-sS" || echo "-sT")

# ---- Build target list + per-host ports -------------------------------------
# TARGETS_FILE: one host per line. If an inventory is given, we also learn each
# host's open ports so we only re-probe what's already known to be open.
TARGETS_FILE="$OUTDIR/targets.txt"
: > "$TARGETS_FILE"
declare -A HOST_PORTS=()

if [[ -n "$INVENTORY" ]]; then
  [[ -r "$INVENTORY" ]] || { echo "Can't read $INVENTORY" >&2; exit 1; }
  # CSV columns: ip,hostname,mac,vendor,os_guess,proto,port,state,...
  while IFS=, read -r ip _ _ _ _ proto port state _; do
    [[ "$ip" == "ip" || -z "$ip" ]] && continue
    grep -qxF "$ip" "$TARGETS_FILE" || echo "$ip" >> "$TARGETS_FILE"
    [[ "$proto" == "tcp" && "$state" == "open" && -n "$port" ]] && \
      HOST_PORTS["$ip"]="${HOST_PORTS[$ip]:+${HOST_PORTS[$ip]},}$port"
  done < "$INVENTORY"
fi
[[ -n "$TARGETS" ]] && for h in $TARGETS; do grep -qxF "$h" "$TARGETS_FILE" || echo "$h" >> "$TARGETS_FILE"; done
if [[ -n "$TARGET_FILE" ]]; then
  [[ -r "$TARGET_FILE" ]] || { echo "Can't read $TARGET_FILE" >&2; exit 1; }
  grep -vE '^\s*(#|$)' "$TARGET_FILE" >> "$TARGETS_FILE"
fi
sort -uV "$TARGETS_FILE" -o "$TARGETS_FILE"
log "Targets: $(wc -l < "$TARGETS_FILE" | tr -d ' ')  ->  $TARGETS_FILE"

# NSE selection. "vuln" probes for known flaws without weaponizing them.
# brute/dos/exploit categories are deliberately excluded.
if [[ $SAFE_ONLY -eq 1 ]]; then NSE="safe"; else NSE="vuln or safe"; fi
# Service-specific safe scripts worth adding regardless of category:
SVC_SCRIPTS="ssh2-enum-algos,ssh-auth-methods,dns-nsid,dns-recursion,\
http-methods,http-security-headers,http-title,http-headers,http-enum,\
ssl-cert,ssl-enum-ciphers,ssl-dh-params"

# ---- Per-host assessment ----------------------------------------------------
while read -r host; do
  [[ -z "$host" ]] && continue
  safe=$(echo "$host" | tr '/:' '__')
  pflag=""
  if [[ -n "$PORTS" ]]; then pflag="-p $PORTS"
  elif [[ -n "${HOST_PORTS[$host]:-}" ]]; then pflag="-p ${HOST_PORTS[$host]}"
  fi
  log "Assessing $host ${pflag:-(top 1000 ports)}"
  # shellcheck disable=SC2086
  nmap -Pn $SCAN -sV $pflag --open -T4 \
       --script "($NSE) or ($SVC_SCRIPTS)" \
       --script-args "http.useragent=assessment" \
       --host-timeout "$HOST_TIMEOUT" --script-timeout 3m \
       -oA "$OUTDIR/host-$safe" "$host" >>"$LOG" 2>&1 || log "  (nmap returned non-zero for $host; partial results kept)"

  # TLS deep-dive with testssl.sh if available, for any ssl/https port found
  if command -v testssl.sh >/dev/null 2>&1; then
    for sslport in $(grep -oE '[0-9]+/open/tcp//(ssl|https)' "$OUTDIR/host-$safe.gnmap" 2>/dev/null | cut -d/ -f1 | sort -un); do
      log "  testssl.sh $host:$sslport"
      testssl.sh --quiet --color 0 --severity LOW "$host:$sslport" \
        > "$OUTDIR/testssl-$safe-$sslport.txt" 2>>"$LOG" || true
    done
  fi
done < "$TARGETS_FILE"

# ---- CVE/version notes + findings rollup ------------------------------------
log "Building findings report"
if command -v python3 >/dev/null; then
python3 -I - "$OUTDIR" <<'PY' 2>&1 | tee -a "$LOG"
import csv, glob, os, re, sys, xml.etree.ElementTree as ET
out = sys.argv[1]

# Known-vulnerable version intelligence. Keyed by (product_substr, version_regex).
# Each entry: list of (CVE/label, severity, note). Non-exhaustive, extend freely.
INTEL = [
    ("dnsmasq", r"^2\.(?:[0-9]|1[0-9]|2[0-9]|3[0-9]|40)$|^2\.8[0-2]$",
        [("DNSpooq (CVE-2020-25681..25687)", "HIGH",
          "dnsmasq < 2.83 vulnerable to cache poisoning + heap overflow. 2.83 fixes most; confirm >= 2.83 and that it isn't an openly recursive resolver.")],),
    ("dnsmasq", r"^2\.83$",
        [("DNSpooq-adjacent hardening", "INFO",
          "2.83 is the DNSpooq fix release. Verify recursion is restricted to trusted clients (dns-recursion result) so it can't be used in amplification.")],),
    ("OpenSSH", r"^[0-6]\.|^7\.[0-6]($|[^0-9])",
        [("OpenSSH <= 7.6 age", "MEDIUM",
          "OpenSSH 7.4 is old (CentOS/RHEL 7 era). Review for CVE-2018-15473 (username enumeration) and dated cipher/MAC support; prefer key-only auth.")],),
    ("openresty", r".*",
        [("OpenResty = nginx+LuaJIT", "INFO",
          "Version hidden by server header. Map the bundled nginx core version to nginx CVEs; ensure it's a current OpenResty release.")],),
]

def intel_for(product, version):
    hits = []
    for prod, vre, items in INTEL:
        if prod.lower() in (product or "").lower() and re.search(vre, version or ""):
            hits.extend(items)
    return hits

rows = []  # host, port, service, product, version, source, severity, finding
for xf in sorted(glob.glob(os.path.join(out, "host-*.xml"))):
    try: root = ET.parse(xf).getroot()
    except ET.ParseError: continue
    for h in root.findall("host"):
        a = h.find("address"); ip = a.get("addr") if a is not None else ""
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open": continue
            port = p.get("portid"); sv = p.find("service")
            g = lambda k: (sv.get(k, "") if sv is not None else "")
            svc, prod, ver = g("name"), g("product"), g("version")
            # NSE script findings
            for s in p.findall("script"):
                sid = s.get("id", ""); outp = (s.get("output","") or "").strip().replace("\n"," ")
                low = outp.lower()
                if sid.startswith(("ssh","dns","http","ssl")) or "vuln" in sid or \
                   any(w in low for w in ("vulnerable","cve-","weak","expired","deprecated","sslv","tlsv1.0","tlsv1.1")):
                    sev = "HIGH" if ("vulnerable" in low or "cve-" in low) else "INFO"
                    rows.append([ip, port, svc, prod, ver, f"nse:{sid}", sev, outp[:300]])
            # version-based intel
            for label, sev, note in intel_for(prod, ver):
                rows.append([ip, port, svc, prod, ver, "version-intel", sev, f"{label} — {note}"])

seen = set(); rows = [r for r in rows if not (tuple(r) in seen or seen.add(tuple(r)))]
order = {"HIGH":0,"MEDIUM":1,"LOW":2,"INFO":3}
rows.sort(key=lambda r: (order.get(r[6],9), r[0], int(r[1]) if r[1].isdigit() else 0))

with open(os.path.join(out,"findings.csv"),"w",newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["host","port","service","product","version","source","severity","finding"])
    w.writerows(rows)

# Simple self-contained HTML
sev_color = {"HIGH":"#c0392b","MEDIUM":"#d68910","LOW":"#2874a6","INFO":"#566573"}
html = ["<!doctype html><meta charset=utf-8><title>Vulnerability Assessment</title>",
        "<style>body{font:14px system-ui;margin:2rem;color:#1a1a1a}",
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}",
        "th{background:#f4f4f4}td.sev{font-weight:700;color:#fff}tr:nth-child(even){background:#fafafa}</style>",
        f"<h1>Vulnerability Assessment</h1><p>{len(rows)} findings across {len(set(r[0] for r in rows))} host(s). "
        "Non-destructive assessment — validate each finding before remediation.</p>",
        "<table><tr><th>Sev</th><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Source</th><th>Finding</th></tr>"]
for r in rows:
    c = sev_color.get(r[6],"#566573")
    ver = f"{r[3]} {r[4]}".strip()
    html.append(f"<tr><td class=sev style='background:{c}'>{r[6]}</td><td>{r[0]}</td><td>{r[1]}</td>"
                f"<td>{r[2]}</td><td>{ver}</td><td>{r[5]}</td><td>{r[7]}</td></tr>")
html.append("</table>")
open(os.path.join(out,"findings.html"),"w").write("".join(html))
print(f"findings.csv / findings.html: {len(rows)} findings")
PY
fi

log "Done. Results in $OUTDIR"
ls -1 "$OUTDIR" | sed 's/^/    /' | tee -a "$LOG"

#!/usr/bin/env bash
# rstor-egress-watch.sh
# Run on a Linux NAT box to find which INTERNAL hosts are connecting to RStor
# (s3.yellowbrick.rstorcloud.io) and how much they upload.
#
# Usage (as root):
#   ./rstor-egress-watch.sh snapshot          # who is connected right now
#   ./rstor-egress-watch.sh watch             # log every new/closed connection until Ctrl-C (or DURATION)
#   ./rstor-egress-watch.sh sni               # sniff TLS SNI - catches bucket-style hostnames (cbb-backup.s3...)
#   ./rstor-egress-watch.sh logrule           # print iptables/nft rules for persistent kernel logging
#
# Env overrides: HOST, BUCKET, LOG, DURATION (sec, 0=forever), IFACE (default any)
# Needs: conntrack (conntrack-tools); tshark or tcpdump for "sni".
# Byte counts need conntrack accounting:  sysctl -w net.netfilter.nf_conntrack_acct=1

set -uo pipefail

HOST="${HOST:-s3.yellowbrick.rstorcloud.io}"
BUCKET="${BUCKET:-cbb-backup}"
LOG="${LOG:-/var/log/rstor-egress.log}"
DURATION="${DURATION:-0}"
IFACE="${IFACE:-any}"
MODE="${1:-snapshot}"

die() { echo "ERROR: $*" >&2; exit 1; }
ts()  { date '+%F %T'; }

[[ $EUID -eq 0 ]] || die "run as root"

resolve_ips() {
    # Resolve the endpoint and the virtual-hosted bucket name; RStor may front with several IPs.
    { getent ahostsv4 "$HOST"; getent ahostsv4 "$BUCKET.$HOST"; } 2>/dev/null \
        | awk '{print $1}' | sort -u
}

mapfile -t IPS < <(resolve_ips)
[[ ${#IPS[@]} -gt 0 ]] || die "could not resolve $HOST - check DNS on this box"
IP_RE="$(IFS='|'; echo "${IPS[*]//./\\.}")"

echo "[$(ts)] Endpoint $HOST resolves to: ${IPS[*]}"
if [[ "$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null)" != "1" ]]; then
    echo "[$(ts)] NOTE: conntrack accounting is off - no byte counts. Enable: sysctl -w net.netfilter.nf_conntrack_acct=1"
fi

# Parse a conntrack line -> "proto src sport dst dport state bytes_up bytes_down"
# First src/dst/sport/dport/bytes = original (inside->out) direction; second bytes = reply.
parse_ct='
{
  state="-"; osrc=""; odst=""; osp=""; odp=""; up="-"; down="-"; nb=0
  for (i=1;i<=NF;i++) {
    if ($i ~ /^(ESTABLISHED|SYN_SENT|SYN_RECV|FIN_WAIT|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSE)$/) state=$i
    if ($i ~ /^src=/   && osrc=="") { osrc=substr($i,5) }
    else if ($i ~ /^dst=/   && odst=="") { odst=substr($i,5) }
    else if ($i ~ /^sport=/ && osp=="")  { osp=substr($i,7) }
    else if ($i ~ /^dport=/ && odp=="")  { odp=substr($i,7) }
    if ($i ~ /^bytes=/) { nb++; if (nb==1) up=substr($i,7); else if (nb==2) down=substr($i,7) }
  }
  print osrc, osp, odst, odp, state, up, down
}'

case "$MODE" in

snapshot)
    command -v conntrack >/dev/null || die "install conntrack-tools (apt install conntrack / dnf install conntrack-tools)"
    printf "\n%-16s %-6s %-16s %-5s %-12s %14s %14s\n" SRC SPORT DST DPORT STATE BYTES_UP BYTES_DOWN
    for ip in "${IPS[@]}"; do
        conntrack -L -p tcp -d "$ip" 2>/dev/null | awk "$parse_ct" \
          | while read -r s sp d dp st up dn; do
                printf "%-16s %-6s %-16s %-5s %-12s %14s %14s\n" "$s" "$sp" "$d" "$dp" "$st" "$up" "$dn"
            done
    done
    echo
    echo "Hosts with connections now (count):"
    for ip in "${IPS[@]}"; do conntrack -L -p tcp -d "$ip" 2>/dev/null; done \
        | awk "$parse_ct" | awk '{print $1}' | sort | uniq -c | sort -rn
    ;;

watch)
    command -v conntrack >/dev/null || die "install conntrack-tools"
    echo "[$(ts)] Watching NEW/DESTROY to RStor; logging to $LOG (Ctrl-C to stop)"
    declare -A FIRST LAST CONNS UP
    summary() {
        echo
        echo "===== Summary $(ts) ====="
        printf "%-16s %-20s %-20s %6s %16s\n" SRC FIRST_SEEN LAST_SEEN CONNS MAX_BYTES_UP
        for s in "${!CONNS[@]}"; do
            printf "%-16s %-20s %-20s %6s %16s\n" "$s" "${FIRST[$s]}" "${LAST[$s]}" "${CONNS[$s]}" "${UP[$s]:--}"
        done | sort -k7 -rn
        exit 0
    }
    trap summary INT TERM
    [[ "$DURATION" -gt 0 ]] && { sleep "$DURATION"; kill -INT $$; } &

    while read -r line; do
        grep -qE "dst=($IP_RE) " <<<"$line" || continue
        evt=$(awk '{gsub(/[\[\]]/,"",$1); print $1}' <<<"$line")
        read -r s sp d dp st up dn < <(awk "$parse_ct" <<<"$line")
        now=$(ts)
        echo "$now $evt src=$s:$sp dst=$d:$dp state=$st up=$up down=$dn" | tee -a "$LOG"
        [[ -z "${FIRST[$s]:-}" ]] && FIRST[$s]=$now
        LAST[$s]=$now
        [[ "$evt" == NEW ]] && CONNS[$s]=$(( ${CONNS[$s]:-0} + 1 ))
        [[ -z "${CONNS[$s]:-}" ]] && CONNS[$s]=0
        if [[ "$up" =~ ^[0-9]+$ ]] && (( up > ${UP[$s]:-0} )); then UP[$s]=$up; fi
    done < <(conntrack -E -e NEW,DESTROY -p tcp 2>/dev/null)
    summary
    ;;

sni)
    # Only works when the client uses virtual-hosted style (BUCKET.HOST). Path-style
    # (HOST/BUCKET/...) hides the bucket name inside TLS - you'll only see HOST.
    echo "[$(ts)] Sniffing TLS SNI for *rstorcloud* on $IFACE; logging to $LOG (Ctrl-C to stop)"
    TO=(); [[ "$DURATION" -gt 0 ]] && TO=(timeout "$DURATION")
    if command -v tshark >/dev/null; then
        "${TO[@]}" tshark -i "$IFACE" -l -n -f "tcp port 443" \
          -Y 'tls.handshake.extensions_server_name contains "rstorcloud"' \
          -T fields -E separator=' ' -e frame.time -e ip.src -e tcp.srcport \
          -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null | tee -a "$LOG"
    elif command -v tcpdump >/dev/null; then
        # ClientHello filter: TLS handshake record (0x16), print header line + SNI hit
        "${TO[@]}" tcpdump -i "$IFACE" -nn -l -A \
          'tcp dst port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16)' 2>/dev/null \
          | awk -v b="$BUCKET" '
              /^[0-9]{2}:[0-9]{2}:[0-9]{2}/ { hdr=$0; next }
              /rstorcloud/ { m=match($0,/[A-Za-z0-9.-]*rstorcloud\.io/);
                             host=substr($0,RSTART,RLENGTH);
                             flag=(index(host,b)?"  <== BUCKET":"");
                             print hdr " SNI=" host flag; fflush() }' \
          | tee -a "$LOG"
    else
        die "need tshark or tcpdump"
    fi
    ;;

logrule)
    # Prints (does not apply) rules to log every new connection persistently to the kernel log.
    echo "# iptables (legacy/nft-backed) - apply manually:"
    for ip in "${IPS[@]}"; do
        echo "iptables -I FORWARD -p tcp -d $ip --dport 443 -m conntrack --ctstate NEW -j LOG --log-prefix \"RSTOR-EGRESS \" --log-level 4"
    done
    echo
    echo "# nftables equivalent (adjust table/chain names to yours):"
    echo "nft insert rule inet filter forward ip daddr { $(IFS=,; echo "${IPS[*]}") } tcp dport 443 ct state new log prefix \"RSTOR-EGRESS \""
    echo
    echo "# Then read with:  journalctl -k -g RSTOR-EGRESS   or   grep RSTOR-EGRESS /var/log/kern.log"
    echo "# Remove later with the same rule using -D (iptables) or 'nft delete rule ... handle N'."
    ;;

*)
    die "unknown mode '$MODE' (snapshot | watch | sni | logrule)"
    ;;
esac

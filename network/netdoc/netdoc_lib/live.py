"""Parsers for live operational output (Junos + FortiOS) and session-log splitting."""
import re

IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*"
BGP_STATES = {"Active", "Connect", "Idle", "OpenSent", "OpenConfirm", "Establ", "Established"}

# `user@host> show ...`  (Junos)   or   `HOST # get ...` / `HOST (vdom) $ show` (FortiOS)
PROMPT_JUNOS = re.compile(r"^(?:\{[^}]*\}\s*)?[\w.\-]+@([\w.\-]+)>\s*(.*)$")
PROMPT_FGT = re.compile(r"^([\w.\-]+)(?: \([^)]*\))? [#$] (.*)$")


def split_session(text):
    """Split a captured CLI session into (host, command, body) chunks. Returns [] if no prompts."""
    chunks, cur = [], None
    for line in text.splitlines():
        m = PROMPT_JUNOS.match(line) or PROMPT_FGT.match(line)
        if m and m.group(2).split()[:1] and m.group(2).split()[0] in ("show", "get", "diagnose", "execute"):
            if cur:
                chunks.append(cur)
            cur = {"host": m.group(1), "command": m.group(2).strip(), "lines": []}
        elif cur is not None:
            cur["lines"].append(line)
    if cur:
        chunks.append(cur)
    return [(c["host"], c["command"], "\n".join(c["lines"])) for c in chunks]


def detect(text):
    """Classify a block of output. Returns a kind string or None."""
    if re.search(r"Local Interface\s+Parent Interface\s+Chassis Id", text):
        return "junos_lldp"
    if re.search(r"^Peer\s+AS\s+InPkt\s+OutPkt", text, re.M):
        return "junos_bgp"
    if re.search(r"^Interface\s+Admin\s+Link\s+Proto", text, re.M):
        return "junos_terse"
    if re.search(r"Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent", text):
        return "fgt_bgp"
    if re.search(r"^\s*==\s*\[[^\]]+\]", text, re.M) and "status:" in text:
        return "fgt_ifphys"
    if re.search(r"^Local Port\s+.*(System Name|Neighbor)", text, re.M | re.I) or \
            re.search(r"port\s+\S+\s*\n.*\n?.*neighbor", text, re.I) and "chassis" in text.lower():
        return "fgt_lldp"
    if re.search(r"^Model:\s+\S+", text, re.M) and re.search(r"^Junos:\s+\S+", text, re.M):
        return "junos_version"
    if re.search(r"^Version:\s*Forti\w+-\S+ v", text, re.M):
        return "fgt_status"
    if re.search(r"^Member ID\s+Status\s+Serial No", text, re.M) or "Virtual Chassis ID" in text:
        return "junos_vc"
    return None


def parse_junos_lldp(text):
    out, started = [], False
    for line in text.splitlines():
        if re.match(r"^Local Interface", line):
            started = True
            continue
        if not started or not line.strip():
            continue
        t = line.split()
        if len(t) < 4:
            continue
        local, parent = t[0], t[1]
        chassis = t[2]
        system = t[-1]
        port = " ".join(t[3:-1]) if len(t) > 4 else ""
        out.append({"local": local.removesuffix(".0"), "parent": "" if parent == "-" else parent,
                    "chassis": chassis, "remote_port": port, "remote_system": system})
    return out


def parse_junos_bgp(text):
    out = {}
    for line in text.splitlines():
        t = line.split()
        if len(t) < 7 or not re.fullmatch(IP_RE, t[0]) or not t[1].isdigit():
            continue
        last = t[-1]
        if last in BGP_STATES:
            state = "Established" if last.startswith("Establ") else last
        elif re.fullmatch(r"\d+/\d+/\d+(/\d+)?", last):
            state = "Established"
        else:
            state = last
        out[t[0]] = {"peer_as": t[1], "state": state, "flaps": t[5] if len(t) > 5 else "",
                     "uptime": t[6] if len(t) > 7 else ""}
    return out


def parse_junos_terse(text):
    out = {}
    for line in text.splitlines():
        if not line or line[0].isspace():
            continue
        t = line.split()
        if len(t) >= 3 and t[1] in ("up", "down") and t[2] in ("up", "down"):
            out[t[0].removesuffix(".0") if t[0].endswith(".0") and "." in t[0] else t[0]] = \
                {"admin": t[1], "link": t[2]}
    return out


def parse_junos_version(text):
    d = {}
    m = re.search(r"^Hostname:\s+(\S+)", text, re.M)
    if m:
        d["hostname"] = m.group(1)
    m = re.search(r"^Model:\s+(\S+)", text, re.M)
    if m:
        d["model"] = m.group(1)
    m = re.search(r"^Junos:\s+(\S+)", text, re.M)
    if m:
        d["version"] = m.group(1)
    return d


def parse_junos_vc(text):
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+\(FPC\s+\d+\)\s+(\w+)\s+(\S+)\s+(\S+)\s+\d+\s+(\w+)?", line)
        if m:
            rows.append({"member": m.group(1), "status": m.group(2), "serial": m.group(3),
                         "model": m.group(4), "role": m.group(5) or ""})
    return rows


def parse_fgt_bgp(text):
    out = {}
    for line in text.splitlines():
        t = line.split()
        if len(t) >= 10 and re.fullmatch(IP_RE, t[0]) and t[1] in ("4", "6"):
            last = t[-1]
            state = "Established" if last.isdigit() else last
            out[t[0]] = {"peer_as": t[2], "state": state, "uptime": t[-2], "prefixes": last if last.isdigit() else ""}
    return out


def parse_fgt_ifphys(text):
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^\s*==\s*\[([^\]]+)\]", line)
        if m:
            cur = m.group(1)
            if cur == "onboard":
                cur = None
                continue
            out[cur] = {}
            continue
        if cur:
            m = re.match(r"^\s*(\w[\w ]*):\s*(.*)$", line)
            if m:
                out[cur][m.group(1).strip()] = m.group(2).strip()
    return {k: {"admin": "up" if v.get("status") == "up" else ("down" if v.get("status") else ""),
                "link": v.get("status", ""), "speed": v.get("speed", "")} for k, v in out.items()}


def parse_fgt_status(text):
    d = {}
    m = re.search(r"^Version:\s*(Forti\w+-\S+)\s+v([\d.]+),build(\d+)", text, re.M)
    if m:
        d["model"], d["version"] = m.group(1), f"{m.group(2)} build{m.group(3)}"
    m = re.search(r"^Hostname:\s*(\S+)", text, re.M)
    if m:
        d["hostname"] = m.group(1)
    return d


def parse_fgt_lldp(text):
    """Best effort for `diagnose lldprx neighbor summary` style tables."""
    out = []
    for line in text.splitlines():
        t = line.split()
        if len(t) >= 4 and re.match(r"^(port|wan|lan|dmz|x|internal|a|ha|mgmt)\S*$", t[0], re.I):
            out.append({"local": t[0], "parent": "", "chassis": t[1] if len(t) > 4 else "",
                        "remote_port": t[-2], "remote_system": t[-1]})
    return out


PARSERS = {
    "junos_lldp": ("lldp", parse_junos_lldp),
    "junos_bgp": ("bgp", parse_junos_bgp),
    "junos_terse": ("ifstate", parse_junos_terse),
    "junos_version": ("version", parse_junos_version),
    "junos_vc": ("vc", parse_junos_vc),
    "fgt_bgp": ("bgp", parse_fgt_bgp),
    "fgt_ifphys": ("ifstate", parse_fgt_ifphys),
    "fgt_status": ("version", parse_fgt_status),
    "fgt_lldp": ("lldp", parse_fgt_lldp),
}

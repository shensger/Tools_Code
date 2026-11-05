"""Junos (QFX/EX) config parser.

Accepts either `display set` output or the default curly-brace format
(converted to set lines first). Produces a normalized device dict.
Secrets (passwords, keys, $9$ strings) are never stored.
"""
import re
import shlex
from .common import new_device, new_interface, new_unit, norm_if, expand_vlan_tokens

SECRET_HINTS = ("encrypted-password", "authentication-key", "secret", "pre-shared-key",
                "community", "$9$", "$6$", "$1$", "ssh-rsa", "ssh-ed25519", "ecdsa-sha2")


# ---------------------------------------------------------------- curly -> set
def _tokenize(text):
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c == "#" and (i == 0 or text[i - 1] == "\n" or text[i - 1] in " \t"):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c in "{};[]":
            toks.append(c)
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            toks.append(text[i:j + 1])
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in " \t\r\n{};[]":
                j += 1
            toks.append(text[i:j])
            i = j
    return toks


def curly_to_set(text):
    """Convert Junos hierarchical config to `set` / `deactivate` lines."""
    out, path, inactive_stack = [], [], []
    stmt, in_list, lst = [], False, []
    for t in _tokenize(text):
        if in_list:
            if t == "]":
                in_list = False
            else:
                lst.append(t)
            continue
        if t == "[":
            in_list, lst = True, []
            continue
        if t == "{":
            inactive = False
            while stmt and stmt[0].rstrip(":") in ("inactive", "protect", "replace", "delete"):
                inactive = inactive or stmt[0].startswith("inactive")
                stmt = stmt[1:]
            path.append(stmt)
            inactive_stack.append(inactive)
            if inactive:
                out.append("deactivate " + " ".join(sum(path, [])))
            stmt = []
        elif t == ";":
            inactive = False
            while stmt and stmt[0].rstrip(":") in ("inactive", "protect", "replace", "delete"):
                inactive = inactive or stmt[0].startswith("inactive")
                stmt = stmt[1:]
            base = sum(path, [])
            if lst:
                for v in lst:
                    out.append("set " + " ".join(base + stmt + [v]))
                lst = []
            elif stmt:
                out.append("set " + " ".join(base + stmt))
            if inactive and stmt:
                out.append("deactivate " + " ".join(base + stmt))
            stmt = []
        elif t == "}":
            if path:
                path.pop()
                inactive_stack.pop()
            stmt = []
        else:
            stmt.append(t)
    return out


def looks_like_junos_config(text):
    if re.search(r"^set (system|interfaces|vlans|protocols|routing-options|chassis) ", text, re.M):
        return "set"
    if re.search(r"^\s*(system|interfaces|vlans|protocols|routing-options)\s*\{", text, re.M):
        return "curly"
    return None


# ---------------------------------------------------------------- set parser
def _split(line):
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def parse(text, source_name=""):
    kind = looks_like_junos_config(text)
    lines = curly_to_set(text) if kind == "curly" else [l.strip() for l in text.splitlines()]
    sets = [l for l in lines if l.startswith("set ")]
    deact = [l[len("deactivate "):] for l in lines if l.startswith("deactivate ")]

    dev = new_device("junos")
    dev["sources"].append(source_name)
    m = re.search(r"^## Last commit: (.+)$", text, re.M)
    if m:
        dev["last_commit"] = m.group(1).strip()

    ri_ifaces = {}  # "xe-0/0/1.0" -> instance
    for raw in sets:
        body = raw[4:]
        if any(body.startswith(d) for d in deact):
            dev["inactive"].append(body)
            continue
        if any(h in body for h in SECRET_HINTS):
            # still allow non-secret structure lines like `system login user x class y`
            if not body.startswith("system login user") or "authentication" in body:
                continue
        t = _split(body)
        if not t:
            continue
        if t[0] == "groups" or t[0] == "apply-groups":
            dev["notes"].add("Config uses groups; collect with `| display inheritance` so inherited settings are parsed.")
            continue
        _handle(dev, t, "master", ri_ifaces)

    # bind interfaces to routing instances
    for ifu, inst in ri_ifaces.items():
        name, _, unit = ifu.partition(".")
        unit = unit or "0"
        itf = dev["interfaces"].get(name)
        if itf and unit in itf["units"]:
            itf["units"][unit]["instance"] = inst
        dev["ri_interfaces"].setdefault(inst, []).append(ifu)

    # resolve VLAN membership names -> ids
    name2id = {n: v["id"] for n, v in dev["vlans"].items() if v.get("id") is not None}
    for itf in dev["interfaces"].values():
        for u in itf["units"].values():
            ids, undefined, allv = expand_vlan_tokens(u.pop("_vlan_tokens", []), name2id)
            u["vlans"] = ids
            u["vlans_all"] = allv
            u["vlans_undefined"] = undefined
    for vname, v in dev["vlans"].items():  # old EX `vlans X interface Y`
        for ifu in v.pop("_ifaces", []):
            n, _, unit = ifu.partition(".")
            itf = dev["interfaces"].setdefault(n, new_interface(n))
            u = itf["units"].setdefault(unit or "0", new_unit(unit or "0"))
            if v.get("id") is not None and v["id"] not in u["vlans"]:
                u["vlans"].append(v["id"])
            u.setdefault("mode", u.get("mode") or "access")
    dev["notes"] = sorted(dev["notes"])
    return dev


def _iface(dev, name):
    name = norm_if(name)
    return dev["interfaces"].setdefault(name, new_interface(name))


def _handle(dev, t, inst, ri_ifaces):
    k = t[0]
    if k == "version":
        dev["version"] = t[1] if len(t) > 1 else ""
    elif k == "system":
        if t[1:2] == ["host-name"] and len(t) > 2:
            dev["hostname"] = t[2]
        elif t[1:2] == ["domain-name"] and len(t) > 2:
            dev["domain"] = t[2]
        elif t[1:2] == ["name-server"] and len(t) > 2:
            dev["services"].setdefault("dns", []).append(t[2])
        elif t[1:3] == ["ntp", "server"] and len(t) > 3:
            dev["services"].setdefault("ntp", []).append(t[3])
        elif t[1:3] == ["syslog", "host"] and len(t) > 3:
            if t[3] not in dev["services"].setdefault("syslog", []):
                dev["services"]["syslog"].append(t[3])
    elif k == "chassis":
        if t[1:4] == ["aggregated-devices", "ethernet", "device-count"] and len(t) > 4:
            dev["lag_device_count"] = int(t[4])
    elif k == "virtual-chassis":
        if t[1:2] == ["preprovisioned"]:
            dev["vc"]["preprovisioned"] = True
        elif t[1:2] == ["member"] and len(t) > 3:
            mem = dev["vc"]["members"].setdefault(t[2], {"member": t[2]})
            if t[3] in ("role", "serial-number") and len(t) > 4:
                mem[t[3].replace("-number", "")] = t[4]
    elif k == "interfaces":
        _handle_iface(dev, t[1:])
    elif k == "vlans" and len(t) > 2:
        v = dev["vlans"].setdefault(t[1], {"name": t[1], "id": None, "l3": None, "description": ""})
        if t[2] == "vlan-id":
            v["id"] = int(t[3]) if t[3].isdigit() else t[3]
        elif t[2] == "l3-interface":
            v["l3"] = t[3]
        elif t[2] == "description":
            v["description"] = " ".join(t[3:])
        elif t[2] == "interface":
            v.setdefault("_ifaces", []).append(t[3])
    elif k == "routing-options":
        _handle_ro(dev, t[1:], inst)
    elif k == "protocols":
        if t[1:2] == ["bgp"]:
            _handle_bgp(dev, t[2:], inst)
        elif t[1:2] == ["lldp"]:
            dev["services"]["lldp"] = True
    elif k == "routing-instances" and len(t) > 2:
        ri, rest = t[1], t[2:]
        dev["routing_instances"].setdefault(ri, {"name": ri, "type": ""})
        if rest[0] == "instance-type":
            dev["routing_instances"][ri]["type"] = rest[1]
        elif rest[0] == "interface":
            ri_ifaces[rest[1] if "." in rest[1] else rest[1] + ".0"] = ri
        elif rest[0] in ("routing-options", "protocols"):
            _handle(dev, rest, ri, ri_ifaces)


def _handle_iface(dev, t):
    if not t or t[0] in ("interface-range",):
        if t and t[0] == "interface-range":
            dev["notes"].add("Config uses interface-range; member ports are not expanded in this report.")
        return
    itf = _iface(dev, t[0])
    r = t[1:]
    if not r:
        return
    a = r[0]
    if a == "description":
        itf["description"] = " ".join(r[1:])
    elif a == "disable":
        itf["disabled"] = True
    elif a == "mtu":
        itf["mtu"] = r[1]
    elif a == "speed":
        itf["speed"] = r[1]
    elif a in ("ether-options", "gigether-options") and r[1:2] == ["802.3ad"] and len(r) > 2:
        itf["lag"] = r[2] if r[2] not in ("lacp",) else itf.get("lag")
    elif a == "aggregated-ether-options":
        if r[1:2] == ["lacp"] and len(r) > 2 and r[2] in ("active", "passive"):
            itf["lacp"] = r[2]
        elif r[1:2] == ["minimum-links"]:
            itf["min_links"] = r[2]
        elif r[1:2] == ["lacp"] and len(r) > 3 and r[2] == "system-id":
            itf["lacp_system_id"] = r[3]
        elif r[1:2] == ["link-speed"]:
            itf["speed"] = r[2]
    elif a == "esi":
        itf["esi"] = True
    elif a in ("vlan-tagging", "flexible-vlan-tagging"):
        itf["vlan_tagging"] = True
    elif a == "native-vlan-id":
        itf["native_vlan"] = r[1]
    elif a == "unit" and len(r) > 1:
        u = itf["units"].setdefault(r[1], new_unit(r[1]))
        _handle_unit(u, r[2:])


def _handle_unit(u, r):
    if not r:
        return
    a = r[0]
    if a == "description":
        u["description"] = " ".join(r[1:])
    elif a == "disable":
        u["disabled"] = True
    elif a == "vlan-id":
        u["vlan_id"] = r[1]
    elif a == "family" and len(r) > 1:
        fam = r[1]
        if fam not in u["families"]:
            u["families"].append(fam)
        rest = r[2:]
        if fam == "inet" and rest[:1] == ["address"] and len(rest) > 1:
            if rest[1] not in u["inet"]:
                u["inet"].append(rest[1])
            if "vrrp-group" in rest and "virtual-address" in rest:
                u["vips"].append(rest[rest.index("virtual-address") + 1])
        elif fam == "inet6" and rest[:1] == ["address"] and len(rest) > 1:
            if rest[1] not in u["inet6"]:
                u["inet6"].append(rest[1])
        elif fam == "ethernet-switching":
            if rest[:1] in (["interface-mode"], ["port-mode"]) and len(rest) > 1:
                u["mode"] = rest[1]
            elif rest[:2] == ["vlan", "members"] and len(rest) > 2:
                u.setdefault("_vlan_tokens", []).extend(x for x in rest[2:] if x not in ("[", "]"))
            elif rest[:1] == ["native-vlan-id"] and len(rest) > 1:
                u["native_vlan"] = rest[1]


def _handle_ro(dev, r, inst):
    if not r:
        return
    if r[0] == "router-id":
        if inst == "master":
            dev["router_id"] = r[1]
    elif r[0] == "autonomous-system":
        if inst == "master":
            dev["asn"] = r[1]
        else:
            dev["routing_instances"][inst]["asn"] = r[1]
    elif r[:2] == ["static", "route"] and len(r) > 3:
        pfx, rest = r[2], r[3:]
        rt = {"instance": inst, "prefix": pfx, "next_hop": "", "type": "", "preference": "", "qualified": False}
        if rest[0] in ("next-hop", "qualified-next-hop"):
            rt["next_hop"], rt["type"] = rest[1], "next-hop"
            rt["qualified"] = rest[0] == "qualified-next-hop"
            if rt["qualified"] and len(rest) > 3 and rest[2] == "preference":
                rt["preference"] = rest[3]
        elif rest[0] in ("discard", "reject"):
            rt["type"] = rest[0]
        elif rest[0] == "next-table":
            rt["type"], rt["next_hop"] = "next-table", rest[1]
        elif rest[0] == "resolve":
            for e in dev["static_routes"]:
                if e["prefix"] == pfx and e["instance"] == inst:
                    e["resolve"] = True
            return
        elif rest[0] == "preference":
            # preference applies to an existing route entry
            for e in dev["static_routes"]:
                if e["prefix"] == pfx and e["instance"] == inst:
                    e["preference"] = rest[1]
            return
        else:
            return
        dev["static_routes"].append(rt)


def _handle_bgp(dev, r, inst):
    bgp = dev["bgp"]
    if not r:
        return
    if r[0] == "group" and len(r) > 2:
        g = bgp["groups"].setdefault((inst, r[1]), {"instance": inst, "name": r[1], "type": "",
                                                    "peer_as": "", "local_address": "", "local_as": "",
                                                    "import": [], "export": [], "multihop": False})
        rest = r[2:]
        if rest[0] == "neighbor" and len(rest) > 1:
            n = bgp["neighbors"].setdefault((inst, rest[1]), {"instance": inst, "group": r[1], "ip": rest[1],
                                                               "peer_as": "", "description": "", "local_address": ""})
            if len(rest) > 3 and rest[2] in ("peer-as", "description", "local-address"):
                n[rest[2].replace("-", "_")] = " ".join(rest[3:])
        elif rest[0] in ("type", "peer-as", "local-address") and len(rest) > 1:
            g[rest[0].replace("-", "_")] = rest[1]
        elif rest[0] == "local-as" and len(rest) > 1:
            g["local_as"] = rest[1]
        elif rest[0] in ("import", "export") and len(rest) > 1:
            g[rest[0]].append(rest[1])
        elif rest[0] == "multihop":
            g["multihop"] = True

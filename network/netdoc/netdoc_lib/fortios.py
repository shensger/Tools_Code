"""FortiOS config parser (`show` / `show full-configuration` output, single or multi-VDOM).
Secrets (psksecret, passwd, ENC blobs, private keys) are never stored."""
import re
import shlex
from collections import OrderedDict
from .common import new_device, new_interface, new_unit, mask_to_cidr

SECRET_KEYS = {"psksecret", "password", "passwd", "secret", "private-key", "certificate",
               "key", "ppk-secret", "auth-pwd", "psksecret-remote", "local-cert", "authpasswd"}


def looks_like_fortios_config(text):
    return bool(re.search(r"^\s*config (system|firewall|router) ", text, re.M)) and \
        bool(re.search(r"^\s*(edit|set) ", text, re.M))


def _node(kind, key=""):
    return {"kind": kind, "key": key, "settings": OrderedDict(), "entries": OrderedDict(), "children": OrderedDict()}


def parse_tree(text):
    root = _node("entry", "root")
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            t = shlex.split(line, posix=True)
        except ValueError:
            t = line.split()
        if not t:
            continue
        cmd = t[0]
        if cmd == "config":
            n = _node("config", " ".join(t[1:]))
            stack[-1]["children"].setdefault(n["key"], []).append(n)
            stack.append(n)
        elif cmd == "edit":
            top = stack[-1]
            if top["kind"] != "config":
                continue
            e = _node("entry", t[1] if len(t) > 1 else "")
            top["entries"][e["key"]] = e
            stack.append(e)
        elif cmd == "set" and len(t) > 1:
            if t[1] in SECRET_KEYS or any(v.startswith("ENC ") for v in t[2:]) or "ENC" in t[2:3]:
                continue
            stack[-1]["settings"][t[1]] = t[2:]
        elif cmd == "next":
            if stack[-1]["kind"] == "entry" and len(stack) > 1:
                stack.pop()
        elif cmd == "end":
            if stack[-1]["kind"] == "entry" and len(stack) > 1:
                stack.pop()
            if stack[-1]["kind"] == "config" and len(stack) > 1:
                stack.pop()
    return root


def _walk(node, vdom, out):
    for name, nodes in node["children"].items():
        for n in nodes:
            if name == "vdom":
                for vk, ventry in n["entries"].items():
                    if vk not in out["_vdoms"]:
                        out["_vdoms"].append(vk)
                    _walk(ventry, vk, out)
            elif name == "global":
                _walk(n, "global", out)
            else:
                out.setdefault(name, []).append((vdom, n))


def _s(e, k, default=""):
    v = e["settings"].get(k)
    if v is None:
        return default
    return " ".join(v)


def _l(e, k):
    return list(e["settings"].get(k, []))


def parse(text, source_name=""):
    dev = new_device("fortios")
    dev["sources"].append(source_name)
    m = re.search(r"#config-version=([A-Z0-9]+)-([\d.]+)-FW-build(\d+)", text)
    if m:
        dev["model"], dev["version"] = m.group(1), f"{m.group(2)} build{m.group(3)}"
    tree = parse_tree(text)
    cfg = {"_vdoms": []}
    _walk(tree, "root", cfg)
    dev["fw"]["vdoms"] = cfg["_vdoms"]

    for vdom, n in cfg.get("system global", []):
        h = _s(n, "hostname")
        if h:
            dev["hostname"] = h

    for vdom, n in cfg.get("system interface", []):
        for name, e in n["entries"].items():
            itf = dev["interfaces"].setdefault(name, new_interface(name))
            u = itf["units"].setdefault("0", new_unit("0"))
            ipv = _l(e, "ip")
            if len(ipv) >= 2 and ipv[0] != "0.0.0.0":
                c = mask_to_cidr(ipv[0], ipv[1])
                if c:
                    u["inet"].append(c)
            elif len(ipv) == 1 and "/" in ipv[0] and not ipv[0].startswith("0.0.0.0"):
                u["inet"].append(ipv[0])
            for sname, sub in e["children"].items():
                if sname == "secondaryip":
                    for se in sub[0]["entries"].values():
                        sip = _l(se, "ip")
                        if len(sip) >= 2:
                            c = mask_to_cidr(sip[0], sip[1])
                            if c:
                                u["inet"].append(c)
                if sname == "ipv6":
                    ip6 = _s(sub[0], "ip6-address")
                    if ip6 and not ip6.startswith("::/0"):
                        u["inet6"].append(ip6)
            itf["vdom"] = _s(e, "vdom") or vdom
            itf["alias"] = _s(e, "alias")
            itf["description"] = _s(e, "description") or itf["alias"]
            itf["type"] = _s(e, "type") or "physical"
            itf["role"] = _s(e, "role")
            itf["mode"] = _s(e, "mode") or "static"
            itf["allowaccess"] = _l(e, "allowaccess")
            itf["disabled"] = _s(e, "status") == "down"
            itf["parent"] = _s(e, "interface")
            itf["members"] = _l(e, "member")
            itf["mtu"] = _s(e, "mtu") if _s(e, "mtu-override") == "enable" else ""
            itf["speed"] = _s(e, "speed")
            vid = _s(e, "vlanid")
            itf["fw_vlanid"] = int(vid) if vid.isdigit() else None
            if itf["type"] == "aggregate":
                itf["lacp"] = _s(e, "lacp-mode") or "active"
                itf["min_links"] = _s(e, "min-links")
                for mbr in itf["members"]:
                    dev["interfaces"].setdefault(mbr, new_interface(mbr))["lag"] = name

    for vdom, n in cfg.get("system zone", []):
        for name, e in n["entries"].items():
            members = _l(e, "interface")
            dev["fw"]["zones"][name] = {"name": name, "vdom": vdom, "interfaces": members,
                                        "intrazone": _s(e, "intrazone") or "deny"}
            for mbr in members:
                if mbr in dev["interfaces"]:
                    dev["interfaces"][mbr]["zone"] = name

    for vdom, n in cfg.get("router static", []):
        for k, e in n["entries"].items():
            dst = _l(e, "dst")
            prefix = mask_to_cidr(dst[0], dst[1]) if len(dst) >= 2 else ("0.0.0.0/0" if not _s(e, "dstaddr") else "")
            if prefix and "/" in prefix:
                import ipaddress
                prefix = str(ipaddress.ip_interface(prefix).network)
            rt = {"instance": vdom, "prefix": prefix or f"addr:{_s(e, 'dstaddr')}",
                  "next_hop": _s(e, "gateway"), "device": _s(e, "device"),
                  "type": "blackhole" if _s(e, "blackhole") == "enable" else "next-hop",
                  "preference": _s(e, "distance"), "comment": _s(e, "comment"),
                  "disabled": _s(e, "status") == "disable", "seq": k, "qualified": False}
            if not rt["next_hop"] and rt["device"] and rt["type"] != "blackhole":
                rt["type"], rt["next_hop"] = "interface", ""
            if _s(e, "dynamic-gateway") == "enable":
                rt["next_hop"] = "dynamic (DHCP/PPPoE)"
            dev["static_routes"].append(rt)

    for vdom, n in cfg.get("router bgp", []):
        asn = _s(n, "as")
        if asn and asn != "0":
            dev["asn"] = asn
        rid = _s(n, "router-id")
        if rid:
            dev["router_id"] = rid
        for sub in n["children"].get("neighbor", []):
            for ip, e in sub["entries"].items():
                dev["bgp"]["neighbors"][(vdom, ip)] = {
                    "instance": vdom, "group": "", "ip": ip, "peer_as": _s(e, "remote-as"),
                    "description": _s(e, "description"), "local_address": _s(e, "update-source")}
        for sub in n["children"].get("neighbor-range", []):
            for k, e in sub["entries"].items():
                dev["bgp"]["neighbors"][(vdom, "range " + _s(e, "prefix"))] = {
                    "instance": vdom, "group": _s(e, "neighbor-group"), "ip": "range " + _s(e, "prefix"),
                    "peer_as": "", "description": "dynamic neighbor range", "local_address": ""}

    for vdom, n in cfg.get("firewall vip", []):
        for name, e in n["entries"].items():
            mapped = []
            for x in _l(e, "mappedip"):
                mapped.append(x)
            for sub in e["children"].get("realservers", []):
                for rs in sub["entries"].values():
                    mapped.append(_s(rs, "ip"))
            dev["fw"]["vips"].append({
                "vdom": vdom, "name": name, "extintf": _s(e, "extintf"), "extip": _s(e, "extip"),
                "mappedip": ", ".join(mapped), "portforward": _s(e, "portforward") == "enable",
                "protocol": _s(e, "protocol") or ("tcp" if _s(e, "portforward") == "enable" else "any"),
                "extport": _s(e, "extport"), "mappedport": _s(e, "mappedport"),
                "type": _s(e, "type") or "static-nat", "comment": _s(e, "comment")})

    for vdom, n in cfg.get("firewall policy", []):
        for pid, e in n["entries"].items():
            dev["fw"]["policies"].append({
                "vdom": vdom, "id": pid, "name": _s(e, "name"),
                "srcintf": _l(e, "srcintf"), "dstintf": _l(e, "dstintf"),
                "srcaddr": _l(e, "srcaddr"), "dstaddr": _l(e, "dstaddr"),
                "service": _l(e, "service"), "action": _s(e, "action") or "deny",
                "status": _s(e, "status") or "enable", "nat": _s(e, "nat") == "enable",
                "schedule": _s(e, "schedule"), "logtraffic": _s(e, "logtraffic"),
                "comments": _s(e, "comments")})

    for vdom, n in cfg.get("vpn ipsec phase1-interface", []):
        for name, e in n["entries"].items():
            dev["fw"]["ipsec_p1"].append({
                "vdom": vdom, "name": name, "interface": _s(e, "interface"),
                "remote_gw": _s(e, "remote-gw") or ("dialup" if _s(e, "type") == "dynamic" else ""),
                "ike_version": _s(e, "ike-version") or "1", "proposal": _s(e, "proposal"),
                "dhgrp": _s(e, "dhgrp"), "comments": _s(e, "comments")})
    for vdom, n in cfg.get("vpn ipsec phase2-interface", []):
        for name, e in n["entries"].items():
            def sub(prefix):
                v = _l(e, prefix + "-subnet")
                if len(v) >= 2:
                    return mask_to_cidr(v[0], v[1]) or " ".join(v)
                return _s(e, prefix + "-name") or "0.0.0.0/0"
            dev["fw"]["ipsec_p2"].append({"vdom": vdom, "name": name, "phase1": _s(e, "phase1name"),
                                          "src": sub("src"), "dst": sub("dst"),
                                          "proposal": _s(e, "proposal"), "pfs": _s(e, "pfs") or "enable"})

    for vdom, n in cfg.get("system dns", []):
        for k in ("primary", "secondary"):
            if _s(n, k):
                dev["services"].setdefault("dns", []).append(_s(n, k))
    for vdom, n in cfg.get("system ntp", []):
        for sub in n["children"].get("ntpserver", []):
            for e in sub["entries"].values():
                dev["services"].setdefault("ntp", []).append(_s(e, "server"))
    for key in ("log syslogd setting", "log syslogd2 setting"):
        for vdom, n in cfg.get(key, []):
            if _s(n, "status") == "enable":
                dev["services"].setdefault("syslog", []).append(_s(n, "server"))
    for vdom, n in cfg.get("system ha", []):
        mode = _s(n, "mode")
        if mode and mode != "standalone":
            dev["services"]["ha"] = f"{mode} group {_s(n, 'group-name')}".strip()

    dev["notes"] = sorted(dev["notes"])
    return dev

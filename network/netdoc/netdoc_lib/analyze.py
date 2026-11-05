"""Load inputs, merge per device, infer links, and produce findings."""
import ipaddress
import os
import re
from collections import defaultdict
from . import junos, fortios, live
from .common import new_device, short_host, norm_if, iface_net, vlan_ranges

KNOWN_AS = {"12076": "Microsoft ExpressRoute", "8075": "Microsoft", "7224": "AWS",
            "16509": "AWS", "15169": "Google", "396982": "Google Cloud", "13335": "Cloudflare",
            "31898": "Oracle Cloud"}
TIER = {"external": 0, "firewall": 1, "core": 2, "distribution": 3, "access": 4, "endpoint": 5}
MGMT_IFS = re.compile(r"^(em\d|fxp\d|me\d|vme|re\d:mgmt-\d|mgmt\d?|ha\d?mgmt)", re.I)


# ------------------------------------------------------------------ loading
def _files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if not n.startswith("."):
                        yield os.path.join(root, n)
        elif os.path.isfile(p):
            yield p


def _prefix(path):
    b = os.path.basename(path)
    if "__" in b:
        return b.split("__")[0]
    return b.split(".")[0]


def _read(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        data = data.decode("utf-16", errors="replace").encode("utf-8")
    if b"\x00" in data[:2000]:
        return None
    return data.decode("utf-8-sig", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def load(paths):
    devices, live_chunks, unrecognized, inventory = {}, [], [], []
    alias = {}

    def add_device(dev, key, src):
        host = dev["hostname"] or key
        dev["hostname"] = host
        k = short_host(host)
        if k in devices:
            existing = devices[k]
            existing["notes"].append(f"Duplicate config for {host} in {src}; first one kept.")
            return existing
        dev["aliases"] = {short_host(key), k}
        devices[k] = dev
        for a in dev["aliases"]:
            alias[a] = k
        return dev

    roots = [p if os.path.isdir(p) else os.path.dirname(p) for p in paths]
    for path in _files(paths):
        text = _read(path)
        root = next((r for r in roots if os.path.abspath(path).startswith(os.path.abspath(r))), os.path.dirname(path))
        name = os.path.relpath(path, root)
        if text is None:
            unrecognized.append((name, "binary file"))
            continue
        chunks = live.split_session(text)
        if not chunks:
            chunks = [(_prefix(path), "", text)]
        recognized = False
        for host, cmd, body in chunks:
            if junos.looks_like_junos_config(body):
                add_device(junos.parse(body, name), host, name)
                inventory.append((name, host, "Junos config"))
                recognized = True
            elif fortios.looks_like_fortios_config(body):
                add_device(fortios.parse(body, name), host, name)
                inventory.append((name, host, "FortiOS config"))
                recognized = True
            else:
                kind = live.detect(body)
                if kind:
                    live_chunks.append((host, kind, body, name))
                    inventory.append((name, host, kind))
                    recognized = True
        if not recognized:
            unrecognized.append((name, "no recognized config or show-command output"))

    for host, kind, body, name in live_chunks:
        k = alias.get(short_host(host))
        if not k:
            dev = new_device("junos" if kind.startswith("junos") else "fortios")
            dev["hostname"] = host
            dev["notes"].add("No configuration collected for this device; live data only.")
            k = short_host(host)
            dev["aliases"] = {k}
            devices[k] = dev
            alias[k] = k
        dev = devices[k]
        slot, fn = live.PARSERS[kind]
        data = fn(body)
        dev["sources"].append(name)
        if slot == "lldp":
            dev["live"]["lldp"].extend(data)
        elif slot in ("bgp", "ifstate"):
            dev["live"][slot].update(data)
        elif slot == "version":
            for f in ("model", "version"):
                if data.get(f) and not dev[f]:
                    dev[f] = data[f]
        elif slot == "vc":
            dev["vc"]["live"] = data
    for d in devices.values():
        d["notes"] = sorted(set(d["notes"])) if isinstance(d["notes"], (set, list)) else []
        d["aliases"] = sorted(d["aliases"])
    return devices, inventory, unrecognized


# ------------------------------------------------------------------ helpers
def unit_name(itf, unit):
    return itf["name"] if unit == "0" else f"{itf['name']}.{unit}"


def iter_units(dev):
    for itf in dev["interfaces"].values():
        for u, ud in itf["units"].items():
            yield itf, u, ud


def infer_role(dev):
    h = dev["hostname"].lower()
    if dev["platform"] == "fortios":
        return "firewall"
    if re.search(r"core|spine|cr\d|bdr|border", h):
        return "core"
    if re.search(r"dist|agg|stor|leaf", h):
        return "distribution"
    if re.search(r"acc|idf|edge|ex\d|sw\d", h):
        return "access"
    irbs = sum(1 for itf, u, ud in iter_units(dev) if itf["name"].startswith(("irb", "vlan")) and ud["inet"])
    if dev["bgp"]["neighbors"] or irbs >= 3:
        return "core"
    return "access"


def mgmt_ip(dev):
    for itf, u, ud in iter_units(dev):
        if MGMT_IFS.match(itf["name"]) and ud["inet"]:
            return ud["inet"][0].split("/")[0]
    return ""


def switch_view(dev, ifname):
    """(mode, set_of_vlans, all_flag, native) for a port, or None."""
    itf = dev["interfaces"].get(ifname)
    if not itf:
        return None
    if dev["platform"] == "fortios":
        tagged = {i["fw_vlanid"] for i in dev["interfaces"].values() if i["parent"] == ifname and i["fw_vlanid"]}
        if tagged:
            return ("trunk", tagged, False, "untagged" if itf["units"].get("0", {}).get("inet") else "")
        if itf["units"].get("0", {}).get("inet"):
            return ("routed", set(), False, "")
        return None
    u = itf["units"].get("0")
    if not u:
        return None
    if "ethernet-switching" in u["families"] or u["vlans"] or u["mode"]:
        mode = u["mode"] or "access"
        return (mode, set(u["vlans"]), u["vlans_all"], u["native_vlan"] or itf["native_vlan"])
    if u["inet"]:
        return ("routed", set(), False, "")
    if itf["vlan_tagging"]:
        tagged = {int(x["vlan_id"]) for x in itf["units"].values() if str(x["vlan_id"]).isdigit()}
        return ("trunk", tagged, False, itf["native_vlan"])
    return None


# ------------------------------------------------------------------ analysis
def analyze(devices):
    model = {"devices": devices, "links": [], "findings": [], "networks": [], "external": {}}
    F = model["findings"]

    def find(sev, cat, dev, obj, text, rec, evidence=""):
        F.append({"severity": sev, "category": cat, "device": dev, "object": obj,
                  "finding": text, "recommendation": rec, "evidence": evidence})

    for d in devices.values():
        d["role"] = infer_role(d)
        d["mgmt_ip"] = mgmt_ip(d)

    # ---- address map / networks
    ip_owner = defaultdict(list)      # ip -> [(dev, iface)]
    nets = defaultdict(list)          # network -> [(dev, iface, ip, instance)]
    for k, d in devices.items():
        for itf, u, ud in iter_units(d):
            if ud.get("disabled") or itf["disabled"]:
                pass
            for c in ud["inet"]:
                ii = iface_net(c)
                if not ii:
                    continue
                inst = ud["instance"] if d["platform"] == "junos" else (itf["vdom"] or "root")
                ip_owner[str(ii.ip)].append((k, unit_name(itf, u)))
                nets[ii.network].append((k, unit_name(itf, u), str(ii.ip), inst))
    model["_ip_owner"] = ip_owner

    for ip, owners in ip_owner.items():
        distinct = sorted(set(owners))
        if len(distinct) > 1:
            find("High", "IP addressing", ", ".join(sorted({o[0] for o in distinct})), ip,
                 f"IP {ip} is configured on more than one interface: " +
                 "; ".join(f"{devices[a]['hostname']} {b}" for a, b in distinct),
                 "Remove the duplicate; if it is a shared gateway, use VRRP virtual-address instead of a static duplicate.",
                 "config")

    # ---- links: LLDP
    links, seen = [], {}
    for k, d in devices.items():
        for n in d["live"]["lldp"]:
            rk = None
            rs = short_host(n["remote_system"])
            for kk, dd in devices.items():
                if rs and rs in dd["aliases"]:
                    rk = kk
                    break
            a_if = norm_if(n["local"])
            a_lag = n["parent"] or (d["interfaces"].get(a_if, {}) or {}).get("lag") or ""
            b_if = norm_if(n["remote_port"]) if n["remote_port"] else ""
            b_lag = ""
            if rk and b_if in devices[rk]["interfaces"]:
                b_lag = devices[rk]["interfaces"][b_if].get("lag") or ""
            b = rk or ("ext:" + n["remote_system"])
            key = tuple(sorted([(k, a_if), (b, b_if)]))
            if key in seen:
                seen[key]["confirmed"] = True
                continue
            L = {"a": k, "a_if": a_if, "a_lag": a_lag, "b": b, "b_if": b_if, "b_lag": b_lag,
                 "b_known": bool(rk), "source": "LLDP", "confirmed": False,
                 "remote_name": n["remote_system"], "chassis": n.get("chassis", "")}
            seen[key] = L
            links.append(L)
    lldp_ifs = {(L["a"], L["a_if"]) for L in links} | {(L["b"], L["b_if"]) for L in links if L["b_known"]}
    lldp_pairs = {frozenset((L["a"], L["b"])) for L in links}

    # ---- links: point-to-point subnets
    for net, members in nets.items():
        if net.version == 4 and net.prefixlen >= 29 or net.version == 6 and net.prefixlen >= 126:
            devs = sorted({m[0] for m in members})
            if len(devs) >= 2:
                for i in range(len(devs)):
                    for j in range(i + 1, len(devs)):
                        ma = next(m for m in members if m[0] == devs[i])
                        mb = next(m for m in members if m[0] == devs[j])
                        links.append({"a": ma[0], "a_if": ma[1], "a_lag": "", "b": mb[0], "b_if": mb[1],
                                      "b_lag": "", "b_known": True, "source": f"Shared subnet {net}",
                                      "confirmed": False, "remote_name": "", "chassis": ""})

    # ---- links: descriptions
    hostkeys = {k: [a for a in d["aliases"] if len(a) >= 4] for k, d in devices.items()}
    for k, d in devices.items():
        for itf in d["interfaces"].values():
            desc = (itf["description"] or "").lower()
            if not desc:
                continue
            for ok, al in hostkeys.items():
                if ok == k or not any(re.search(r"(?<![\w-])" + re.escape(a) + r"(?![\w])", desc) for a in al):
                    continue
                nm = itf["name"]
                lk = [L for L in links if L["source"] == "LLDP" and
                      ((L["a"] == k and nm in (L["a_if"], L["a_lag"])) or (L["b"] == k and nm in (L["b_if"], L["b_lag"])))]
                if lk:
                    others = {L["b"] if L["a"] == k else L["a"] for L in lk}
                    other = sorted(others)[0]
                    if ok not in others:
                        find("Medium", "Documentation", d["hostname"], itf["name"],
                             f"Description says '{itf['description']}' but LLDP shows the neighbor is "
                             f"{devices[other]['hostname'] if other in devices else other.removeprefix('ext:')}.",
                             "Correct the interface description (or the cabling, if the description is right).", "config + LLDP")
                elif (k, itf["name"]) not in lldp_ifs:
                    links.append({"a": k, "a_if": itf["name"], "a_lag": itf.get("lag") or "", "b": ok, "b_if": "",
                                  "b_lag": "", "b_known": True, "source": "Description", "confirmed": False,
                                  "remote_name": "", "chassis": ""})

    # ---- BGP peerings
    for k, d in devices.items():
        for (inst, ip), n in d["bgp"]["neighbors"].items():
            owner = ip_owner.get(ip.split("/")[0], [])
            g = d["bgp"]["groups"].get((inst, n["group"]), {})
            peer_as = n["peer_as"] or g.get("peer_as", "") or (d["asn"] if g.get("type") == "internal" else "")
            n["peer_as_eff"] = peer_as
            n["type_eff"] = g.get("type", "") or ("internal" if peer_as and peer_as == d["asn"] else "external")
            if owner and owner[0][0] != k:
                n["peer_device"] = owner[0][0]
            elif n["type_eff"] == "internal":
                ext = f"iBGP peer {ip} (not documented)"
                n["peer_device"] = "ext:" + ext
                model["external"].setdefault("ext:" + ext, {"label": ext, "peers": []})["peers"].append((k, ip))
            else:
                ext = f"AS {peer_as}" if peer_as else "unknown AS"
                if peer_as in KNOWN_AS:
                    ext += f" ({KNOWN_AS[peer_as]})"
                n["peer_device"] = "ext:" + ext
                model["external"].setdefault("ext:" + ext, {"label": ext, "peers": []})["peers"].append((k, ip))

    model["links"] = links

    # ---- per-device checks
    for k, d in devices.items():
        H = d["hostname"]
        live_if = d["live"]["ifstate"]
        live_bgp = d["live"]["bgp"]
        has_live_bgp = bool(live_bgp) or any("bgp" in s.lower() for s in d["sources"])

        # LAGs
        aes = {n: i for n, i in d["interfaces"].items() if re.match(r"^(ae\d+|reth\d+)$", n) or i["type"] == "aggregate"}
        members = defaultdict(list)
        for i in d["interfaces"].values():
            if i.get("lag"):
                members[i["lag"]].append(i["name"])
        for lag, mem in members.items():
            if lag not in aes:
                find("High", "LAG", H, lag, f"Ports {', '.join(sorted(mem))} are assigned to {lag}, but {lag} has no configuration.",
                     f"Configure {lag} (LACP, family/VLANs) or remove the 802.3ad statements.", "config")
        for lag, i in aes.items():
            if not members.get(lag) and not i["disabled"]:
                find("Medium", "LAG", H, lag, f"{lag} is configured but has no member ports.",
                     "Add member ports or remove the unused LAG.", "config")
            if d["platform"] == "junos" and not i["lacp"] and members.get(lag):
                find("Low", "LAG", H, lag, f"{lag} is a static LAG (no LACP).",
                     "Enable `aggregated-ether-options lacp active` so a miscabled member is detected.", "config")
            if lag in live_if and live_if[lag]["link"] == "down" and not i["disabled"]:
                find("High", "LAG", H, lag, f"{lag} is configured but its link is down.",
                     "Check member ports, LACP state (`show lacp interfaces`) and far-end config.", "live")
            down = [m for m in members.get(lag, []) if m in live_if and live_if[m]["link"] == "down"]
            if down and not (lag in live_if and live_if[lag]["link"] == "down"):
                find("Medium", "LAG", H, lag, f"{lag} is running with member(s) down: {', '.join(down)}.",
                     "Restore the member link(s) to regain redundancy and bandwidth.", "live")
        if d["platform"] == "junos":
            idx = [int(m.group(1)) for n in aes for m in [re.match(r"ae(\d+)$", n)] if m]
            if idx:
                if d["lag_device_count"] is None:
                    find("High", "LAG", H, "chassis", "`chassis aggregated-devices ethernet device-count` is not set; ae interfaces will not be created.",
                         f"Set device-count to at least {max(idx) + 1}.", "config")
                elif max(idx) >= d["lag_device_count"]:
                    find("High", "LAG", H, "chassis", f"device-count is {d['lag_device_count']} but ae{max(idx)} is configured; it will not come up.",
                         f"Raise device-count to at least {max(idx) + 1}.", "config")
        # LAG members going to different neighbors
        by_lag = defaultdict(set)
        for L in links:
            if L["source"] != "LLDP":
                continue
            if L["a"] == k and L["a_lag"]:
                by_lag[L["a_lag"]].add(L["b"])
            if L["b"] == k and L["b_lag"]:
                by_lag[L["b_lag"]].add(L["a"])
        for lag, peers in by_lag.items():
            if len(peers) > 1 and not d["interfaces"].get(lag, {}).get("esi"):
                names = [devices[p]["hostname"] if p in devices else p.removeprefix("ext:") for p in peers]
                find("Medium", "LAG", H, lag, f"Members of {lag} connect to different devices: {', '.join(sorted(names))}.",
                     "Confirm this is an MC-LAG/ESI-LAG or a VC/stack on the far end; otherwise fix cabling.", "LLDP")

        # VLANs and IRBs
        if d["platform"] == "junos":
            used, any_all = set(), False
            for itf, u, ud in iter_units(d):
                used.update(ud["vlans"])
                any_all = any_all or ud["vlans_all"]
                if ud["vlans_undefined"]:
                    find("Medium", "VLAN", H, unit_name(itf, u), f"VLAN member(s) {', '.join(ud['vlans_undefined'])} are not defined under `vlans`.",
                         "Define the VLAN or remove the member reference.", "config")
            unused = [f"{v['name']} ({v['id']})" for v in d["vlans"].values()
                      if v["id"] not in used and not v["l3"] and not any_all]
            if unused:
                find("Low", "VLAN", H, "vlans", f"{len(unused)} VLAN(s) defined but not on any port or IRB: {', '.join(unused[:15])}"
                     + (" ..." if len(unused) > 15 else ""), "Remove stale VLANs or document why they are kept.", "config")
            bound = {v["l3"] for v in d["vlans"].values() if v["l3"]}
            for v in d["vlans"].values():
                if v["l3"]:
                    n, _, u = v["l3"].partition(".")
                    unit = d["interfaces"].get(n, {}).get("units", {}).get(u or "0")
                    if not unit or not unit["inet"]:
                        find("Medium", "VLAN", H, v["l3"], f"VLAN {v['name']} ({v['id']}) points to {v['l3']}, which has no IPv4 address.",
                             "Add the gateway address or remove the l3-interface binding.", "config")
            for itf, u, ud in iter_units(d):
                if itf["name"] in ("irb", "vlan") and ud["inet"] and f"{itf['name']}.{u}" not in bound:
                    find("Medium", "VLAN", H, f"{itf['name']}.{u}", f"{itf['name']}.{u} ({', '.join(ud['inet'])}) is not bound to any VLAN.",
                         "Bind it with `vlans <name> l3-interface` or remove it.", "config")

        # Static routes
        conn = defaultdict(list)
        for itf, u, ud in iter_units(d):
            inst = ud["instance"] if d["platform"] == "junos" else (itf["vdom"] or "root")
            for c in ud["inet"]:
                ii = iface_net(c)
                if ii:
                    conn[inst].append((ii.network, unit_name(itf, u)))
        for rt in d["static_routes"]:
            nh = rt["next_hop"]
            rt["resolves_via"] = ""
            try:
                nh_ip = ipaddress.ip_address(nh)
            except ValueError:
                continue
            if d["platform"] == "fortios" and rt.get("device"):
                devitf = d["interfaces"].get(rt["device"])
                if devitf and not devitf["units"].get("0", {}).get("inet"):
                    rt["resolves_via"] = f"{rt['device']} (no IP; tunnel/DHCP)"
                    continue
            hit = [n for net, n in conn[rt["instance"]] if nh_ip in net]
            if hit:
                rt["resolves_via"] = hit[0]
            elif str(nh_ip) != "0.0.0.0":
                rt["resolves_via"] = "NOT CONNECTED"
                find("Medium", "Routing", H, rt["prefix"], f"Static route {rt['prefix']} via {nh} ({rt['instance']}): next-hop is not on a connected subnet.",
                     "Confirm the next-hop (typo, moved subnet, or recursive route via `resolve`).", "config")

        # BGP
        for (inst, ip), n in d["bgp"]["neighbors"].items():
            if ip.startswith("range"):
                continue
            if not n.get("peer_as_eff"):
                find("Medium", "BGP", H, ip, f"BGP neighbor {ip} ({inst}) has no peer-as in neighbor or group config.",
                     "Set peer-as for the neighbor or its group.", "config")
            st = live_bgp.get(ip)
            n["live_state"] = st["state"] if st else ("not in summary" if has_live_bgp else "")
            n["live_uptime"] = st.get("uptime", "") if st else ""
            if st and st["state"] != "Established":
                find("High", "BGP", H, ip, f"BGP session to {ip} ({n.get('description') or n['peer_device'].removeprefix('ext:')}) is {st['state']}.",
                     "Check reachability of the peer address, AS numbers, authentication and the far end.", "live")

        # Interface live state
        if live_if and d["platform"] == "junos":
            down = [i["name"] for i in d["interfaces"].values()
                    if not i["disabled"] and (i["description"] or i["lag"]) and not re.match(r"^(ae|irb|lo|vlan|em|fxp|me|vme)", i["name"])
                    and i["name"] in live_if and live_if[i["name"]]["link"] == "down" and not i.get("lag")]
            if down:
                find("Medium", "Interfaces", H, ", ".join(down[:12]) + (" ..." if len(down) > 12 else ""),
                     f"{len(down)} described, enabled interface(s) have link down.",
                     "Confirm whether these are expected (spare/decommissioned); disable or update descriptions if so.", "live")
        nodesc = sorted({L["a_if"] for L in links if L["source"] == "LLDP" and L["a"] == k
                         and not (d["interfaces"].get(L["a_if"], {}) or {}).get("description")})
        if nodesc:
            find("Low", "Documentation", H, ", ".join(nodesc[:12]) + (" ..." if len(nodesc) > 12 else ""),
                 f"{len(nodesc)} interface(s) with an LLDP neighbor have no description.",
                 "Add descriptions naming the far-end device and port.", "LLDP")

        # Services
        if d["platform"] in ("junos", "fortios") and d["interfaces"]:
            for svc in ("ntp", "syslog"):
                if not d["services"].get(svc):
                    find("Low", "Management", H, svc, f"No {svc.upper()} server configured.",
                         f"Configure {svc.upper()} (time sync and central logging are needed for incident timelines).", "config")

        # FortiGate specifics
        if d["platform"] == "fortios":
            for i in d["interfaces"].values():
                wanish = i["role"] == "wan" or i["name"].lower().startswith("wan") or i["mode"] in ("dhcp", "pppoe")
                acc = set(i["allowaccess"])
                if wanish and acc & {"http", "telnet"}:
                    find("High", "Firewall", H, i["name"], f"WAN-facing {i['name']} allows {', '.join(sorted(acc & {'http', 'telnet'}))} admin access.",
                         "Remove http/telnet from allowaccess on internet-facing interfaces.", "config")
                elif wanish and acc & {"https", "ssh"}:
                    find("Medium", "Firewall", H, i["name"], f"WAN-facing {i['name']} allows {', '.join(sorted(acc & {'https', 'ssh'}))} admin access.",
                         "Restrict admin to trusted hosts / VPN, or remove from the WAN interface.", "config")
            for p in d["fw"]["policies"]:
                if p["status"] == "disable" or p["action"] != "accept":
                    continue
                allsrc, alldst = "all" in p["srcaddr"], "all" in p["dstaddr"]
                allsvc = "ALL" in p["service"]
                if allsrc and alldst and allsvc:
                    find("High", "Firewall", H, f"policy {p['id']}", f"Policy {p['id']} '{p['name']}' ({','.join(p['srcintf'])} → {','.join(p['dstintf'])}) allows all sources, destinations and services.",
                         "Restrict to required addresses/services or document the business need.", "config")
                elif allsvc and allsrc and any(devices[k]["interfaces"].get(x, {}).get("role") == "wan" or x.lower().startswith("wan") for x in p["srcintf"]):
                    find("High", "Firewall", H, f"policy {p['id']}", f"Policy {p['id']} '{p['name']}' allows ALL services from any internet source.",
                         "Limit inbound services to what the published host needs.", "config")
            nolog = [p["id"] for p in d["fw"]["policies"] if p["action"] == "accept" and p["status"] != "disable" and p["logtraffic"] == "disable"]
            if nolog:
                find("Low", "Firewall", H, "policies", f"{len(nolog)} accept policies have traffic logging disabled: {', '.join(nolog[:15])}.",
                     "Enable logging (at least utm/all) so the SIEM sees allowed sessions.", "config")
            for v in d["fw"]["vips"]:
                if not v["portforward"] and v["type"] == "static-nat":
                    find("Medium", "Firewall", H, f"VIP {v['name']}", f"VIP {v['name']} maps {v['extip']} → {v['mappedip']} on all ports (no port forwarding).",
                         "Confirm a full 1:1 NAT is intended; exposure then depends entirely on policy services.", "config")
            for p1 in d["fw"]["ipsec_p1"]:
                if p1["ike_version"] == "1":
                    find("Low", "VPN", H, p1["name"], f"IPsec tunnel {p1['name']} uses IKEv1.", "Move to IKEv2 when the peer supports it.", "config")
                if re.search(r"\b(des|3des|md5)", p1["proposal"]) or re.search(r"(^|[^\d])(1|2|5)($|\s)", p1["dhgrp"]):
                    find("Medium", "VPN", H, p1["name"], f"IPsec tunnel {p1['name']} offers weak crypto (proposal '{p1['proposal']}', DH '{p1['dhgrp']}').",
                         "Use AES-GCM/AES256 with SHA256+ and DH 14/19/20+.", "config")

    # ---- cross-device: trunk/VLAN consistency across LLDP links
    done = set()
    for L in links:
        if L["source"] != "LLDP" or not L["b_known"]:
            continue
        a, b = devices[L["a"]], devices[L["b"]]
        ai, bi = L["a_lag"] or L["a_if"], L["b_lag"] or L["b_if"]
        key = tuple(sorted([(L["a"], ai), (L["b"], bi)]))
        if key in done:
            continue
        done.add(key)
        va, vb = switch_view(a, ai), switch_view(b, bi)
        if not va or not vb:
            continue
        an, bn = f"{a['hostname']} {ai}", f"{b['hostname']} {bi}"
        modes = {va[0], vb[0]}
        if va[0] != vb[0]:
            find("Medium", "VLAN", f"{a['hostname']}, {b['hostname']}", f"{ai} ⇄ {bi}",
                 f"Port mode mismatch: {an} is {va[0]}, {bn} is {vb[0]}.", "Make both ends the same mode.", "config + LLDP")
        elif modes == {"access"} and va[1] != vb[1]:
            find("High", "VLAN", f"{a['hostname']}, {b['hostname']}", f"{ai} ⇄ {bi}",
                 f"Access VLAN mismatch: {an} is VLAN {vlan_ranges(va[1])}, {bn} is VLAN {vlan_ranges(vb[1])}.",
                 "Put both ends in the same VLAN.", "config + LLDP")
        elif modes == {"trunk"} and not va[2] and not vb[2]:
            only_a, only_b = va[1] - vb[1], vb[1] - va[1]
            if only_a or only_b:
                parts = []
                if only_a:
                    parts.append(f"VLAN {vlan_ranges(only_a)} allowed on {an} but not {bn}")
                if only_b:
                    parts.append(f"VLAN {vlan_ranges(only_b)} allowed on {bn} but not {an}")
                find("Medium", "VLAN", f"{a['hostname']}, {b['hostname']}", f"{ai} ⇄ {bi}",
                     "Trunk VLAN mismatch: " + "; ".join(parts) + ".",
                     "Add the missing VLAN(s) to the trunk on the far end, or prune both ends if the VLAN is not needed there.",
                     "config + LLDP")
            if va[3] and vb[3] and str(va[3]) != str(vb[3]) and "untagged" not in (va[3], vb[3]):
                find("Medium", "VLAN", f"{a['hostname']}, {b['hostname']}", f"{ai} ⇄ {bi}",
                     f"Native VLAN mismatch: {an} native {va[3]}, {bn} native {vb[3]}.", "Match the native VLAN on both ends.", "config + LLDP")

    # ---- cross-device: VLAN naming drift
    by_id = defaultdict(set)
    for d in devices.values():
        for v in d["vlans"].values():
            if isinstance(v["id"], int):
                by_id[v["id"]].add(v["name"])
    drift = {i: n for i, n in by_id.items() if len(n) > 1}
    if drift:
        find("Low", "VLAN", "multiple", "naming", "Same VLAN ID has different names across devices: " +
             "; ".join(f"{i}: {', '.join(sorted(n))}" for i, n in sorted(drift.items())[:10]),
             "Standardize VLAN names so the documentation and configs read the same everywhere.", "config")

    # ---- networks table
    vlan_by_irb = {}
    for k, d in devices.items():
        for v in d["vlans"].values():
            if v["l3"]:
                vlan_by_irb[(k, v["l3"] if "." in v["l3"] else v["l3"] + ".0")] = v
    for net, members in sorted(nets.items(), key=lambda x: (x[0].version, x[0])):
        vlan, desc, kinds = "", [], set()
        for (k, ifn, ip, inst) in members:
            d = devices[k]
            v = vlan_by_irb.get((k, ifn)) or vlan_by_irb.get((k, ifn + ".0"))
            if v:
                vlan = f"{v['id']} {v['name']}"
            base = ifn.split(".")[0]
            itf = d["interfaces"].get(base) or d["interfaces"].get(ifn)
            if itf:
                if itf.get("fw_vlanid"):
                    vlan = vlan or str(itf["fw_vlanid"])
                ud = itf["units"].get(ifn.split(".")[1] if "." in ifn else "0", {})
                dsc = (ud or {}).get("description") or itf.get("description")
                if dsc and dsc not in desc:
                    desc.append(dsc)
            if base.startswith("lo"):
                kinds.add("Loopback")
            elif MGMT_IFS.match(base):
                kinds.add("Management")
        if not kinds:
            if net.prefixlen in (30, 31, 127):
                kinds.add("Point-to-point")
            elif net.prefixlen == net.max_prefixlen:
                kinds.add("Host")
            else:
                kinds.add("LAN / VLAN")
        model["networks"].append({
            "subnet": str(net), "prefixlen": net.prefixlen, "type": "/".join(sorted(kinds)), "vlan": vlan,
            "addresses": "; ".join(f"{devices[k]['hostname']} {ifn} = {ip}" for k, ifn, ip, inst in members),
            "instances": ", ".join(sorted({inst for *_, inst in members})),
            "description": " | ".join(desc[:3]),
            "usable_hosts": max(net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0), 0)})

    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    F.sort(key=lambda f: (order[f["severity"]], f["category"], f["device"], f["object"]))
    return model

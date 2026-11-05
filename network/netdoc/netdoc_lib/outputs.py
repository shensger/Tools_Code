"""Build tables, workbook, topology (JSON + Mermaid) and the report draft."""
import csv
import datetime as dt
import json
import os
import re
from collections import defaultdict, Counter
from .analyze import TIER, iter_units, unit_name, switch_view
from .common import vlan_ranges

SEV_FILL = {"High": "F8CBAD", "Medium": "FFE699", "Low": "DDEBF7", "Info": "EDEDED"}


def _name(model, key):
    d = model["devices"].get(key)
    return d["hostname"] if d else key.removeprefix("ext:")


# ------------------------------------------------------------------ tables
def build_tables(model):
    devs = model["devices"]
    T = {}
    lldp_peer = {}
    for L in model["links"]:
        if L["source"] != "LLDP":
            continue
        lldp_peer[(L["a"], L["a_if"])] = f"{_name(model, L['b'])} {L['b_if']}".strip()
        if L["b_known"]:
            lldp_peer[(L["b"], L["b_if"])] = f"{_name(model, L['a'])} {L['a_if']}".strip()

    T["Devices"] = [{
        "Hostname": d["hostname"], "Platform": {"junos": "Juniper Junos", "fortios": "FortiGate FortiOS"}[d["platform"]],
        "Model": d["model"], "Version": d["version"], "Role": d["role"].title(), "Mgmt IP": d["mgmt_ip"],
        "Router ID": d["router_id"], "Local AS": d["asn"],
        "Virtual Chassis": "; ".join(f"m{m['member']} {m.get('role', '')} {m.get('serial', '')}".strip() for m in d["vc"]["members"].values())
        or "; ".join(f"m{m['member']} {m['role']} {m['serial']} {m['status']}" for m in d["vc"].get("live", [])),
        "HA": d["services"].get("ha", ""), "VDOMs": ", ".join(d["fw"]["vdoms"]),
        "Interfaces": len(d["interfaces"]), "VLANs": len(d["vlans"]),
        "NTP": ", ".join(d["services"].get("ntp", [])), "Syslog": ", ".join(d["services"].get("syslog", [])),
        "Last commit": d["last_commit"],
        "Live data": ", ".join(x for x, ok in (("LLDP", d["live"]["lldp"]), ("BGP", d["live"]["bgp"]), ("Interface state", d["live"]["ifstate"])) if ok) or "none",
        "Notes": " ".join(d["notes"]),
    } for d in sorted(devs.values(), key=lambda d: (TIER.get(d["role"], 9), d["hostname"]))]

    rows = []
    for k, d in sorted(devs.items(), key=lambda x: x[1]["hostname"]):
        live = d["live"]["ifstate"]
        for itf, u, ud in sorted(iter_units(d), key=lambda x: (_ifsort(x[0]["name"]), _ifsort(x[1]))):
            full = unit_name(itf, u)
            sv = switch_view(d, itf["name"]) if u == "0" else None
            st = live.get(full) or (live.get(itf["name"]) if u == "0" else None) or {}
            rows.append({
                "Device": d["hostname"], "Interface": full,
                "Description": ud["description"] or (itf["description"] if u == "0" else ""),
                "Config": "disabled" if itf["disabled"] or ud["disabled"] else "enabled",
                "Admin/Link (live)": f"{st.get('admin', '')}/{st.get('link', '')}" if st else "",
                "LAG": itf.get("lag") or "", "Mode": (sv[0] if sv else ("tagged sub-if" if ud["vlan_id"] else "")),
                "Access/Native VLAN": (vlan_ranges(sv[1]) if sv and sv[0] == "access" else (str(sv[3]) if sv else "")),
                "Trunk VLANs": ("all" if sv and sv[2] else (vlan_ranges(sv[1]) if sv and sv[0] == "trunk" else
                                (str(itf["fw_vlanid"] or ud["vlan_id"] or "")))),
                "IPv4": ", ".join(ud["inet"]), "IPv6": ", ".join(ud["inet6"]),
                "LLDP neighbor": lldp_peer.get((k, full), ""),
                "Instance/VDOM": ud["instance"] if d["platform"] == "junos" else itf["vdom"],
                "Zone/Role": " ".join(x for x in (itf.get("zone"), itf.get("role")) if x),
                "Admin access": " ".join(itf.get("allowaccess", [])),
            })
        # physical ports present only in live/LLDP data
        for name, st in sorted(live.items(), key=lambda x: _ifsort(x[0])):
            if name.split(".")[0] in d["interfaces"] or "." in name:
                continue
            if (k, name) in lldp_peer or st.get("link") == "up":
                if re.match(r"^(xe|et|ge|mge|port|wan|x|lan|internal)", name):
                    rows.append({"Device": d["hostname"], "Interface": name, "Description": "",
                                 "Config": "not configured", "Admin/Link (live)": f"{st['admin']}/{st['link']}",
                                 "LAG": "", "Mode": "", "Access/Native VLAN": "", "Trunk VLANs": "", "IPv4": "", "IPv6": "",
                                 "LLDP neighbor": lldp_peer.get((k, name), ""), "Instance/VDOM": "", "Zone/Role": "", "Admin access": ""})
    T["Interfaces"] = rows

    lags = []
    for k, d in sorted(devs.items(), key=lambda x: x[1]["hostname"]):
        mem = defaultdict(list)
        for i in d["interfaces"].values():
            if i.get("lag"):
                mem[i["lag"]].append(i["name"])
        peers = defaultdict(set)
        for L in model["links"]:
            if L["source"] == "LLDP" and L["a"] == k and L["a_lag"]:
                peers[L["a_lag"]].add(f"{_name(model, L['b'])} {L['b_lag'] or L['b_if']}")
            if L["source"] == "LLDP" and L["b"] == k and L["b_lag"]:
                peers[L["b_lag"]].add(f"{_name(model, L['a'])} {L['a_lag'] or L['a_if']}")
        for n, i in sorted(d["interfaces"].items(), key=lambda x: _ifsort(x[0])):
            if not (re.match(r"^(ae|reth)\d+$", n) or i["type"] == "aggregate" or n in mem):
                continue
            sv = switch_view(d, n)
            st = d["live"]["ifstate"].get(n, {})
            lags.append({"Device": d["hostname"], "LAG": n, "Description": i["description"],
                         "Members": ", ".join(sorted(mem.get(n, []), key=_ifsort)), "Member count": len(mem.get(n, [])),
                         "LACP": i["lacp"] or ("static" if d["platform"] == "junos" else ""), "Min links": i["min_links"],
                         "Mode": sv[0] if sv else "", "VLANs": ("all" if sv and sv[2] else vlan_ranges(sv[1]) if sv else ""),
                         "IPv4": ", ".join(x for u in i["units"].values() for x in u["inet"]),
                         "Far end (LLDP)": "; ".join(sorted(peers.get(n, []))),
                         "Live link": st.get("link", "")})
    T["LAGs"] = lags

    vl = defaultdict(lambda: {"names": set(), "devices": set(), "gw": [], "access": Counter(), "trunks": [], "desc": set()})
    for k, d in devs.items():
        for v in d["vlans"].values():
            if not isinstance(v["id"], int):
                continue
            r = vl[v["id"]]
            r["names"].add(v["name"])
            r["devices"].add(d["hostname"])
            if v["description"]:
                r["desc"].add(v["description"])
            if v["l3"]:
                n, _, u = v["l3"].partition(".")
                ud = d["interfaces"].get(n, {}).get("units", {}).get(u or "0")
                if ud and ud["inet"]:
                    r["gw"].append(f"{d['hostname']} {v['l3']} {', '.join(ud['inet'])}" + (f" (VIP {', '.join(ud['vips'])})" if ud["vips"] else ""))
        for itf, u, ud in iter_units(d):
            if d["platform"] != "junos" or u != "0":
                continue
            sv = switch_view(d, itf["name"])
            if not sv or itf["name"].startswith("irb"):
                continue
            if sv[0] == "access":
                for vid in sv[1]:
                    vl[vid]["access"][d["hostname"]] += 1
            elif sv[0] == "trunk":
                for vid in sv[1]:
                    vl[vid]["trunks"].append(f"{d['hostname']} {itf['name']}")
        if d["platform"] == "fortios":
            for i in d["interfaces"].values():
                if i["fw_vlanid"]:
                    r = vl[i["fw_vlanid"]]
                    r["names"].add(i["name"])
                    r["devices"].add(d["hostname"])
                    ips = ", ".join(i["units"].get("0", {}).get("inet", []))
                    r["gw"].append(f"{d['hostname']} {i['name']} on {i['parent']}" + (f" {ips}" if ips else ""))
    T["VLANs"] = [{"VLAN ID": vid, "Name(s)": ", ".join(sorted(r["names"])), "Description": "; ".join(sorted(r["desc"])),
                   "Defined on": ", ".join(sorted(r["devices"])), "L3 gateway(s)": "; ".join(r["gw"]),
                   "Access ports": "; ".join(f"{h}: {c}" for h, c in sorted(r["access"].items())),
                   "Trunks carrying": len(r["trunks"]),
                   "Trunk list": ", ".join(r["trunks"][:40]) + (" ..." if len(r["trunks"]) > 40 else "")}
                  for vid, r in sorted(vl.items())]

    T["IP Plan"] = [{"Subnet": n["subnet"], "Type": n["type"], "VLAN": n["vlan"], "Assigned": n["addresses"],
                     "Instance/VDOM": n["instances"], "Description": n["description"], "Usable hosts": n["usable_hosts"]}
                    for n in model["networks"]]

    T["Static Routes"] = [{"Device": d["hostname"], "Instance/VDOM": r["instance"], "Prefix": r["prefix"],
                           "Next hop": r["next_hop"] or (f"via {r.get('device')}" if r["type"] == "interface" else r["type"]), "Egress (FortiGate)": r.get("device", ""),
                           "Type": ("qualified " if r.get("qualified") else "") + r["type"],
                           "Preference/Distance": r["preference"], "Resolves via": r.get("resolves_via", ""),
                           "Status": "disabled" if r.get("disabled") else "", "Comment": r.get("comment", "")}
                          for d in sorted(devs.values(), key=lambda d: d["hostname"]) for r in d["static_routes"]]

    bg = []
    for d in sorted(devs.values(), key=lambda d: d["hostname"]):
        for (inst, ip), n in sorted(d["bgp"]["neighbors"].items()):
            g = d["bgp"]["groups"].get((inst, n["group"]), {})
            bg.append({"Device": d["hostname"], "Instance/VDOM": inst, "Group": n["group"], "Type": n.get("type_eff", ""),
                       "Local AS": g.get("local_as") or d["asn"], "Peer IP": ip, "Peer AS": n.get("peer_as_eff", ""),
                       "Peer": _name(model, n.get("peer_device", "")), "Description": n["description"],
                       "Local address": n["local_address"] or g.get("local_address", ""),
                       "Import": ", ".join(g.get("import", [])), "Export": ", ".join(g.get("export", [])),
                       "Live state": n.get("live_state", ""), "Up/Down": n.get("live_uptime", "")})
    T["BGP"] = bg

    T["Links"] = [{"Device A": _name(model, L["a"]), "Port A": L["a_if"], "LAG A": L["a_lag"],
                   "Device B": _name(model, L["b"]), "Port B": L["b_if"], "LAG B": L["b_lag"],
                   "Source": L["source"], "Seen from both ends": "yes" if L["confirmed"] else "",
                   "B is documented device": "yes" if L["b_known"] else "no"} for L in model["links"]]

    T["Findings"] = [{"Severity": f["severity"], "Category": f["category"], "Device": f["device"], "Object": f["object"],
                      "Finding": f["finding"], "Recommendation": f["recommendation"], "Evidence": f["evidence"]}
                     for f in model["findings"]]

    fw = [d for d in devs.values() if d["platform"] == "fortios"]
    if fw:
        T["FW Policies"] = [{"Device": d["hostname"], "VDOM": p["vdom"], "ID": p["id"], "Name": p["name"],
                             "From": ", ".join(p["srcintf"]), "To": ", ".join(p["dstintf"]),
                             "Source": ", ".join(p["srcaddr"]), "Destination": ", ".join(p["dstaddr"]),
                             "Service": ", ".join(p["service"]), "Action": p["action"], "NAT": "yes" if p["nat"] else "",
                             "Status": p["status"], "Log": p["logtraffic"], "Comments": p["comments"]}
                            for d in fw for p in d["fw"]["policies"]]
        T["FW VIPs"] = [{"Device": d["hostname"], "VDOM": v["vdom"], "Name": v["name"], "Ext interface": v["extintf"],
                         "External IP": v["extip"], "Mapped IP": v["mappedip"],
                         "Ports": f"{v['protocol']} {v['extport']} → {v['mappedport'] or v['extport']}" if v["portforward"] else "all ports",
                         "Comment": v["comment"]} for d in fw for v in d["fw"]["vips"]]
        T["IPsec"] = [{"Device": d["hostname"], "VDOM": p["vdom"], "Tunnel": p["name"], "Interface": p["interface"],
                       "Remote gateway": p["remote_gw"], "IKE": f"v{p['ike_version']}", "Proposal": p["proposal"],
                       "DH": p["dhgrp"],
                       "Phase 2 selectors": "; ".join(f"{q['src']} ⇄ {q['dst']}" for q in d["fw"]["ipsec_p2"] if q["phase1"] == p["name"]),
                       "Comments": p["comments"]} for d in fw for p in d["fw"]["ipsec_p1"]]
        T["FW Zones"] = [{"Device": d["hostname"], "Zone": z["name"], "VDOM": z["vdom"],
                          "Interfaces": ", ".join(z["interfaces"]), "Intrazone": z["intrazone"]}
                         for d in fw for z in d["fw"]["zones"].values()]
    return T


def _ifsort(name):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", str(name))]


# ------------------------------------------------------------------ topology
def build_topology(model):
    devs = model["devices"]
    nodes, edges = {}, {}
    for k, d in devs.items():
        nodes[k] = {"id": k, "label": d["hostname"], "kind": "device", "role": d["role"], "platform": d["platform"],
                    "model": d["model"], "mgmt_ip": d["mgmt_ip"], "tier": TIER.get(d["role"], 4)}

    def edge(a, b, label, src, extra=None):
        key = tuple(sorted([a, b]))
        e = edges.setdefault(key, {"a": key[0], "b": key[1], "labels": [], "sources": set(), "members": 0,
                                   "confirmed": False})
        if label and label not in e["labels"]:
            e["labels"].append(label)
        e["sources"].add(src)
        if extra:
            e["members"] += extra.get("members", 0)
            e["confirmed"] = e["confirmed"] or extra.get("confirmed", False)

    lag_seen = set()
    for L in model["links"]:
        a, b = L["a"], L["b"]
        if b not in nodes:
            nodes[b] = {"id": b, "label": b.removeprefix("ext:"), "kind": "external", "role": "endpoint",
                        "platform": "", "model": "", "mgmt_ip": "", "tier": TIER["endpoint"]}
        if L["source"] == "LLDP":
            ai, bi = L["a_lag"] or L["a_if"], L["b_lag"] or L["b_if"]
            key = (tuple(sorted([(a, ai), (b, bi)])))
            label = f"{ai} ⇄ {bi}" if bi else ai
            if (L["a_lag"] or L["b_lag"]):
                if key in lag_seen:
                    edges[tuple(sorted([a, b]))]["members"] += 1
                    continue
                lag_seen.add(key)
            edge(a, b, label, "LLDP", {"members": 1, "confirmed": L["confirmed"]})
        elif L["source"].startswith("Shared subnet"):
            edge(a, b, f"L3 {L['source'].split()[-1]}", "subnet")
        else:
            edge(a, b, f"{L['a_if']} (per description)", "description")
    for ek, ext in model["external"].items():
        nodes[ek] = {"id": ek, "label": ext["label"], "kind": "external", "role": "external", "platform": "",
                     "model": "", "mgmt_ip": "", "tier": TIER["external"]}
        for k, ip in ext["peers"]:
            st = devs[k]["bgp"]["neighbors"]
            state = next((n.get("live_state", "") for (i, p), n in st.items() if p == ip), "")
            edge(k, ek, f"eBGP {ip}" + (f" [{state}]" if state else ""), "bgp")
    for k, d in devs.items():
        for (inst, ip), n in d["bgp"]["neighbors"].items():
            pd_ = n.get("peer_device", "")
            if pd_ in devs:
                edge(k, pd_, f"{'iBGP' if n.get('type_eff') == 'internal' else 'eBGP'} {ip}", "bgp")

    # layered layout
    tiers = defaultdict(list)
    for n in nodes.values():
        tiers[n["tier"]].append(n)
    for t, ns in tiers.items():
        ns.sort(key=lambda n: n["label"])
        width = max(len(ns), 1)
        for i, n in enumerate(ns):
            n["x"] = int((i - (width - 1) / 2) * 260)
            n["y"] = int(t * 200)
    out_edges = []
    for e in edges.values():
        e["sources"] = sorted(e["sources"])
        lbl = "; ".join(e["labels"][:3]) + (f" +{len(e['labels']) - 3}" if len(e["labels"]) > 3 else "")
        if e["members"] > 1:
            lbl += f" ({e['members']} links)"
        e["label"] = lbl
        e["style"] = "solid" if "LLDP" in e["sources"] else ("dashed" if "bgp" in e["sources"] or "subnet" in e["sources"] else "dotted")
        out_edges.append(e)
    return {"nodes": list(nodes.values()), "edges": out_edges,
            "legend": {"solid": "physical link seen by LLDP", "dashed": "L3 adjacency / BGP session from config",
                       "dotted": "inferred from interface description only"}}


def mermaid(topo):
    def nid(s):
        return re.sub(r"[^A-Za-z0-9_]", "_", s)
    names = {0: "External / WAN", 1: "Firewalls", 2: "Core", 3: "Distribution", 4: "Access", 5: "Attached endpoints"}
    lines = ["flowchart TB"]
    tiers = defaultdict(list)
    for n in topo["nodes"]:
        tiers[n["tier"]].append(n)
    for t in sorted(tiers):
        lines.append(f'  subgraph T{t}["{names.get(t, "Other")}"]')
        for n in tiers[t]:
            sub = "<br/>".join(x for x in (n["model"], n["mgmt_ip"]) if x)
            text = n["label"] + (f"<br/><small>{sub}</small>" if sub else "")
            shape = (f'(["{text}"])' if n["kind"] == "external" else f'["{text}"]')
            lines.append(f"    {nid(n['id'])}{shape}")
        lines.append("  end")
    for e in topo["edges"]:
        arrow = {"solid": "---", "dashed": "-.-", "dotted": "-.-"}[e["style"]]
        lbl = e["label"].replace('"', "'")
        lines.append(f'  {nid(e["a"])} {arrow}|"{lbl}"| {nid(e["b"])}')
    lines += ["  classDef firewall fill:#fde2e1,stroke:#c0392b", "  classDef core fill:#dbe9f7,stroke:#1f5f99",
              "  classDef distribution fill:#e3f1e3,stroke:#2e7d32", "  classDef access fill:#f3f3f3,stroke:#666",
              "  classDef external fill:#fff7e0,stroke:#b8860b,stroke-dasharray:4 3"]
    for n in topo["nodes"]:
        cls = n["role"] if n["kind"] == "device" else "external"
        lines.append(f"  class {nid(n['id'])} {cls}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ workbook
def write_workbook(T, path, meta):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    hdr = PatternFill("solid", fgColor="1F3864")
    thin = Side(style="thin", color="D9D9D9")
    ws["A1"] = meta["title"]
    ws["A1"].font = Font(size=16, bold=True, color="1F3864")
    r = 3
    for k, v in meta["summary"]:
        ws.cell(r, 1, k).font = Font(bold=True)
        ws.cell(r, 2, v)
        r += 1
    r += 1
    ws.cell(r, 1, "Findings by severity").font = Font(bold=True, size=12)
    r += 1
    for sev in ("High", "Medium", "Low"):
        n = sum(1 for f in T["Findings"] if f["Severity"] == sev)
        c = ws.cell(r, 1, sev)
        c.fill = PatternFill("solid", fgColor=SEV_FILL[sev])
        ws.cell(r, 2, n)
        r += 1
    r += 1
    ws.cell(r, 1, "Top findings").font = Font(bold=True, size=12)
    r += 1
    for f in T["Findings"][:10]:
        ws.cell(r, 1, f["Severity"]).fill = PatternFill("solid", fgColor=SEV_FILL[f["Severity"]])
        ws.cell(r, 2, f"{f['Device']}: {f['Finding']}").alignment = Alignment(wrap_text=True, vertical="top")
        r += 1
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 110

    order = ["Findings", "Devices", "Links", "LAGs", "Interfaces", "VLANs", "IP Plan", "Static Routes", "BGP",
             "FW Zones", "FW Policies", "FW VIPs", "IPsec"]
    for name in order:
        rows = T.get(name)
        if rows is None:
            continue
        ws = wb.create_sheet(name)
        cols = list(rows[0].keys()) if rows else ["(none)"]
        for j, c in enumerate(cols, 1):
            cell = ws.cell(1, j, c)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = hdr
            cell.alignment = Alignment(vertical="center", wrap_text=True)
        widths = [len(c) + 2 for c in cols]
        for i, row in enumerate(rows, 2):
            for j, c in enumerate(cols, 1):
                v = row.get(c, "")
                cell = ws.cell(i, j, v)
                cell.border = Border(bottom=thin)
                cell.alignment = Alignment(vertical="top", wrap_text=len(str(v)) > 60)
                widths[j - 1] = min(max(widths[j - 1], len(str(v)) + 2), 70)
            if name == "Findings":
                ws.cell(i, 1).fill = PatternFill("solid", fgColor=SEV_FILL.get(row["Severity"], "FFFFFF"))
            if name == "Interfaces" and str(row.get("Admin/Link (live)", "")).endswith("/down") and row.get("Config") == "enabled":
                ws.cell(i, cols.index("Admin/Link (live)") + 1).font = Font(color="C00000", bold=True)
        for j, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(j)].width = max(w, 8)
        ws.freeze_panes = "A2"
        if rows:
            ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}{len(rows) + 1}"
    wb.save(path)


def write_csvs(T, outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, rows in T.items():
        fn = os.path.join(outdir, re.sub(r"\W+", "_", name.lower()).strip("_") + ".csv")
        with open(fn, "w", newline="", encoding="utf-8") as f:
            if not rows:
                f.write("(none)\n")
                continue
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


# ------------------------------------------------------------------ report draft
def _md_table(rows, cols=None, limit=None):
    if not rows:
        return "_None found._\n"
    cols = cols or list(rows[0].keys())
    shown = rows[:limit] if limit else rows
    esc = lambda v: str(v).replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    out += ["| " + " | ".join(esc(r.get(c, "")) for c in cols) + " |" for r in shown]
    if limit and len(rows) > limit:
        out.append(f"\n_{len(rows) - limit} more rows in the workbook._")
    return "\n".join(out) + "\n"


def write_report(T, model, meta, path):
    devs = model["devices"]
    sev = Counter(f["Severity"] for f in T["Findings"])
    fw = any(d["platform"] == "fortios" for d in devs.values())
    s = []
    s.append(f"# {meta['title']}\n")
    s.append(f"**Site / scope:** {meta['site'] or '_[site]_'}  \n**Prepared:** {meta['date']}  \n**Prepared by:** {meta['author']}  \n"
             f"**Sources:** {meta['sources']}\n")
    s.append("## 1. Executive summary\n")
    s.append("<!-- CLAUDE: replace this comment with 3-5 sentences: what the network is, how it is built, its health, and the 2-3 findings that matter most. -->\n")
    s.append(f"- Devices documented: {len(devs)} ({', '.join(f'{c} {r}' for r, c in Counter(d['role'] for d in devs.values()).items())})\n"
             f"- Physical links mapped: {sum(1 for L in model['links'] if L['source'] == 'LLDP')} (LLDP), "
             f"{sum(1 for L in model['links'] if L['source'] != 'LLDP')} inferred\n"
             f"- VLANs: {len(T['VLANs'])} · Subnets: {len(T['IP Plan'])} · BGP sessions: {len(T['BGP'])} · Static routes: {len(T['Static Routes'])}\n"
             f"- Findings: {sev.get('High', 0)} high, {sev.get('Medium', 0)} medium, {sev.get('Low', 0)} low\n")
    s.append("## 2. Topology\n")
    s.append("<!-- CLAUDE: insert the topology diagram here (Excalidraw / Mermaid) and describe the layout in 2-4 sentences: tiers, uplinks, WAN/cloud edges, redundancy. -->\n")
    s.append("Legend: solid = physical link seen by LLDP; dashed = L3/BGP adjacency from config; dotted = inferred from description only.\n")
    s.append("## 3. Device inventory\n")
    s.append(_md_table(T["Devices"], ["Hostname", "Platform", "Model", "Version", "Role", "Mgmt IP", "Router ID", "Local AS", "Virtual Chassis", "HA"]))
    s.append("## 4. Physical connectivity\n### 4.1 Inter-device links\n")
    s.append(_md_table([r for r in T["Links"] if r["B is documented device"] == "yes" or r["Source"] != "LLDP"],
                       ["Device A", "Port A", "LAG A", "Device B", "Port B", "LAG B", "Source", "Seen from both ends"], 80))
    s.append("### 4.2 Link aggregation (LAG)\n")
    s.append(_md_table(T["LAGs"], ["Device", "LAG", "Description", "Members", "LACP", "Mode", "VLANs", "IPv4", "Far end (LLDP)", "Live link"], 60))
    s.append("### 4.3 Other attached systems (LLDP)\n")
    s.append(_md_table([r for r in T["Links"] if r["B is documented device"] == "no"], ["Device A", "Port A", "Device B", "Port B"], 60))
    s.append("## 5. Layer 2 — VLANs\n")
    s.append(_md_table(T["VLANs"], ["VLAN ID", "Name(s)", "Description", "Defined on", "L3 gateway(s)", "Access ports", "Trunks carrying"], 120))
    s.append("## 6. Layer 3 — IP addressing plan\n")
    s.append(_md_table(T["IP Plan"], ["Subnet", "Type", "VLAN", "Assigned", "Instance/VDOM", "Description"], 150))
    s.append("## 7. Routing\n### 7.1 BGP\n")
    s.append("<!-- CLAUDE: one paragraph on the BGP design (ASNs, who peers with whom, cloud/WAN edges, live state). -->\n")
    s.append(_md_table(T["BGP"], ["Device", "Instance/VDOM", "Group", "Type", "Local AS", "Peer IP", "Peer AS", "Peer", "Description", "Live state"]))
    s.append("### 7.2 Static routes\n")
    s.append(_md_table(T["Static Routes"], ["Device", "Instance/VDOM", "Prefix", "Next hop", "Egress (FortiGate)", "Preference/Distance", "Resolves via"], 120))
    if fw:
        s.append("## 8. Security edge (FortiGate)\n### 8.1 Interfaces and zones\n")
        fwnames = {d["hostname"] for d in devs.values() if d["platform"] == "fortios"}
        s.append(_md_table([r for r in T["Interfaces"] if r["Device"] in fwnames],
                           ["Device", "Interface", "Description", "Mode", "Trunk VLANs", "IPv4", "Zone/Role", "Admin access"], 80))
        s.append("### 8.2 Published services (VIP / NAT)\n")
        s.append(_md_table(T.get("FW VIPs", [])))
        s.append("### 8.3 IPsec tunnels\n")
        s.append(_md_table(T.get("IPsec", [])))
        s.append("### 8.4 Policy summary\n")
        pol = T.get("FW Policies", [])
        s.append(f"{len(pol)} policies ({sum(1 for p in pol if p['Status'] == 'disable')} disabled). Full list is in the workbook.\n")
    n = 9 if fw else 8
    s.append(f"## {n}. Findings and recommendations\n")
    s.append("<!-- CLAUDE: open with 2-3 sentences prioritising the high findings; keep the table. -->\n")
    s.append(_md_table(T["Findings"], ["Severity", "Category", "Device", "Object", "Finding", "Recommendation"]))
    s.append(f"## {n + 1}. Data sources and gaps\n")
    s.append(_md_table([{"File": a, "Device/host": b, "Recognized as": c} for a, b, c in meta["inventory"]]))
    gaps = meta["gaps"]
    s.append("\n**Gaps:**\n" + ("\n".join(f"- {g}" for g in gaps) if gaps else "- None noted.") + "\n")
    s.append("\nPer-device port maps are in the workbook (Interfaces tab).\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(s))


def write_model_json(model, path):
    def conv(o):
        if isinstance(o, dict):
            return {(" | ".join(k) if isinstance(k, tuple) else str(k)): conv(v) for k, v in o.items() if not str(k).startswith("_")}
        if isinstance(o, (list, tuple)):
            return [conv(x) for x in o]
        if isinstance(o, set):
            return sorted(o)
        return o
    with open(path, "w", encoding="utf-8") as f:
        json.dump(conv(model), f, indent=1, default=str)

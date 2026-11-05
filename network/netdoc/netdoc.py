#!/usr/bin/env python3
"""netdoc - build network documentation from Juniper (Junos) and FortiGate (FortiOS)
configs plus optional live show-command output.

Usage:
  python3 netdoc.py INPUT [INPUT ...] -o OUTDIR [--title T] [--site S] [--author A]

INPUT is a folder or files. Each file may be:
  * a config  (Junos `show configuration | display set` or curly-brace; FortiOS `show`)
  * one show-command output (host taken from the file name: HOST__command.txt)
  * a whole CLI session log with prompts (user@host> show ... / HOST # get ...)

Outputs in OUTDIR:
  network_documentation.xlsx   workbook (Findings, Devices, Links, LAGs, Interfaces, VLANs, IP Plan, ...)
  tables/*.csv                 every workbook tab as CSV (for Sheets artifacts / other tools)
  report.md                    document draft with all tables filled in
  topology.json / topology.mmd diagram data (nodes with layered x/y, edges) and Mermaid source
  model.json                   full normalized model (no secrets)
"""
import argparse
import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netdoc_lib import analyze as A  # noqa: E402
from netdoc_lib import outputs as O  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--title", default="Network Infrastructure Documentation")
    ap.add_argument("--site", default="")
    ap.add_argument("--author", default="")
    args = ap.parse_args()

    devices, inventory, unrecognized = A.load(args.inputs)
    if not devices:
        print("ERROR: no Junos/FortiOS configs or recognized show output found.", file=sys.stderr)
        for f, why in unrecognized:
            print(f"  skipped {f}: {why}", file=sys.stderr)
        sys.exit(2)
    model = A.analyze(devices)
    T = O.build_tables(model)
    topo = O.build_topology(model)

    gaps = []
    for d in devices.values():
        if not d["interfaces"]:
            gaps.append(f"{d['hostname']}: no configuration collected (live data only).")
        missing = [x for x, ok in (("LLDP", d["live"]["lldp"]), ("interface state", d["live"]["ifstate"]),
                                   ("BGP summary", d["live"]["bgp"] or not d["bgp"]["neighbors"])) if not ok]
        if missing:
            gaps.append(f"{d['hostname']}: no live {', '.join(missing)} - links/state for this device are from config only.")
        for n in d["notes"]:
            gaps.append(f"{d['hostname']}: {n}")
    unknown_lldp = sorted({L["remote_name"] for L in model["links"] if L["source"] == "LLDP" and not L["b_known"]})
    if unknown_lldp:
        gaps.append("LLDP neighbors not in this document set (servers, storage, other switches): " + ", ".join(unknown_lldp[:25])
                    + (" ..." if len(unknown_lldp) > 25 else ""))
    for f, why in unrecognized:
        gaps.append(f"Skipped {f}: {why}.")

    os.makedirs(args.out, exist_ok=True)
    date = dt.date.today().isoformat()
    meta = {"title": args.title, "site": args.site, "author": args.author or "_[author]_", "date": date,
            "sources": f"{len(inventory)} captures from {len(devices)} devices (see section: Data sources)",
            "inventory": inventory, "gaps": gaps,
            "summary": [("Site / scope", args.site), ("Generated", date), ("Devices", len(devices)),
                        ("Links (LLDP)", sum(1 for L in model["links"] if L["source"] == "LLDP")),
                        ("VLANs", len(T["VLANs"])), ("Subnets", len(T["IP Plan"])),
                        ("BGP sessions", len(T["BGP"])), ("Static routes", len(T["Static Routes"])),
                        ("Data gaps", len(gaps))]}

    O.write_workbook(T, os.path.join(args.out, "network_documentation.xlsx"), meta)
    O.write_csvs(T, os.path.join(args.out, "tables"))
    O.write_report(T, model, meta, os.path.join(args.out, "report.md"))
    import json
    with open(os.path.join(args.out, "topology.json"), "w") as f:
        json.dump(topo, f, indent=1)
    with open(os.path.join(args.out, "topology.mmd"), "w") as f:
        f.write(O.mermaid(topo))
    O.write_model_json(model, os.path.join(args.out, "model.json"))

    # console summary for Claude
    print(f"Devices: {len(devices)}")
    for d in sorted(devices.values(), key=lambda d: d['hostname']):
        print(f"  {d['hostname']:<28} {d['platform']:<8} {d['role']:<13} {d['model'] or '-':<16} "
              f"if={len(d['interfaces'])} vlans={len(d['vlans'])} bgp={len(d['bgp']['neighbors'])} "
              f"routes={len(d['static_routes'])} lldp={len(d['live']['lldp'])} ifstate={len(d['live']['ifstate'])}")
    sev = {}
    for f in model["findings"]:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    print(f"Links: {len(model['links'])}  Subnets: {len(T['IP Plan'])}  VLANs: {len(T['VLANs'])}  "
          f"Findings: {sev.get('High', 0)} high / {sev.get('Medium', 0)} medium / {sev.get('Low', 0)} low")
    for f in model["findings"]:
        if f["severity"] == "High":
            print(f"  HIGH  {f['device']}: {f['finding']}")
    if gaps:
        print("Gaps:")
        for g in gaps:
            print("  - " + g)
    print(f"Wrote outputs to {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()

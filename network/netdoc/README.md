# netdoc

Builds network documentation from Juniper (Junos QFX/EX) and FortiGate (FortiOS) configs plus optional live show output: a formatted workbook (findings, devices, links, LAGs, port map, VLANs, IP plan, static routes, BGP, FortiGate policies/VIPs/IPsec), CSVs, a document draft (`report.md`), and topology data (`topology.json` with layout, `topology.mmd` Mermaid).

Read-only: it only parses files. Secrets in configs are dropped and never written to outputs.

## Collect (jump box, read-only)
```powershell
.\collect.ps1 -Junos chi-core-01,chi-dist-01 -FortiGate chi-fw-01 -OutDir C:\netdoc\chicago\2026-11-04
```
Or save device output manually as `HOST__command.txt`, or whole CLI session logs with prompts.

## Generate
```bash
python3 netdoc.py ./captures -o ./out --title "Chicago Network Documentation" --site "YellowBrick Chicago" --author Shawn
```
Requires Python 3.9+ and `openpyxl`. Try it on `sample/`, which has seeded issues (trunk VLAN mismatch, duplicate IRB address, down eBGP, LAG member down, unreachable static route, risky FortiGate policy).

Also packaged as the Claude skill `network-docs`.

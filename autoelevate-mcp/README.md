# autoelevate-mcp

MCP server for AutoElevate (CyberFOX) that vets elevation requests against **CMMC Level 2 / NIST SP 800-171 Rev 2** before anyone approves them.

AutoElevate has no public API. This server uses the same JSON API the `msp.autoelevate.com` portal uses (`apollo.autoelevate.com/api`), so CyberFOX can change it without notice. If calls start failing after a portal update, the endpoints in `client.py` are the place to look.

## Tools

| Tool | What it does |
|---|---|
| `ae_list_requests` | Pending (or all) elevation requests for the last N days, optionally one company |
| `ae_get_request` | Full request by AutoElevate id **or ConnectWise ticket number** |
| `ae_analyze_request` | The pre-approval analysis. Returns verdict, markdown table and a ready-to-post CW note |
| `ae_decide_request` | Approve or deny. Guarded (see below) |
| `ae_audit_rules` | Audits existing rules: shells/LOLBins, OS components, all-companies rules, remote access, etc. |
| `ae_list_computers` | Agents with version, elevation mode, AV and Windows Update state |
| `ae_list_companies` | Company names and ids |

## The analysis

| Check | Practices | Outcome |
|---|---|---|
| Shell / LOLBin / OS component / wrapper (`powershell.exe`, `cmd.exe`, `regedit.exe`, `msiexec.exe`...) | AC.L2-3.1.7, 3.1.5 | Escalate; never a standing rule |
| Authenticode signature, self-signed, signer vs vendor | SI.L2-3.14.2, CM.L2-3.4.8 | Untrusted = **deny**; unsigned or mismatch = escalate |
| Restricted categories: remote access, P2P, crypto, VPN/proxy, AI, consumer, dual-use admin tools | AC.L2-3.1.12, CM.L2-3.4.6/3.4.7 | Remote access, P2P, crypto = **deny**; others escalate |
| Client's approved software baseline (`baselines/*.yaml`) | CM.L2-3.4.8 | Denied list = **deny**; not listed / no baseline / below min version = escalate |
| User-installed from Downloads/AppData, or from a network share | CM.L2-3.4.9 | Recorded; network share escalates |
| VirusTotal by SHA-256 | SI.L2-3.14.2 | 2+ engines = **deny**; 1 or unknown file = escalate |
| CISA KEV cross-checked against NVD version ranges | SI.L2-3.14.1, RA.L2-3.11.2 | KEV CVE affecting this version = **deny** |
| NVD CVEs covering this exact version | RA.L2-3.11.2 | CVSS >= 7 = escalate |
| End-of-life (endoflife.date, products mapped in `policy.yaml`) | SI.L2-3.14.1 | EOL = escalate |
| Device posture from the AE agent (AV, Windows Update, technician mode) | SI.L2-3.14.1/3.14.2 | Issues escalate |
| Change record (the analysis + CW note + AE audit log) | CM.L2-3.4.3, 3.4.4, AU.L2-3.3.1 | Always |

**APPROVE** only when everything passes. The recommended scope is the narrowest that works: installers are one-time with no rule; recurring apps get a computer-level rule. All-companies rules are never offered.

## Approval guardrails

`ae_decide_request` refuses unless:

- `confirm=true` (Claude is told to only set it after you say so)
- the same request was analyzed in this session within the last 2 hours, and is still PENDING
- approving against a DENY or ESCALATE verdict includes your `override_reason`, which goes into the CW note
- a standing rule is computer, location or company level (never `msp`), and never for a shell, OS component or wrapper

The workflow it's built for: analyze, show you the table, post the `cw_note` to the request's ConnectWise ticket with the ConnectWise MCP, then decide when you say so, and post the decision note.

## Setup (Windows, Claude Desktop)

1. **Service user.** In the AutoElevate portal, create a dedicated user with a local password (Entra SSO users can't sign in through the API) and set up 2FA. Keep the TOTP secret (the base32 string behind the QR code). Give it the least role that can view and approve requests.
2. **Install.**
   ```powershell
   cd tools_code\autoelevate-mcp
   py -m venv .venv
   .venv\Scripts\pip install -e .
   ```
3. **Keys.** A free VirusTotal API key (required for the malware check; without it every request escalates). An NVD API key is optional but avoids rate limits.
4. **Claude Desktop config** (`%APPDATA%\Claude\claude_desktop_config.json`):
   ```json
   "autoelevate": {
     "command": "C:\\path\\to\\tools_code\\autoelevate-mcp\\.venv\\Scripts\\autoelevate-mcp.exe",
     "env": {
       "AE_EMAIL": "svc-claude@netrique.com",
       "AE_PASSWORD": "...",
       "AE_TOTP_SECRET": "...",
       "VT_API_KEY": "...",
       "NVD_API_KEY": "..."
     }
   }
   ```
   For a quick test without a service user, set `AE_TOKEN` to the `authToken` value from the portal's browser storage. It expires after 24 hours.

## Baselines

One YAML per client in `baselines/`, named by the AutoElevate company name slug (`Example Client` -> `example-client.yaml`). See `baselines/_example.yaml`. Until a client has one, every request for that client escalates on CM.L2-3.4.8, which is the honest answer: permit-by-exception needs a documented list. Point `AE_BASELINE_DIR` elsewhere if the baselines shouldn't live in this repo.

## Config

- `config/policy.yaml`: LOLBin list, category terms, sanctioned remote tools (`categories.remote_access.allow`), installer markers, endoflife.date mappings.
- `config/cmmc_l2_rev2.yaml`: practice titles and check-to-practice mapping. DoD's interim guidance during the CMMC pause enforces Rev 2; for Rev 3, copy the file and set `AE_CONTROL_MAP`.

## Tests

```
pip install -e .[test]
pytest
```
The tests use an anonymized fixture from a real request and mock the AutoElevate API; nothing hits the network.

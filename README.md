# tools_code

Scripts and tooling.

## ninjaone/

- `Update-NinjaADDocumentation.ps1` – run on a domain controller as a NinjaOne automation; collects AD facts (short name, functional level, Domain Admins, DCs, DNS, DHCP, schema master, RODCs, servers) and writes them into the client's "Active Directory" Documentation document via `Ninja-Property-Docs-Set`.
- `Enable-BitLockerEnforced.ps1` – run as a NinjaOne automation (SYSTEM) on workstations; enables BitLocker on the OS drive or resumes protection on drives that are encrypted with a clear key (Windows auto device encryption). Adds recovery password + TPM protectors, escrows the recovery key to AD / Entra ID / an optional NinjaOne secure field *before* turning protection on, and refuses to enable if escrow fails (exit 3). Saves the key to the NinjaOne Secure field `bitlockerRecoveryKey` by default (create it with Automations = Write); override with script variable `ninjaField`. Other optional variables: `allowNoEscrow`, `skipPolicyKeys`. Exit codes: 0 ok, 1 fail, 2 TPM not ready, 3 escrow failed.

## activedirectory/

- `Get-ADPasswordExpiry.ps1` – reports each AD user's last password change, password age, expiry date and days until expiry (uses `msDS-UserPasswordExpiryTimeComputed`, so fine-grained password policies are honored). Each user gets a Status of `Expired`, `ExpiringSoon`, `OK`, `NeverExpires` or `MustChange`, ready to pipe into an alerting step. Parameters: `-SearchBase`, `-Server`, `-WarningDays` (default 14), `-IncludeDisabled`, `-OnlyAlertable`, `-CsvPath`. Requires the ActiveDirectory module.

## linux/

- `distrust-emudhra-g3.sh` – blocklists the compromised eMudhra trust path (Oct 2026 intermediate key compromise) on RHEL-family hosts that can't get a fixed `ca-certificates` package (e.g. EOL CentOS Stream 8). Blocklists `emSign ECC Root CA - G3` and `EM DV TLS CA - G3B`, SHA-256 fingerprint-checks both before writing, runs `update-ca-trust extract`, then confirms `curl` rejects `dv-g3b-emudhra.we-have-a-problem.com`. Handles RHEL 8 `blacklist` and RHEL 9 `blocklist` dirs; idempotent. `--check` verifies without changing anything. Exit codes: 0 rejected (good), 1 error, 2 applied but still connecting, 3 `--check` vulnerable. Does not cover certifi, Node or Go bundles.

## autoelevate-mcp/

- MCP server for AutoElevate (CyberFOX) built on the admin portal's internal API. `ae_analyze_request` runs a CMMC Level 2 / NIST 800-171 Rev 2 pre-approval analysis on an elevation request (signature, VirusTotal, CISA KEV + NVD for the exact version, EOL, client software baseline, restricted categories, shells/LOLBins, device posture) and returns a verdict plus a ConnectWise note. `ae_decide_request` approves/denies only with confirmation, a fresh analysis, and a recorded override reason when going against the verdict. `ae_audit_rules` flags risky existing rules. See `autoelevate-mcp/README.md`.

# tools_code

Scripts and tooling.

## ninjaone/

- `Update-NinjaADDocumentation.ps1` – run on a domain controller as a NinjaOne automation; collects AD facts (short name, functional level, Domain Admins, DCs, DNS, DHCP, schema master, RODCs, servers) and writes them into the client's "Active Directory" Documentation document via `Ninja-Property-Docs-Set`.
- `Enable-BitLockerEnforced.ps1` – run as a NinjaOne automation (SYSTEM) on workstations; enables BitLocker on the OS drive or resumes protection on drives that are encrypted with a clear key (Windows auto device encryption). Adds recovery password + TPM protectors, escrows the recovery key to AD / Entra ID / an optional NinjaOne secure field *before* turning protection on, and refuses to enable if escrow fails (exit 3). Saves the key to the NinjaOne Secure field `bitlockerRecoveryKey` by default (create it with Automations = Write); override with script variable `ninjaField`. Other optional variables: `allowNoEscrow`, `skipPolicyKeys`. Exit codes: 0 ok, 1 fail, 2 TPM not ready, 3 escrow failed.

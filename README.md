# tools_code

Scripts and tooling.

## ninjaone/

- `Update-NinjaADDocumentation.ps1` – run on a domain controller as a NinjaOne automation; collects AD facts (short name, functional level, Domain Admins, DCs, DNS, DHCP, schema master, RODCs, servers) and writes them into the client's "Active Directory" Documentation document via `Ninja-Property-Docs-Set`.

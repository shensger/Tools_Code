<#
.SYNOPSIS
  Pulls the emudhraG3Status / emudhraStatus custom fields for every device in
  every NinjaOne organization and writes one CSV row per device.

.DESCRIPTION
  Uses the NinjaOne API bulk custom-field query (/v2/queries/custom-fields), so
  the whole tenant takes a handful of calls instead of one per device.
  Output columns: Organization, OrgId, DeviceId, Device, NodeClass, Online,
  LastContact (UTC date), Status, ExitCode, Tool, LastRun, RawG3Status,
  EmudhraStatus.

  Status is the first word of emudhraG3Status (OK / VULNERABLE / INCONCLUSIVE),
  or "Not populated". Pair with cross-platform/test-emudhra-g3.sh,
  cross-platform/Test-EmudhraG3.ps1 and macos/distrust-emudhra-g3-macos.sh.

  Credentials: pass -ClientId/-ClientSecret, or set NINJAONE_CLIENT_ID /
  NINJAONE_CLIENT_SECRET, or leave both unset to read them from the Claude
  Desktop config (the NinjaOne MCP server's env block). The secret is never
  printed.

.EXAMPLE
  .\Get-EmudhraG3StatusAllOrgs.ps1 -OutFile C:\Temp\emudhra.csv
#>
[CmdletBinding()]
param(
  [string]$ClientId     = $env:NINJAONE_CLIENT_ID,
  [string]$ClientSecret = $env:NINJAONE_CLIENT_SECRET,
  [string]$BaseUrl      = 'https://app.ninjarmm.com',
  [string]$OutFile      = (Join-Path $env:TEMP 'emudhraG3Status-allorgs.csv')
)
$ErrorActionPreference = 'Stop'

if (-not $ClientId -or -not $ClientSecret) {
  $cfgPath = Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'
  if (-not (Test-Path $cfgPath)) { throw 'No credentials given and Claude Desktop config not found.' }
  $cfg = Get-Content $cfgPath -Raw   # regex, not ConvertFrom-Json: the file may not be strict JSON
  $ClientId     = [regex]::Match($cfg, '"NINJAONE_CLIENT_ID"\s*:\s*"([^"]+)"').Groups[1].Value
  $ClientSecret = [regex]::Match($cfg, '"NINJAONE_CLIENT_SECRET"\s*:\s*"([^"]+)"').Groups[1].Value
  if (-not $ClientId -or -not $ClientSecret) { throw 'NinjaOne credentials not found in Claude Desktop config.' }
}

$tok = Invoke-RestMethod -Method Post -Uri "$BaseUrl/ws/oauth/token" -ContentType 'application/x-www-form-urlencoded' `
  -Body @{ grant_type = 'client_credentials'; client_id = $ClientId; client_secret = $ClientSecret; scope = 'monitoring' }
$h = @{ Authorization = "Bearer $($tok.access_token)" }

# PS 5.1 returns JSON arrays as a single pipeline object; ForEach-Object unrolls them.
function Get-Array([string]$Uri) { Invoke-RestMethod -Headers $h -Uri $Uri | ForEach-Object { $_ } }

$orgs = @{}
Get-Array "$BaseUrl/v2/organizations?pageSize=1000" | ForEach-Object { $orgs[[int]$_.id] = $_.name }

$devices = @(); $after = 0
do {
  $page = @(Get-Array "$BaseUrl/v2/devices?pageSize=1000&after=$after")
  $devices += $page
  if ($page.Count) { $after = ($page | Measure-Object -Property id -Maximum).Maximum }
} while ($page.Count -eq 1000)

$cf = @{}; $cursor = $null
do {
  $u = "$BaseUrl/v2/queries/custom-fields?fields=emudhraG3Status,emudhraStatus&pageSize=1000"
  if ($cursor) { $u += "&cursor=$cursor" }
  $r = Invoke-RestMethod -Headers $h -Uri $u
  foreach ($row in $r.results) { $cf[[int]$row.deviceId] = $row.fields }
  $cursor = $r.cursor.name
} while ($cursor -and @($r.results).Count -gt 0)

$rows = foreach ($d in $devices) {
  $f   = $cf[[int]$d.id]
  $raw = if ($f) { $f.emudhraG3Status } else { $null }
  $m   = if ($raw) { [regex]::Match($raw, '^(\w+) \| exit=(-?\d+) \| ([^|]+?) \| (.+)$') } else { $null }
  [pscustomobject]@{
    Organization  = $orgs[[int]$d.organizationId]
    OrgId         = $d.organizationId
    DeviceId      = $d.id
    Device        = if ($d.displayName) { $d.displayName } else { $d.systemName }
    NodeClass     = $d.nodeClass
    Online        = -not $d.offline
    LastContact   = if ($d.lastContact) { [DateTimeOffset]::FromUnixTimeSeconds([long][double]$d.lastContact).UtcDateTime.ToString('yyyy-MM-dd') } else { '' }
    Status        = if ($m -and $m.Success) { $m.Groups[1].Value } else { 'Not populated' }
    ExitCode      = if ($m -and $m.Success) { [int]$m.Groups[2].Value } else { $null }
    Tool          = if ($m -and $m.Success) { $m.Groups[3].Value } else { '' }
    LastRun       = if ($m -and $m.Success) { $m.Groups[4].Value } else { '' }
    RawG3Status   = $raw
    EmudhraStatus = if ($f) { $f.emudhraStatus } else { $null }
  }
}
$rows | Sort-Object Organization, Device | Export-Csv $OutFile -NoTypeInformation -Encoding UTF8

$rows | Group-Object Status | Sort-Object Name | ForEach-Object { '{0,-14} {1}' -f $_.Name, $_.Count }
"Orgs: $($orgs.Count)  Devices: $($devices.Count)  ->  $OutFile"

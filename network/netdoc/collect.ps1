<#
.SYNOPSIS
  Read-only collection of Junos and FortiOS config + show output for netdoc.py.
.DESCRIPTION
  Uses OpenSSH with existing key-based auth and ~/.ssh/config aliases. Runs only show/get
  commands, one ssh call per command, and saves HOST__suffix.txt files in OutDir.
.EXAMPLE
  .\collect.ps1 -Junos chi-core-01,chi-dist-01 -FortiGate chi-fw-01 -OutDir C:\netdoc\chicago\2026-11-04
#>
param(
  [string[]]$Junos = @(),
  [string[]]$FortiGate = @(),
  [Parameter(Mandatory = $true)][string]$OutDir,
  [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'collect.log'

$junosCmds = [ordered]@{
  'config' = 'show configuration | display inheritance no-comments | display set | no-more'
  'version' = 'show version | no-more'
  'lldp'    = 'show lldp neighbors | no-more'
  'terse'   = 'show interfaces terse | no-more'
  'bgp'     = 'show bgp summary | no-more'
  'vc'      = 'show virtual-chassis | no-more'
}
$fgtCmds = [ordered]@{
  'config' = 'show'
  'status' = 'get system status'
  'ifphys' = 'get system interface physical'
  'bgp'    = 'get router info bgp summary'
}

# Guard: only read-only show/get commands, no chaining.
function Assert-ReadOnly([string]$cmd) {
  if ($cmd -notmatch '^(show|get)( |$)' -or $cmd -match '[;`\r\n]') { throw "Refusing non read-only command: $cmd" }
}

function Invoke-Collect([string]$hostAlias, $cmds) {
  foreach ($k in $cmds.Keys) {
    $cmd = $cmds[$k]
    Assert-ReadOnly $cmd
    $file = Join-Path $OutDir ("{0}__{1}.txt" -f $hostAlias, $k)
    $start = Get-Date
    $out = & ssh -o BatchMode=yes -o ConnectTimeout=$TimeoutSec $hostAlias $cmd 2>&1
    $rc = $LASTEXITCODE
    $out | Out-File -FilePath $file -Encoding utf8
    $lines = ($out | Measure-Object -Line).Lines
    "{0:s}`t{1}`t{2}`trc={3}`tlines={4}`t{5:N1}s" -f $start, $hostAlias, $k, $rc, $lines, ((Get-Date) - $start).TotalSeconds |
      Tee-Object -FilePath $log -Append
    if ($rc -ne 0 -and $k -eq 'config') {
      Write-Warning "$hostAlias config collection failed (rc=$rc) - skipping remaining commands for this host."
      break
    }
  }
}

foreach ($h in $Junos) { Invoke-Collect $h $junosCmds }
foreach ($h in $FortiGate) { Invoke-Collect $h $fgtCmds }
Write-Host "Done. Files in $OutDir"

<#
.SYNOPSIS
  One-shot: collect (read-only) from Junos/FortiGate over SSH, then build the documentation.
.EXAMPLE
  .\netdoc.ps1 -Site chicago -Junos chi-core,cho-stor -FortiGate yb-nat
  .\netdoc.ps1 -Site slc -Captures C:\netdoc\captures\slc\from-kim     # skip SSH, use supplied files
.NOTES
  Captures: C:\netdoc\captures\<site>\<yyyy-MM-dd_HHmm>\   Output: C:\netdoc\output\<site>\<same stamp>\
#>
param(
  [Parameter(Mandatory = $true)][string]$Site,
  [string[]]$Junos = @(),
  [string[]]$FortiGate = @(),
  [string]$Captures = '',
  [string]$Title = '',
  [string]$Author = $env:USERNAME,
  [string]$Root = 'C:\netdoc'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'

if (-not $Captures) {
  if (-not ($Junos -or $FortiGate)) { throw 'Give -Junos and/or -FortiGate host aliases, or -Captures <folder>.' }
  $Captures = Join-Path $Root "captures\$Site\$stamp"
  & (Join-Path $here 'collect.ps1') -Junos $Junos -FortiGate $FortiGate -OutDir $Captures
}
if (-not (Test-Path $Captures)) { throw "Captures folder not found: $Captures" }

$out = Join-Path $Root "output\$Site\$stamp"
if (-not $Title) { $Title = "$((Get-Culture).TextInfo.ToTitleCase($Site)) Network Infrastructure Documentation" }
$env:PYTHONIOENCODING = 'utf-8'
& python (Join-Path $here 'netdoc.py') $Captures -o $out --title $Title --site $Site --author $Author
if ($LASTEXITCODE -ne 0) { throw "netdoc.py failed (exit $LASTEXITCODE)" }
Write-Host "`nCaptures: $Captures`nOutput:   $out"

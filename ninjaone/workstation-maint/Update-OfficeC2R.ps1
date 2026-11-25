#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 7 - forces a Microsoft 365 / Office Click-to-Run update and
    reports the version before and after.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.

    - Reads the Click-to-Run configuration: version, channel, products, whether updates are
      enabled and whether policy points updates to a network share / ConfigMgr.
    - MSI Office (2016/2019 volume MSI) is not Click-to-Run: it is patched through Microsoft
      Update, so the script says so and exits 0 (use Install-WindowsUpdates.ps1).
    - Runs OfficeC2RClient.exe /update user displaylevel=false and waits (up to maxWaitMinutes)
      for the update to finish, then reports the new version.
    - forceAppShutdown=true closes open Office apps so the update applies immediately (users
      lose unsaved work - only use inside the agreed maintenance window). With false, the
      update downloads and applies the next time the apps are closed.

    Ninja script variables (all optional):
      forceAppShutdown  Checkbox  Close running Office apps to apply now. Default false.
      maxWaitMinutes    Integer   How long to wait for the update. Default 45.
      ninjaField        Text      Device text field for the one-line result. Default none.

.OUTPUTS
    Exit codes: 0 updated / already current / not C2R, 1 update did not complete in time or
    failed, 2 error.
#>
[CmdletBinding()]
param(
    [switch]$ForceAppShutdown,
    [int]$MaxWaitMinutes = 0,
    [string]$NinjaField = $env:ninjaField
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Write-Log([string]$Msg) { Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg) }
function Set-ResultField([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($NinjaField) -or $NinjaField -eq 'none') { return }
    if (-not (Get-Command -Name Set-NinjaProperty -ErrorAction SilentlyContinue)) { return }
    if ($Value.Length -gt 200) { $Value = $Value.Substring(0, 200) }
    try { Set-NinjaProperty -Name $NinjaField -Value $Value } catch { Write-Log "WARN: could not write field '$NinjaField': $($_.Exception.Message)" }
}

if ($env:forceAppShutdown -eq 'true') { $ForceAppShutdown = $true }
if ($MaxWaitMinutes -le 0) {
    $MaxWaitMinutes = 45
    if ($env:maxWaitMinutes -match '^\d+$') { $MaxWaitMinutes = [int]$env:maxWaitMinutes }
}

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 2
}

$C2RKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$Channels = @{
    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current'
    '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Preview'
    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise'
    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise'
    'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Preview'
    '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta'
}

function Get-C2RVersion { [string](Get-ItemProperty -Path $C2RKey -ErrorAction SilentlyContinue).VersionToReport }

try {
    Write-Log "Org: $env:NINJA_ORGANIZATION_NAME  Device: $env:COMPUTERNAME  ForceAppShutdown=$ForceAppShutdown  MaxWait=$MaxWaitMinutes min"

    if (-not (Test-Path -Path $C2RKey)) {
        $msi = @()
        foreach ($r in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
            $msi += @(Get-ItemProperty -Path $r -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^Microsoft Office (Professional|Standard|Home|Small Business)' -and $_.WindowsInstaller -eq 1 })
        }
        if ($msi.Count -gt 0) {
            Write-Log ("MSI Office found: {0} {1}. MSI Office is patched through Microsoft Update - run Install-WindowsUpdates.ps1." -f $msi[0].DisplayName, $msi[0].DisplayVersion)
            Set-ResultField ("MSI | {0:yyyy-MM-dd HH:mm} | {1} - patch via Microsoft Update" -f (Get-Date), $msi[0].DisplayName)
        }
        else {
            Write-Log 'No Click-to-Run Office installed.'
            Set-ResultField ("NONE | {0:yyyy-MM-dd HH:mm} | no Click-to-Run Office" -f (Get-Date))
        }
        exit 0
    }

    $cfg = Get-ItemProperty -Path $C2RKey
    $channelUrl = [string]$cfg.UpdateChannel
    if ([string]::IsNullOrWhiteSpace($channelUrl)) { $channelUrl = [string]$cfg.CDNBaseUrl }
    $channel = 'Unknown'
    foreach ($id in $Channels.Keys) { if ($channelUrl -match $id) { $channel = $Channels[$id] } }
    $before = Get-C2RVersion
    Write-Log ("Office C2R: {0}  version {1}  channel {2}  platform {3}" -f $cfg.ProductReleaseIds, $before, $channel, $cfg.Platform)

    if ([string]$cfg.UpdatesEnabled -eq 'False') { Write-Log 'WARNING: Office automatic updates are disabled in the C2R configuration.' }
    $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate' -ErrorAction SilentlyContinue
    if ($pol) {
        if ($pol.enableautomaticupdates -eq 0) { Write-Log 'WARNING: policy disables Office automatic updates (enableautomaticupdates=0).' }
        if ($pol.updatepath)         { Write-Log "NOTE: policy update path: $($pol.updatepath) - updates come from there, not the CDN." }
        if ($pol.officemgmtcom -eq 1) { Write-Log 'NOTE: Office updates are managed by ConfigMgr (officemgmtcom=1); this may not apply anything.' }
    }

    $appNames = @('WINWORD', 'EXCEL', 'OUTLOOK', 'POWERPNT', 'MSACCESS', 'ONENOTE', 'MSPUB', 'VISIO', 'WINPROJ', 'lync')
    $running = @(Get-Process -Name $appNames -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
    if ($running.Count -gt 0) {
        $note = 'update will apply when they are closed'
        if ($ForceAppShutdown) { $note = 'they will be closed' }
        Write-Log ("Office apps running: {0} - {1}" -f ($running -join ', '), $note)
    }

    $client = $null
    foreach ($base in @($env:CommonProgramW6432, $env:CommonProgramFiles)) {
        if ([string]::IsNullOrWhiteSpace($base)) { continue }
        $cand = Join-Path $base 'microsoft shared\ClickToRun\OfficeC2RClient.exe'
        if (-not $client -and (Test-Path -LiteralPath $cand)) { $client = $cand }
    }
    if (-not $client) { throw 'OfficeC2RClient.exe not found under Common Files\microsoft shared\ClickToRun' }

    $force = 'false'
    if ($ForceAppShutdown) { $force = 'true' }
    $c2rArgs = "/update user displaylevel=false forceappshutdown=$force updatepromptuser=false"
    Write-Log "Running: OfficeC2RClient.exe $c2rArgs"
    Start-Process -FilePath $client -ArgumentList $c2rArgs -WindowStyle Hidden | Out-Null

    # The client drives the update through the ClickToRun service. Poll until the reported
    # version changes, or the client has been gone for a while (nothing to apply), or timeout.
    $started  = Get-Date
    $deadline = $started.AddMinutes($MaxWaitMinutes)
    Start-Sleep -Seconds 60
    while ((Get-Date) -lt $deadline) {
        if ((Get-C2RVersion) -ne $before) { break }
        $busy = @(Get-Process -Name 'OfficeC2RClient' -ErrorAction SilentlyContinue).Count -gt 0
        if (-not $busy -and ((Get-Date) - $started).TotalMinutes -ge 5) { break }
        Start-Sleep -Seconds 30
    }
    $after = Get-C2RVersion
    $stillBusy = @(Get-Process -Name 'OfficeC2RClient' -ErrorAction SilentlyContinue).Count -gt 0

    if ($after -ne $before) {
        Write-Log "RESULT: UPDATED $before -> $after"
        Set-ResultField ("UPDATED | {0:yyyy-MM-dd HH:mm} | {1} -> {2} | {3}" -f (Get-Date), $before, $after, $channel)
        exit 0
    }
    if ($stillBusy) {
        Write-Log "RESULT: update still running after $MaxWaitMinutes min (version $after). Check again later."
        Set-ResultField ("TIMEOUT | {0:yyyy-MM-dd HH:mm} | still updating from {1}" -f (Get-Date), $before)
        exit 1
    }
    $msg = 'no new version applied - already current (re-run later to confirm if the update was still applying)'
    if ($running.Count -gt 0 -and -not $ForceAppShutdown) { $msg = 'no change yet - update may be waiting for Office apps to close' }
    Write-Log "RESULT: $msg (version $after, channel $channel)"
    Set-ResultField ("CURRENT | {0:yyyy-MM-dd HH:mm} | {1} | {2}" -f (Get-Date), $after, $msg)
    exit 0
}
catch {
    Write-Error "Office update failed: $($_.Exception.Message)"
    Set-ResultField ("ERROR | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $_.Exception.Message)
    exit 2
}

#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 8 - DISM component store repair, System File Checker and an
    online CHKDSK scan, with a repair queued for the next reboot when needed.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.

    1. DISM: Repair-WindowsImage -Online -ScanHealth. If the image is Repairable, runs
       -RestoreHealth (uses Windows Update as the source; can fail on WSUS-only devices).
       Skipped with skipDism.
    2. SFC: sfc /scannow, result parsed from its output (no violations / repaired /
       unable to repair / could not run / repair pending reboot).
    3. CHKDSK: Repair-Volume -Scan (online, read-only) on every fixed NTFS volume with a letter.
       When a volume needs repair and scheduleChkdsk is on:
         - system volume: marked dirty (fsutil dirty set) so autochk repairs it on the next boot
         - other volumes: Repair-Volume -SpotFix (seconds-long dismount of that volume)
    4. Physical disk health (Get-PhysicalDisk HealthStatus / OperationalStatus) for context.

    Typical run time 15-45 minutes (DISM and SFC are the slow parts). Nothing reboots; the queued
    disk repair runs at the reboot in maintenance step 9 and can add several minutes to that boot.

    Ninja script variables (all optional):
      skipDism         Checkbox  Skip the DISM steps.
      scheduleChkdsk   Checkbox  Queue a repair when a scan finds errors. Default true.
      ninjaField       Text      Device text field for the one-line result. Default none.

.OUTPUTS
    Exit codes:
      0  Healthy, repaired, or a disk repair is queued for the next reboot
      1  Corruption that could not be repaired (DISM NonRepairable / SFC unable to fix) or a
         physical disk reporting unhealthy
      2  Error
#>
[CmdletBinding()]
param(
    [switch]$SkipDism,
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

if ($env:skipDism -eq 'true') { $SkipDism = $true }
$ScheduleChkdsk = $true
if ($env:scheduleChkdsk -eq 'false') { $ScheduleChkdsk = $false }

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 2
}

function Invoke-Sfc {
    # sfc writes UTF-16 to a redirected stdout; read it as Unicode or every char has a NUL.
    $prev = [Console]::OutputEncoding
    try {
        try { [Console]::OutputEncoding = [Text.Encoding]::Unicode } catch { }   # no console handle: NULs are stripped below
        $out = & "$env:windir\System32\sfc.exe" /scannow 2>&1 | Out-String
    }
    finally { try { [Console]::OutputEncoding = $prev } catch { } }
    $out = ($out -replace "`0", '') -replace '\s+', ' '
    $code = $LASTEXITCODE
    $state = 'UNKNOWN'
    if     ($out -match 'did not find any integrity violations')               { $state = 'CLEAN' }
    elseif ($out -match 'found corrupt files and successfully repaired')        { $state = 'REPAIRED' }
    elseif ($out -match 'found corrupt files but was unable to fix')            { $state = 'UNREPAIRED' }
    elseif ($out -match 'system repair pending|There is a system repair pending') { $state = 'PENDING_REBOOT' }
    elseif ($out -match 'could not perform the requested operation')            { $state = 'FAILED' }
    [pscustomobject]@{ State = $state; ExitCode = $code; Text = $out }
}

try {
    Write-Log "Org: $env:NINJA_ORGANIZATION_NAME  Device: $env:COMPUTERNAME  SkipDism=$SkipDism  ScheduleChkdsk=$ScheduleChkdsk"
    $problems = New-Object System.Collections.Generic.List[string]
    $summary  = New-Object System.Collections.Generic.List[string]

    # 1. DISM
    if ($SkipDism) { $summary.Add('DISM=skipped') }
    else {
        Write-Log 'DISM: ScanHealth (several minutes)...'
        $scan = Repair-WindowsImage -Online -ScanHealth -NoRestart
        $health = [string]$scan.ImageHealthState
        Write-Log "DISM: image health = $health"
        if ($health -eq 'Repairable') {
            Write-Log 'DISM: RestoreHealth...'
            try {
                $fix = Repair-WindowsImage -Online -RestoreHealth -NoRestart
                $health = [string]$fix.ImageHealthState
                Write-Log "DISM: after RestoreHealth = $health"
                if ($health -ne 'Healthy') { $problems.Add("DISM $health") }
            }
            catch {
                Write-Log "DISM: RestoreHealth failed - $($_.Exception.Message) (WSUS-only devices may need a repair source)"
                $problems.Add('DISM RestoreHealth failed')
                $health = 'RepairFailed'
            }
        }
        elseif ($health -eq 'NonRepairable') { $problems.Add('DISM NonRepairable') }
        $summary.Add("DISM=$health")
    }

    # 2. SFC
    Write-Log 'SFC: scannow (10-20 minutes)...'
    $sfc = Invoke-Sfc
    Write-Log "SFC: $($sfc.State) (exit $($sfc.ExitCode))"
    if ($sfc.State -eq 'UNKNOWN' -or $sfc.State -eq 'FAILED') { Write-Log "SFC output: $($sfc.Text.Trim())" }
    if ($sfc.State -eq 'UNREPAIRED' -or $sfc.State -eq 'FAILED') { $problems.Add("SFC $($sfc.State)") }
    if ($sfc.State -eq 'UNREPAIRED') { Write-Log "SFC: details in $env:windir\Logs\CBS\CBS.log" }
    $summary.Add("SFC=$($sfc.State)")

    # 3. CHKDSK (online scan)
    $sysLetter = $env:SystemDrive.TrimEnd(':')
    $queued = @()
    $vols = @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' })
    foreach ($v in $vols) {
        $L = [string]$v.DriveLetter
        $res = 'ScanFailed'
        try { $res = [string](Repair-Volume -DriveLetter $L -Scan -ErrorAction Stop) } catch { Write-Log "CHKDSK ${L}: scan failed - $($_.Exception.Message)" }
        Write-Log "CHKDSK ${L}: $res"
        if ($res -eq 'NoErrorsFound' -or $res -eq 'ScanFailed') { continue }
        if (-not $ScheduleChkdsk) { $problems.Add("Volume $L needs repair"); continue }
        if ($L -eq $sysLetter) {
            & "$env:windir\System32\fsutil.exe" dirty set "${L}:" | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-Log "CHKDSK ${L}: marked dirty - autochk will repair it on next boot"; $queued += $L }
            else { $problems.Add("Could not mark $L dirty") }
        }
        else {
            try {
                $fixRes = [string](Repair-Volume -DriveLetter $L -SpotFix -ErrorAction Stop)
                Write-Log "CHKDSK ${L}: SpotFix = $fixRes"
            }
            catch {
                & "$env:windir\System32\fsutil.exe" dirty set "${L}:" | Out-Null
                Write-Log "CHKDSK ${L}: SpotFix failed ($($_.Exception.Message)) - marked dirty for next boot"
                $queued += $L
            }
        }
    }
    $chk = 'OK'
    if ($queued.Count -gt 0) { $chk = 'QUEUED(' + ($queued -join ',') + ')' }
    $summary.Add("CHKDSK=$chk")

    # 4. Physical disks
    foreach ($d in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        Write-Log ("Disk {0} {1} ({2}): health={3} status={4}" -f $d.DeviceId, $d.FriendlyName, $d.MediaType, $d.HealthStatus, ($d.OperationalStatus -join ','))
        if ([string]$d.HealthStatus -ne 'Healthy') { $problems.Add("Disk $($d.FriendlyName) $($d.HealthStatus)") }
    }

    $status = 'OK'
    if ($queued.Count -gt 0 -or $sfc.State -eq 'PENDING_REBOOT') { $status = 'REBOOT_TO_FIX' }
    if ($problems.Count -gt 0) { $status = 'PROBLEM' }
    Write-Log ("RESULT: {0} | {1}" -f $status, ($summary -join ' '))
    if ($problems.Count -gt 0) { Write-Log ("Problems: " + ($problems -join '; ')) }
    Set-ResultField ("{0} | {1:yyyy-MM-dd HH:mm} | {2}" -f $status, (Get-Date), ($summary -join ' '))
    if ($status -eq 'PROBLEM') { exit 1 }
    exit 0
}
catch {
    Write-Error "System repair failed: $($_.Exception.Message)"
    Set-ResultField ("ERROR | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $_.Exception.Message)
    exit 2
}

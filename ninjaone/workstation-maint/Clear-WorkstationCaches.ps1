#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 3 - clears temp files and caches and reports the space reclaimed.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.
    Part of the workstation maintenance set (see ninjaone/workstation-maint/README section).

    What it clears (files older than cleanupAgeDays unless noted; files in use are skipped):
      - C:\Windows\Temp and every profile's AppData\Local\Temp
      - Browser CACHE folders for every profile: Edge, Chrome, Brave, Firefox (cache2), IE/WinINet.
        Only cache - never history, cookies, passwords, bookmarks or sessions.
      - Windows Error Reporting queue/archive (ProgramData\Microsoft\Windows\WER)
      - chkdsk leftovers (found.###\*.chk) on fixed volumes
      - Windows Update download cache (SoftwareDistribution\Download) - all ages. Skipped if an
        update is installing (TiWorker / TrustedInstaller busy). wuauserv/bits are restarted.
      - Delivery Optimization cache (Delete-DeliveryOptimizationCache)
      - Optional: Recycle Bin on all fixed drives (emptyRecycleBin)
      - Optional: new Teams (MSTeams) cache, only for users where Teams is not running (clearTeamsCache)

    Does NOT touch crash dumps (needed for BSOD diagnosis), Downloads, Desktop or Documents.

    Ninja script variables (all optional):
      cleanupAgeDays   Integer   Age threshold for temp/WER/chk files. Default 2. Browser cache
                                 and update caches ignore this.
      clearUpdateCache Checkbox  Default true.
      emptyRecycleBin  Checkbox  Default false.
      clearTeamsCache  Checkbox  Default false.
      dryRun           Checkbox  Measure only, delete nothing.
      ninjaField       Text      Device text field to write the one-line result to. Default none.

.OUTPUTS
    Exit codes: 0 success, 1 failure.
#>
[CmdletBinding()]
param(
    [int]$CleanupAgeDays = -1,
    [switch]$DryRun,
    [switch]$EmptyRecycleBin,
    [switch]$ClearTeamsCache,
    [string]$NinjaField = $env:ninjaField
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Write-Log([string]$Msg) { Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg) }
function Get-Flag([string]$Value, [bool]$Default) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    return ($Value -eq 'true')
}
function Set-ResultField([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($NinjaField) -or $NinjaField -eq 'none') { return }
    if (-not (Get-Command -Name Set-NinjaProperty -ErrorAction SilentlyContinue)) { return }
    if ($Value.Length -gt 200) { $Value = $Value.Substring(0, 200) }
    try { Set-NinjaProperty -Name $NinjaField -Value $Value } catch { Write-Log "WARN: could not write field '$NinjaField': $($_.Exception.Message)" }
}

# ---- Inputs (Ninja env vars; checkboxes arrive as "true"/"false") --------------------------
if ($CleanupAgeDays -lt 0) {
    $CleanupAgeDays = 2
    if ($env:cleanupAgeDays -match '^\d+$') { $CleanupAgeDays = [int]$env:cleanupAgeDays }
}
if (Get-Flag $env:dryRun $false)          { $DryRun = $true }
if (Get-Flag $env:emptyRecycleBin $false) { $EmptyRecycleBin = $true }
if (Get-Flag $env:clearTeamsCache $false) { $ClearTeamsCache = $true }
$ClearUpdateCache = Get-Flag $env:clearUpdateCache $true

# ---- Must be elevated (SYSTEM or admin) -----------------------------------------------------
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 1
}

$script:TotalBytes = [int64]0
$script:TotalFiles = 0

function Remove-Files {
    # Deletes (or measures, in dry run) files under each path older than $Cutoff. Skips reparse
    # points so junctions never lead outside the target folder. Locked files are skipped.
    param([string[]]$Paths, [datetime]$Cutoff, [string[]]$Include = @('*'), [string]$Label)
    $bytes = [int64]0; $count = 0
    foreach ($p in $Paths) {
        if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path -LiteralPath $p)) { continue }
        $files = Get-ChildItem -LiteralPath $p -Recurse -Force -File -Include $Include -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Cutoff -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
        foreach ($f in $files) {
            $len = $f.Length
            if ($DryRun) { $bytes += $len; $count++; continue }
            try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $bytes += $len; $count++ } catch { }
        }
    }
    $script:TotalBytes += $bytes; $script:TotalFiles += $count
    Write-Log ("{0,-28} {1,7} files  {2,9:N1} MB" -f $Label, $count, ($bytes / 1MB))
}

function Get-ProfilePaths {
    Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special=False' -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) } |
        Select-Object -ExpandProperty LocalPath
}

function Get-FreeGB {
    $d = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    [math]::Round($d.FreeSpace / 1GB, 2)
}

try {
    $now      = Get-Date
    $cutoff   = $now.AddDays(-$CleanupAgeDays)
    $profiles = @(Get-ProfilePaths)
    $freeBefore = Get-FreeGB
    Write-Log "Org: $env:NINJA_ORGANIZATION_NAME  Device: $env:COMPUTERNAME  DryRun=$DryRun  AgeDays=$CleanupAgeDays"
    Write-Log "Free on $($env:SystemDrive) before: $freeBefore GB  ($($profiles.Count) user profiles)"

    # 1. Temp folders
    $tempPaths = @("$env:windir\Temp")
    foreach ($pp in $profiles) { $tempPaths += (Join-Path $pp 'AppData\Local\Temp') }
    Remove-Files -Paths $tempPaths -Cutoff $cutoff -Label 'Temp folders'

    # 2. Browser caches (cache only; any age)
    $cacheRel = @(
        'AppData\Local\Microsoft\Windows\INetCache',
        'AppData\Local\Microsoft\Edge\User Data\*\Cache',
        'AppData\Local\Microsoft\Edge\User Data\*\Code Cache',
        'AppData\Local\Microsoft\Edge\User Data\*\GPUCache',
        'AppData\Local\Google\Chrome\User Data\*\Cache',
        'AppData\Local\Google\Chrome\User Data\*\Code Cache',
        'AppData\Local\Google\Chrome\User Data\*\GPUCache',
        'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache',
        'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache',
        'AppData\Local\Mozilla\Firefox\Profiles\*\cache2'
    )
    $cachePaths = foreach ($pp in $profiles) {
        foreach ($r in $cacheRel) {
            Resolve-Path -Path (Join-Path $pp $r) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProviderPath
        }
    }
    Remove-Files -Paths @($cachePaths) -Cutoff $now -Label 'Browser caches'

    # 3. Windows Error Reporting
    Remove-Files -Paths @("$env:ProgramData\Microsoft\Windows\WER\ReportQueue", "$env:ProgramData\Microsoft\Windows\WER\ReportArchive") -Cutoff $cutoff -Label 'Error reporting (WER)'

    # 4. chkdsk leftovers
    $chkDirs = foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
        Get-ChildItem -LiteralPath ($d.DeviceID + '\') -Directory -Force -Filter 'found.*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    Remove-Files -Paths @($chkDirs) -Cutoff $cutoff -Include @('*.chk') -Label 'chkdsk fragments'

    # 5. Windows Update download cache
    if ($ClearUpdateCache) {
        $busy = Get-Process -Name 'TiWorker' -ErrorAction SilentlyContinue
        if ($busy) {
            Write-Log 'Windows Update cache: SKIPPED - an update is installing (TiWorker running)'
        }
        elseif ($DryRun) {
            Remove-Files -Paths @("$env:windir\SoftwareDistribution\Download") -Cutoff $now -Label 'Windows Update cache'
        }
        else {
            $svcs = @('wuauserv', 'bits')
            $wasRunning = @($svcs | Where-Object { (Get-Service -Name $_ -ErrorAction SilentlyContinue).Status -eq 'Running' })
            try {
                foreach ($s in $svcs) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }
                Remove-Files -Paths @("$env:windir\SoftwareDistribution\Download") -Cutoff $now -Label 'Windows Update cache'
            }
            finally {
                foreach ($s in $wasRunning) { Start-Service -Name $s -ErrorAction SilentlyContinue }
            }
        }

        if (Get-Command -Name Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
            $doBefore = Get-FreeGB
            if ($DryRun) { Write-Log 'Delivery Optimization cache: would clear (size not measured in dry run)' }
            else {
                try {
                    Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
                    Write-Log ("Delivery Optimization cache: cleared ({0:N2} GB freed)" -f ((Get-FreeGB) - $doBefore))
                }
                catch { Write-Log "Delivery Optimization cache: $($_.Exception.Message)" }
            }
        }
    }

    # 6. Recycle Bin (optional)
    if ($EmptyRecycleBin) {
        $binPaths = foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) { Join-Path ($d.DeviceID + '\') '$Recycle.Bin' }
        $items = foreach ($bp in $binPaths) {
            if (Test-Path -LiteralPath $bp) {
                Get-ChildItem -LiteralPath $bp -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }
                }
            }
        }
        $binBytes = [int64]0; $binCount = 0
        foreach ($it in @($items)) {
            $size = [int64]0
            if ($it.PSIsContainer) {
                $size = [int64](Get-ChildItem -LiteralPath $it.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            }
            else { $size = $it.Length }
            if (-not $DryRun) {
                try { Remove-Item -LiteralPath $it.FullName -Recurse -Force -ErrorAction Stop } catch { continue }
            }
            $binBytes += $size; $binCount++
        }
        $script:TotalBytes += $binBytes; $script:TotalFiles += $binCount
        Write-Log ("{0,-28} {1,7} items  {2,9:N1} MB" -f 'Recycle Bin', $binCount, ($binBytes / 1MB))
    }

    # 7. New Teams cache (optional, only where Teams is closed for that user)
    if ($ClearTeamsCache) {
        $teamsOwners = @(Get-Process -Name 'ms-teams' -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object { ($_.UserName -split '\\')[-1] })
        foreach ($pp in $profiles) {
            $user = Split-Path -Path $pp -Leaf
            $tc = Join-Path $pp 'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'
            if (-not (Test-Path -LiteralPath $tc)) { continue }
            if ($teamsOwners -contains $user) { Write-Log "Teams cache ($user): SKIPPED - Teams is running"; continue }
            Remove-Files -Paths @($tc) -Cutoff $now -Label "Teams cache ($user)"
        }
    }

    $freeAfter = Get-FreeGB
    $mb = [math]::Round($script:TotalBytes / 1MB, 1)
    $verb = 'Cleared'
    if ($DryRun) { $verb = 'Would clear' }
    Write-Log ("TOTAL: {0} {1} files, {2:N1} MB. Free on {3}: {4} GB -> {5} GB" -f $verb, $script:TotalFiles, $mb, $env:SystemDrive, $freeBefore, $freeAfter)
    Set-ResultField ("OK | {0:yyyy-MM-dd HH:mm} | {1} {2} MB | free {3} GB" -f (Get-Date), $verb, $mb, $freeAfter)
    exit 0
}
catch {
    Write-Error "Cache cleanup failed: $($_.Exception.Message)"
    Set-ResultField ("FAILED | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $_.Exception.Message)
    exit 1
}

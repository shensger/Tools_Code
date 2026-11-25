#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 1 - installs pending Windows (and Microsoft) updates on demand.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.

    Use this for an on-demand patch run during a maintenance window. Routine patching should
    stay with the NinjaOne patch policy - this script does not change any update settings.

    - Searches Microsoft Update when that service is registered on the device (also covers
      MSI Office and other Microsoft products), otherwise Windows Update. Always online - a
      WSUS server configured by policy is bypassed for this run only.
    - Software updates only by default. Excludes feature upgrades (new Windows versions) and
      preview builds unless allowed. Drivers only with includeDrivers (driver/BIOS updates are
      normally done by Update-DriversBIOS.ps1 with the OEM tool).
    - Accepts EULAs, downloads, installs, and reports each update's result.
    - Never reboots. Reports whether a reboot is required.

    Ninja script variables (all optional):
      includeDrivers        Checkbox  Also install driver updates from Windows Update.
      allowFeatureUpdates   Checkbox  Allow Windows feature upgrades (e.g. 23H2 -> 24H2).
      scanOnly              Checkbox  List what would be installed, install nothing.
      ninjaField            Text      Device text field for the one-line result. Default none.

.OUTPUTS
    Exit codes: 0 success / nothing to install, 1 one or more updates failed, 2 error.
#>
[CmdletBinding()]
param(
    [switch]$IncludeDrivers,
    [switch]$AllowFeatureUpdates,
    [switch]$ScanOnly,
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

if ($env:includeDrivers -eq 'true')      { $IncludeDrivers = $true }
if ($env:allowFeatureUpdates -eq 'true') { $AllowFeatureUpdates = $true }
if ($env:scanOnly -eq 'true')            { $ScanOnly = $true }

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 2
}

$MicrosoftUpdateId = '7971f918-a847-4430-9279-4a52d1efe18d'
$ResultNames = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }

try {
    Write-Log "Org: $env:NINJA_ORGANIZATION_NAME  Device: $env:COMPUTERNAME  Drivers=$IncludeDrivers  FeatureUpdates=$AllowFeatureUpdates  ScanOnly=$ScanOnly"

    $session  = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'Netrique Workstation Maintenance'
    $searcher = $session.CreateUpdateSearcher()

    $svcMgr = New-Object -ComObject Microsoft.Update.ServiceManager
    $muRegistered = $false
    foreach ($s in $svcMgr.Services) { if ($s.ServiceID -eq $MicrosoftUpdateId) { $muRegistered = $true } }
    if ($muRegistered) {
        $searcher.ServerSelection = 3      # ssOthers
        $searcher.ServiceID = $MicrosoftUpdateId
        Write-Log 'Source: Microsoft Update (Windows + other Microsoft products)'
    }
    else {
        $searcher.ServerSelection = 2      # ssWindowsUpdate
        Write-Log 'Source: Windows Update (Microsoft Update service not registered)'
    }

    $criteria = "IsInstalled=0 and IsHidden=0 and Type='Software'"
    if ($IncludeDrivers) { $criteria = "IsInstalled=0 and IsHidden=0" }
    Write-Log "Searching ($criteria)... this can take several minutes"
    $result = $searcher.Search($criteria)

    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    $skipped = 0
    foreach ($u in $result.Updates) {
        $cats = @($u.Categories | ForEach-Object { $_.Name })
        $isFeature = ($cats -contains 'Upgrades') -or ($u.Title -match '(?i)feature update')
        $isPreview = $u.Title -match '(?i)\bpreview\b'
        $isDriver  = ($u.Type -eq 2) -or ($cats -contains 'Drivers')
        $reason = $null
        if ($isFeature -and -not $AllowFeatureUpdates) { $reason = 'feature upgrade' }
        elseif ($isPreview) { $reason = 'preview' }
        elseif ($isDriver -and -not $IncludeDrivers) { $reason = 'driver' }
        elseif ($u.InstallationBehavior.CanRequestUserInput) { $reason = 'needs user input' }
        if ($reason) { Write-Log "  skip ($reason): $($u.Title)"; $skipped++; continue }
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        $kb = ''
        if ($u.KBArticleIDs.Count -gt 0) { $kb = 'KB' + $u.KBArticleIDs.Item(0) }
        Write-Log ("  queue: {0} {1} ({2:N0} MB)" -f $kb, $u.Title, ($u.MaxDownloadSize / 1MB))
        [void]$toInstall.Add($u)
    }

    Write-Log "Found $($result.Updates.Count) update(s): $($toInstall.Count) to install, $skipped skipped"
    if ($toInstall.Count -eq 0) {
        Set-ResultField ("OK | {0:yyyy-MM-dd HH:mm} | nothing to install" -f (Get-Date))
        exit 0
    }
    if ($ScanOnly) {
        Set-ResultField ("SCAN | {0:yyyy-MM-dd HH:mm} | {1} pending" -f (Get-Date), $toInstall.Count)
        exit 0
    }

    Write-Log 'Downloading...'
    $dl = $session.CreateUpdateDownloader()
    $dl.Updates = $toInstall
    $dlResult = $dl.Download()
    Write-Log "Download result: $($ResultNames[[int]$dlResult.ResultCode])"

    $ready = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $toInstall) { if ($u.IsDownloaded) { [void]$ready.Add($u) } else { Write-Log "  not downloaded: $($u.Title)" } }
    if ($ready.Count -eq 0) { throw 'No updates downloaded successfully.' }

    Write-Log "Installing $($ready.Count) update(s)..."
    $inst = $session.CreateUpdateInstaller()
    $inst.Updates = $ready
    $inst.ForceQuiet = $true
    $instResult = $inst.Install()

    $ok = 0; $bad = 0
    for ($i = 0; $i -lt $ready.Count; $i++) {
        $r = $instResult.GetUpdateResult($i)
        $code = [int]$r.ResultCode
        if ($code -eq 2 -or $code -eq 3) { $ok++ } else { $bad++ }
        Write-Log ("  {0}: {1}  (HResult 0x{2:X8})" -f $ResultNames[$code], $ready.Item($i).Title, $r.HResult)
    }
    $bad += ($toInstall.Count - $ready.Count)

    $reboot = $instResult.RebootRequired
    Write-Log "RESULT: installed=$ok failed=$bad rebootRequired=$reboot"
    $status = 'OK'
    if ($bad -gt 0) { $status = 'PARTIAL' }
    $rb = ''
    if ($reboot) { $rb = ' | reboot required' }
    Set-ResultField ("{0} | {1:yyyy-MM-dd HH:mm} | installed={2} failed={3}{4}" -f $status, (Get-Date), $ok, $bad, $rb)
    if ($bad -gt 0) { exit 1 }
    exit 0
}
catch {
    $msg = $_.Exception.Message
    if ($_.Exception.HResult) { $msg = "{0} (0x{1:X8})" -f $msg, $_.Exception.HResult }
    Write-Error "Windows Update run failed: $msg"
    Set-ResultField ("ERROR | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $msg)
    exit 2
}

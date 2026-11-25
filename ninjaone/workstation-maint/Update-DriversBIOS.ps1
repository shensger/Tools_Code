#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 2 - installs driver, firmware and (optionally) BIOS updates
    with the manufacturer's tool, falling back to Windows Update drivers.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.

    Manufacturer      Tool used                                     Must already be installed?
    ---------------------------------------------------------------------------------------------
    Dell              Dell Command | Update CLI (dcu-cli.exe)       Yes - deploy DCU with NinjaOne
    HP                HP Image Assistant (HPImageAssistant.exe)     Yes - or set hpiaPath
    Lenovo            LSUClient PowerShell module (PSGallery)       No - installed automatically
    Anything else     Windows Update driver updates                 -
    (Windows Update is also the fallback when the Dell/HP tool is missing, unless disabled.)

    BIOS updates (updateScope = DriversAndBIOS):
      - Skipped automatically if the device is on battery (unless allowOnBattery).
      - BitLocker: Dell DCU suspends it itself (-autoSuspendBitLocker=enable) and HP Image
        Assistant suspends it for BIOS SoftPaqs. For Lenovo the script suspends BitLocker for
        one reboot only when a BIOS update is actually being installed.
      - Nothing reboots. The BIOS flash happens on the next restart (maintenance step 9).

    Logs and downloads: C:\ProgramData\Netrique\Maint\Drivers\<timestamp>\

    Ninja script variables (all optional):
      updateScope      Dropdown  Drivers (default; drivers + firmware) | DriversAndBIOS
      scanOnly         Checkbox  List applicable updates, install nothing.
      allowOnBattery   Checkbox  Allow BIOS updates on battery power. Default false.
      wuFallback       Checkbox  Use Windows Update drivers when the OEM tool is missing. Default true.
      hpiaPath         Text      Full path to HPImageAssistant.exe if not in a standard location.
      ninjaField       Text      Device text field for the one-line result. Default none.

.OUTPUTS
    Exit codes: 0 success / nothing to do, 1 one or more updates failed, 2 error,
    3 OEM tool missing and wuFallback disabled.
#>
[CmdletBinding()]
param(
    [ValidateSet('Drivers', 'DriversAndBIOS', '')]
    [string]$UpdateScope = $env:updateScope,
    [switch]$ScanOnly,
    [switch]$AllowOnBattery,
    [string]$HpiaPath = $env:hpiaPath,
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

if ([string]::IsNullOrWhiteSpace($UpdateScope)) { $UpdateScope = 'Drivers' }
if ($env:scanOnly -eq 'true')       { $ScanOnly = $true }
if ($env:allowOnBattery -eq 'true') { $AllowOnBattery = $true }
$WuFallback = $true
if ($env:wuFallback -eq 'false')    { $WuFallback = $false }

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 2
}

$WorkDir = Join-Path $env:ProgramData ("Netrique\Maint\Drivers\{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Test-OnAcPower {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        return ([string][System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus -ne 'Offline')
    }
    catch { return $true }   # desktops / unknown: treat as AC
}

function Invoke-Tool([string]$File, [string]$Arguments, [int]$TimeoutMinutes = 120) {
    Write-Log "Running: $File $Arguments"
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    $null = $p.Handle   # cache the handle so ExitCode is readable (PS 5.1 quirk)
    if (-not $p.WaitForExit($TimeoutMinutes * 60000)) {
        try { $p.Kill() } catch { }
        throw "$([IO.Path]::GetFileName($File)) timed out after $TimeoutMinutes minutes"
    }
    return $p.ExitCode
}

function Invoke-DellUpdate([bool]$Bios) {
    $dcu = @("$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe", "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe") |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $dcu) { return $null }
    $types = 'driver,firmware'
    if ($Bios) { $types = 'bios,driver,firmware' }
    $log = Join-Path $WorkDir 'dcu.log'
    if ($ScanOnly) { $a = "/scan -silent -updateType=$types -outputLog=`"$log`"" }
    else { $a = "/applyUpdates -silent -reboot=disable -autoSuspendBitLocker=enable -updateType=$types -outputLog=`"$log`"" }
    $code = Invoke-Tool $dcu $a
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 40 | ForEach-Object { Write-Output "    $_" } }
    # 0 ok, 1 reboot required, 5 reboot + rescan required, 500 no updates found
    $map = @{ 0 = 'OK'; 1 = 'OK (reboot required)'; 5 = 'OK (reboot and rescan required)'; 500 = 'No updates found'; 2 = 'Fatal error'; 3 = 'Error'; 4 = 'Not a supported Dell system'; 6 = 'Another DCU instance is running' }
    $text = $map[[int]$code]
    if (-not $text) { $text = 'See DCU exit code reference' }
    Write-Log "Dell Command | Update exit $code - $text"
    return [pscustomobject]@{ Tool = 'DCU'; Ok = (@(0, 1, 5, 500) -contains $code); Detail = "exit $code $text" }
}

function Invoke-HpUpdate([bool]$Bios) {
    $cands = @($HpiaPath, "$env:ProgramFiles\HP\HPIA\HPImageAssistant.exe", "${env:ProgramFiles(x86)}\HP\HPIA\HPImageAssistant.exe",
               "$env:SystemDrive\HPIA\HPImageAssistant.exe", "$env:SystemDrive\SWSetup\HPIA\HPImageAssistant.exe")
    $hpia = $cands | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $hpia) { return $null }
    $cats = 'Drivers,Firmware'
    if ($Bios) { $cats = 'BIOS,Drivers,Firmware' }
    $action = 'Install'
    if ($ScanOnly) { $action = 'List' }
    $a = "/Operation:Analyze /Category:$cats /Selection:All /Action:$action /Silent /ReportFolder:`"$WorkDir\report`" /SoftpaqDownloadFolder:`"$WorkDir\softpaqs`""
    $code = Invoke-Tool $hpia $a
    $map = @{ 0 = 'OK'; 256 = 'No recommendations'; 257 = 'No recommendations selected'; 3010 = 'OK (reboot required)'; 3020 = 'One or more installs failed'; 4096 = 'Platform not supported'; 4097 = 'Invalid parameters'; 8199 = 'SoftPaq download failed' }
    $text = $map[[int]$code]
    if (-not $text) { $text = 'See HPIA exit code reference' }
    $json = Get-ChildItem -LiteralPath (Join-Path $WorkDir 'report') -Filter '*.json' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($json) { Write-Log "HPIA report: $($json.FullName)" }
    Write-Log "HP Image Assistant exit $code - $text"
    return [pscustomobject]@{ Tool = 'HPIA'; Ok = (@(0, 256, 257, 3010) -contains $code); Detail = "exit $code $text" }
}

function Invoke-LenovoUpdate([bool]$Bios) {
    if (-not (Get-Module -ListAvailable -Name LSUClient)) {
        Write-Log 'Installing LSUClient module from PSGallery...'
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }
        Install-Module -Name LSUClient -Repository PSGallery -Scope AllUsers -Force -AllowClobber
    }
    Import-Module -Name LSUClient -Force

    $types = @('Driver', 'Firmware')
    if ($Bios) { $types += 'BIOS' }
    $all = @(Get-LSUpdate)
    $updates = @($all | Where-Object { $_.Installer.Unattended -and ($types -contains [string]$_.Type) })
    Write-Log "Lenovo: $($all.Count) applicable package(s), $($updates.Count) unattended $($types -join '/') update(s)"
    foreach ($u in $updates) { Write-Log ("  {0} [{1}] {2}" -f $u.ID, $u.Type, $u.Title) }
    if ($updates.Count -eq 0 -or $ScanOnly) { return [pscustomobject]@{ Tool = 'LSUClient'; Ok = $true; Detail = "$($updates.Count) update(s) applicable" } }

    if (@($updates | Where-Object { [string]$_.Type -eq 'BIOS' }).Count -gt 0) {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($bl -and [string]$bl.ProtectionStatus -eq 'On') {
            Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 | Out-Null
            Write-Log 'BitLocker suspended for 1 reboot (Lenovo BIOS update queued)'
        }
    }

    $updates | Save-LSUpdate -Path (Join-Path $WorkDir 'lenovo') | Out-Null
    $results = @($updates | Install-LSUpdate -Path (Join-Path $WorkDir 'lenovo'))
    $failed = 0
    foreach ($r in $results) {
        $state = 'OK'
        if (-not $r.Success) { $state = "FAILED ($($r.FailureReason))"; $failed++ }
        Write-Log ("  {0}: {1}  pending={2}" -f $state, $r.Title, $r.PendingAction)
    }
    return [pscustomobject]@{ Tool = 'LSUClient'; Ok = ($failed -eq 0); Detail = "installed=$($results.Count - $failed) failed=$failed" }
}

function Invoke-WuDriverUpdate {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.ServerSelection = 2   # Windows Update online (bypasses WSUS for this run)
    Write-Log 'Searching Windows Update for driver updates...'
    $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $res.Updates) {
        Write-Log "  $($u.Title)"
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$coll.Add($u)
    }
    if ($coll.Count -eq 0 -or $ScanOnly) { return [pscustomobject]@{ Tool = 'WindowsUpdate'; Ok = $true; Detail = "$($coll.Count) driver update(s) applicable" } }
    $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
    $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll; $inst.ForceQuiet = $true
    $r = $inst.Install()
    $bad = 0
    for ($i = 0; $i -lt $coll.Count; $i++) {
        $code = [int]$r.GetUpdateResult($i).ResultCode
        if ($code -ne 2 -and $code -ne 3) { $bad++; Write-Log "  FAILED: $($coll.Item($i).Title)" }
    }
    return [pscustomobject]@{ Tool = 'WindowsUpdate'; Ok = ($bad -eq 0); Detail = "installed=$($coll.Count - $bad) failed=$bad reboot=$($r.RebootRequired)" }
}

try {
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $make = [string]$cs.Manufacturer
    Write-Log ("Org: {0}  Device: {1}  {2} {3}  BIOS {4}  Scope={5}  ScanOnly={6}" -f $env:NINJA_ORGANIZATION_NAME, $env:COMPUTERNAME, $make, $cs.Model, $bios.SMBIOSBIOSVersion, $UpdateScope, $ScanOnly)

    $doBios = ($UpdateScope -eq 'DriversAndBIOS')
    if ($doBios -and -not $ScanOnly -and -not $AllowOnBattery -and -not (Test-OnAcPower)) {
        Write-Log 'WARNING: on battery power - BIOS updates removed from scope (set allowOnBattery to override)'
        $doBios = $false
    }

    $result = $null
    $oemMissing = $false
    if ($make -match '(?i)dell') {
        $result = Invoke-DellUpdate $doBios
        if (-not $result) { $oemMissing = $true; Write-Log 'Dell Command | Update is not installed - deploy it from NinjaOne software / app deployment.' }
    }
    elseif ($make -match '(?i)^(hp|hewlett)') {
        $result = Invoke-HpUpdate $doBios
        if (-not $result) { $oemMissing = $true; Write-Log 'HP Image Assistant not found - deploy it (or set hpiaPath).' }
    }
    elseif ($make -match '(?i)lenovo') {
        $result = Invoke-LenovoUpdate $doBios
    }
    else {
        Write-Log "No OEM tool for '$make' - using Windows Update drivers."
    }

    if (-not $result) {
        if ($oemMissing -and -not $WuFallback) {
            Set-ResultField ("NO_TOOL | {0:yyyy-MM-dd HH:mm} | {1} tool missing" -f (Get-Date), $make)
            exit 3
        }
        $result = Invoke-WuDriverUpdate
        if ($oemMissing) { $result.Detail = "OEM tool missing; " + $result.Detail }
    }

    $status = 'OK'
    if (-not $result.Ok) { $status = 'FAILED' }
    if ($ScanOnly) { $status = 'SCAN' }
    Write-Log "RESULT: $status via $($result.Tool) - $($result.Detail)"
    Set-ResultField ("{0} | {1:yyyy-MM-dd HH:mm} | {2} | {3}" -f $status, (Get-Date), $result.Tool, $result.Detail)
    if (-not $result.Ok) { exit 1 }
    exit 0
}
catch {
    Write-Error "Driver/BIOS update failed: $($_.Exception.Message)"
    Set-ResultField ("ERROR | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $_.Exception.Message)
    exit 2
}

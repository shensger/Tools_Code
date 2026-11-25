#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 6b - finds and (only when told to) silently removes unwanted software.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.

    Audit mode (default) - changes nothing:
      Lists installed programs (HKLM 64/32-bit and per-user installs of logged-on users) that
      match a built-in list of common PUPs / adware / "optimizer" tools, plus anything matching
      softwareNames. Shows the uninstall method that Remove mode would use.

    Remove mode - removes ONLY entries matching softwareNames (the built-in PUP list is never
    removed automatically; copy the names you approve into softwareNames):
      - MSI: msiexec /x {ProductCode} /qn /norestart
      - QuietUninstallString when the vendor provides one
      - Inno Setup (unins###.exe): /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
      - NSIS (uninst*.exe / Uninstall*.exe with NSIS markers): /S
      - Anything else is reported as MANUAL - nothing is guessed.
      Each uninstall has a 10 minute timeout, and every entry is re-checked afterwards.

    Safety:
      - Refuses patterns that are too broad (e.g. "*", or fewer than 4 literal characters).
      - Refuses if one pattern matches more than 5 programs.
      - Never removes the security / RMM stack or Microsoft runtimes (protected list below),
        even if a pattern matches them.

    Ninja script variables:
      mode           Dropdown  Audit (default) | Remove
      softwareNames  Text      Comma-separated display names; wildcards allowed
                               (e.g. "Wave Browser,OneLaunch*,WebCompanion")
      ninjaField     Text      Device text field for the one-line result. Default none.

.OUTPUTS
    Exit codes: 0 nothing found / all removed, 1 something found (Audit) or a removal
    failed / needs manual action, 2 error or unsafe input.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Remove', '')]
    [string]$Mode = $env:mode,
    [string]$SoftwareNames = $env:softwareNames,
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

if ([string]::IsNullOrWhiteSpace($Mode)) { $Mode = 'Audit' }

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 2
}

# Common PUP / adware / scareware "optimizers" - reported in Audit, never auto-removed.
$PupPatterns = @(
    '*Wave Browser*', 'OneLaunch*', '*Shift Browser*', '*WebCompanion*', '*Web Companion*', '*WebDiscover*',
    '*PC App Store*', '*Search Protect*', '*Conduit*', '*Ask Toolbar*', '*Yahoo*Toolbar*', '*Toolbar*',
    '*Driver Booster*', '*Driver Support*', '*DriverMax*', '*Driver Easy*', '*Advanced SystemCare*',
    '*PC Accelerate*', '*PC Cleaner*', '*MyPC Utilities*', '*Reimage*', '*Restoro*', '*Fortect*',
    '*Segurazo*', '*SAntivirus*', '*ByteFence*', '*Total AV*', '*TotalAV*', '*PC Matic*', '*Slimware*',
    '*Mindspark*', '*Clario*', '*CleanMyPC*', '*AVG TuneUp*', '*Avast Cleanup*', '*McAfee WebAdvisor*',
    '*Norton Safe Web*', '*Avast Secure Browser*', '*AVG Secure Browser*', 'Chromium'
)

# Never removed, whatever softwareNames says.
$Protected = @(
    '*NinjaRMM*', '*Ninja*Agent*', '*NinjaOne*', '*Bitdefender*', '*Endpoint Security*', '*Rapid7*', '*Insight Agent*',
    '*Duo *', '*Duo Authentication*', '*Cyrisma*', '*AutoElevate*', '*CrowdStrike*', '*Ironscales*', '*Wazuh*',
    '*SentinelOne*', '*Windows Defender*', 'Microsoft Visual C++*', 'Microsoft .NET*', 'Microsoft Windows*',
    'Microsoft Edge*', 'Microsoft Office*', 'Microsoft 365*', 'Microsoft Teams*', 'Office 16 Click-to-Run*',
    '*Windows Driver Package*', '*BitLocker*', '*ScreenConnect*', '*ConnectWise*'
)

function Test-Like([string]$Text, [string[]]$Patterns) {
    foreach ($p in $Patterns) { if ($Text -like $p) { return $true } }
    return $false
}

function Get-InstalledPrograms {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    # Per-user installs for users whose hive is loaded (logged on). PUPs often install per-user.
    foreach ($k in (Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -match '^S-1-5-21-[\d-]+$') {
            $roots += "Registry::HKEY_USERS\$($k.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        }
    }
    foreach ($r in $roots) {
        if (-not (Test-Path -Path $r)) { continue }
        foreach ($sub in (Get-ChildItem -Path $r -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or [string]::IsNullOrWhiteSpace($p.DisplayName)) { continue }
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName) { continue }
            $scope = 'Machine'
            if ($r -like 'Registry::HKEY_USERS*') { $scope = 'User:' + ($r -split '\\')[1] }
            [pscustomobject]@{
                Name        = [string]$p.DisplayName
                Version     = [string]$p.DisplayVersion
                Publisher   = [string]$p.Publisher
                Key         = $sub.PSChildName
                KeyPath     = $sub.PSPath
                Scope       = $scope
                IsMsi       = ($p.WindowsInstaller -eq 1) -or ([string]$p.UninstallString -match '(?i)msiexec')
                Uninstall   = [string]$p.UninstallString
                QuietUninst = [string]$p.QuietUninstallString
            }
        }
    }
}

function Get-UninstallCommand($App) {
    # Returns @{ File; Args; Method } or $null when no safe silent method is known.
    if ($App.IsMsi) {
        $code = $null
        if ($App.Key -match '^\{[0-9A-Fa-f\-]{36}\}$') { $code = $App.Key }
        elseif ($App.Uninstall -match '(\{[0-9A-Fa-f\-]{36}\})') { $code = $Matches[1] }
        if ($code) { return @{ File = "$env:windir\System32\msiexec.exe"; Args = "/x $code /qn /norestart"; Method = 'MSI' } }
    }
    $cmd = $App.QuietUninst
    $method = 'QuietUninstallString'
    if ([string]::IsNullOrWhiteSpace($cmd)) {
        $cmd = $App.Uninstall
        $method = $null
    }
    if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }

    # Split "C:\path\uninst.exe" args  or  C:\path\uninst.exe args
    $exe = $null; $rest = ''
    if ($cmd -match '^\s*"([^"]+)"\s*(.*)$') { $exe = $Matches[1]; $rest = $Matches[2] }
    elseif ($cmd -match '^\s*(.+?\.exe)\s*(.*)$') { $exe = $Matches[1]; $rest = $Matches[2] }
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) { return $null }

    if (-not $method) {
        $leaf = Split-Path -Path $exe -Leaf
        if ($leaf -match '(?i)^unins\d{3}\.exe$') {
            $method = 'Inno'; $rest = ($rest + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART').Trim()
        }
        else {
            $isNsis = $false
            try {
                $bytes = [IO.File]::ReadAllBytes($exe)
                $text  = [Text.Encoding]::ASCII.GetString($bytes)
                if ($text -match 'Nullsoft|NSIS') { $isNsis = $true }
            } catch { }
            if ($isNsis) { $method = 'NSIS'; $rest = ($rest + ' /S').Trim() }
        }
    }
    if (-not $method) { return $null }
    return @{ File = $exe; Args = $rest; Method = $method }
}

try {
    Write-Log "Org: $env:NINJA_ORGANIZATION_NAME  Device: $env:COMPUTERNAME  Mode=$Mode"

    $requested = @()
    if (-not [string]::IsNullOrWhiteSpace($SoftwareNames)) {
        $requested = @($SoftwareNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    foreach ($pat in $requested) {
        $literal = ($pat -replace '[\*\?\[\]]', '')
        if ($literal.Length -lt 4) {
            Write-Error "Pattern '$pat' is too broad (needs at least 4 literal characters)."
            exit 2
        }
    }
    if ($Mode -eq 'Remove' -and $requested.Count -eq 0) {
        Write-Error 'Remove mode needs softwareNames (comma-separated). Run Audit first and copy the names you approve.'
        exit 2
    }

    $apps = @(Get-InstalledPrograms)
    Write-Log "Installed programs scanned: $($apps.Count)"

    $pups = @($apps | Where-Object { (Test-Like $_.Name $PupPatterns) -and -not (Test-Like $_.Name $Protected) })
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($pat in $requested) {
        $m = @($apps | Where-Object { $_.Name -like $pat })
        if ($m.Count -gt 5) {
            Write-Error "Pattern '$pat' matches $($m.Count) programs - too broad. Narrow it."
            exit 2
        }
        if ($m.Count -eq 0) { Write-Log "Not installed: '$pat'" }
        foreach ($a in $m) {
            if (Test-Like $a.Name $Protected) { Write-Log "PROTECTED - will not remove: $($a.Name)"; continue }
            if (-not ($targets | Where-Object { $_.KeyPath -eq $a.KeyPath })) { $targets.Add($a) }
        }
    }

    if ($pups.Count -gt 0) {
        Write-Log "Possible PUP / adware / optimizer software ($($pups.Count)):"
        foreach ($a in $pups) {
            $u = Get-UninstallCommand $a
            $how = 'MANUAL'
            if ($u) { $how = $u.Method }
            Write-Log ("  {0} {1} [{2}] scope={3} uninstall={4}" -f $a.Name, $a.Version, $a.Publisher, $a.Scope, $how)
        }
    }
    else { Write-Log 'No common PUP / adware entries found.' }

    if ($Mode -eq 'Audit') {
        foreach ($a in $targets) { Write-Log ("Requested (would remove): {0} {1} scope={2}" -f $a.Name, $a.Version, $a.Scope) }
        $n = $pups.Count + $targets.Count
        Set-ResultField ("AUDIT | {0:yyyy-MM-dd HH:mm} | pups={1} requested={2}" -f (Get-Date), $pups.Count, $targets.Count)
        if ($n -gt 0) { exit 1 }
        exit 0
    }

    # ---- Remove mode --------------------------------------------------------------------------
    $removed = 0; $failed = 0; $manual = 0
    foreach ($a in $targets) {
        $u = Get-UninstallCommand $a
        if (-not $u) {
            Write-Log "MANUAL: $($a.Name) - no safe silent uninstall method. UninstallString: $($a.Uninstall)"
            $manual++; continue
        }
        Write-Log ("Removing {0} {1} via {2}: {3} {4}" -f $a.Name, $a.Version, $u.Method, $u.File, $u.Args)
        try {
            $sp = @{ FilePath = $u.File; PassThru = $true; WindowStyle = 'Hidden' }
            if (-not [string]::IsNullOrWhiteSpace($u.Args)) { $sp.ArgumentList = $u.Args }
            $proc = Start-Process @sp
            $null = $proc.Handle   # cache the handle so ExitCode is readable after exit (PS 5.1 quirk)
            if (-not $proc.WaitForExit(600000)) {
                try { $proc.Kill() } catch { }
                Write-Log "  FAILED: timed out after 10 minutes"; $failed++; continue
            }
            $code = $proc.ExitCode
            Start-Sleep -Seconds 3
            $still = Test-Path -LiteralPath $a.KeyPath
            if ((@(0, 3010, 1641, 1605) -contains $code) -and -not $still) {
                Write-Log "  REMOVED (exit $code)"; $removed++
            }
            elseif (-not $still) { Write-Log "  REMOVED (exit $code, entry gone)"; $removed++ }
            else { Write-Log "  FAILED: exit $code and the program is still registered"; $failed++ }
        }
        catch { Write-Log "  FAILED: $($_.Exception.Message)"; $failed++ }
    }

    Write-Log "RESULT: removed=$removed failed=$failed manual=$manual"
    Set-ResultField ("REMOVE | {0:yyyy-MM-dd HH:mm} | removed={1} failed={2} manual={3}" -f (Get-Date), $removed, $failed, $manual)
    if ($failed -gt 0 -or $manual -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Error "Unwanted software check failed: $($_.Exception.Message)"
    Set-ResultField ("ERROR | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $_.Exception.Message)
    exit 2
}

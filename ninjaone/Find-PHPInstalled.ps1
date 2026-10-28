<#
.SYNOPSIS
    Finds PHP installs on a Windows device and flags versions affected by the Oct 2026
    "PHP2Shell" RCE bugs (CVE-2026-109618 / CVE-2026-109619). Writes a one-line result to a
    NinjaOne custom field.

.DESCRIPTION
    Built to run as SYSTEM from NinjaOne across every Windows device, as the host-side complement
    to network\Find-PHPExposure.ps1 (which finds PHP from the network). Read-only.

    Looks for:
      - php.exe / php-cgi.exe / php-win.exe and the PHP runtime / Apache module DLLs
        (php8ts.dll, php8.dll, php8apache2_4.dll, php7..., php5...) on all fixed drives
        (Full, default) or in the usual install locations (Quick)
      - PHP referenced by IIS FastCGI (applicationHost.config), services, and running processes
      - installed-programs entries for PHP / XAMPP / WampServer / Laragon / Bitnami
    Version comes from the binary's file version info; php.exe -v is only run as a fallback.

    Per-install verdict (fixed releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35):
      VULNERABLE    below the fixed release for its branch
      UNSUPPORTED   PHP 8.1 or older (no upstream fix)
      UNKNOWN       PHP found but version couldn't be read
      PATCHED       at or above the fix
    "Web" column: Yes = referenced by IIS FastCGI / a service / a running php-cgi or web server
    process; Bundled = sits inside another app's folder (vendor needs to ship the fix); No = CLI only.

.NINJA SCRIPT VARIABLES (optional)
    ninjaField   device text field for the result (default phpStatus; "none" = don't write)
    scanMode     Full (default - all fixed drives except \Windows) or Quick (known locations only)

.NOTES
    Repo: shensger/tools_code
    Exit codes: 0 = no PHP or all patched, 1 = VULNERABLE / UNSUPPORTED / UNKNOWN found, 2 = error.
    Field value: "NO_PHP | <timestamp>" or "<WORST> | <timestamp> | <version> <path> [web]; ..."
#>

[CmdletBinding()]
param(
    [string]  $NinjaField  = $(if ($env:ninjaField) { $env:ninjaField } else { 'phpStatus' }),
    [ValidateSet('Full', 'Quick')]
    [string]  $ScanMode    = $(if ($env:scanMode -eq 'Quick') { 'Quick' } else { 'Full' }),
    [string[]]$SearchRoots
)

$ErrorActionPreference = 'Continue'
$started = Get-Date
$FixedIn = @{ '8.2' = 35; '8.3' = 36; '8.4' = 27; '8.5' = 12 }
$FixedText = '8.5.12 / 8.4.27 / 8.3.36 / 8.2.35'
$BinRx = '^(php\.exe|php-cgi\.exe|php-win\.exe|php[5-8](ts)?\.dll|php[5-8]apache2_4\.dll)$'

function Set-Field([string]$Value) {
    if (-not $NinjaField -or $NinjaField -eq 'none') { return }
    if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) { return }
    if ($Value.Length -gt 9500) { $Value = $Value.Substring(0, 9500) + ' ...[truncated]' }
    try { Ninja-Property-Set $NinjaField $Value; Write-Output "Wrote result to custom field '$NinjaField'." }
    catch { Write-Output "WARNING: could not write custom field '$NinjaField': $($_.Exception.Message)" }
}

function Get-Verdict([string]$ver) {
    if ($ver -notmatch '^(\d+)\.(\d+)\.(\d+)') { return 'UNKNOWN' }
    $maj = [int]$matches[1]; $min = [int]$matches[2]; $pat = [int]$matches[3]
    if ($maj -lt 8 -or ($maj -eq 8 -and $min -le 1)) { return 'UNSUPPORTED' }
    $mm = "$maj.$min"
    if ($FixedIn.ContainsKey($mm) -and $pat -lt $FixedIn[$mm]) { return 'VULNERABLE' }
    if ($mm -eq '8.6' -and $ver -match '(?i)8\.6\.0[-_]?(alpha|beta|dev|RC[0-3]\b)') { return 'VULNERABLE' }
    return 'PATCHED'
}

# Walk a directory tree without following junctions, ignoring access errors
function Find-PhpFiles([string]$root, [string[]]$skip) {
    $found = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[string]
    if (-not (Test-Path -LiteralPath $root)) { return $found }
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, 'php*')) {
                if ([System.IO.Path]::GetFileName($f) -match $BinRx) { $found.Add($f) }
            }
        } catch { }
        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                $skipIt = $false
                foreach ($s in $skip) { if ($d -ieq $s) { $skipIt = $true; break } }
                if ($skipIt) { continue }
                try {
                    $attr = [System.IO.File]::GetAttributes($d)
                    if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                } catch { continue }
                $stack.Push($d)
            }
        } catch { }
    }
    return $found
}

function Get-PhpVersion([string]$path) {
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        foreach ($v in @($vi.ProductVersion, $vi.FileVersion)) {
            if ($v -and $v -match '(\d+\.\d+\.\d+(?:[-_]?(?:RC|alpha|beta|dev)\d*)?)') { return $matches[1] }
        }
    } catch { }
    # Fallback: ask php.exe itself (no php.ini loaded), with a timeout
    if ($path -match '(?i)\\php(-cgi)?\.exe$') {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $path; $psi.Arguments = '-n -v'
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            if ($p.WaitForExit(10000)) {
                $out = $p.StandardOutput.ReadToEnd()
                if ($out -match 'PHP (\d+\.\d+\.\d+\S*)') { return $matches[1] }
            } else { try { $p.Kill() } catch { } }
        } catch { }
    }
    return ''
}

try {
    # ---------------- where to look ----------------
    $sysRoot = $env:SystemRoot
    $skip = @()
    if ($sysRoot) { $skip += $sysRoot }
    $roots = @()
    if ($SearchRoots) { $roots = $SearchRoots }
    elseif ($ScanMode -eq 'Full') {
        $roots = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName })
        foreach ($r in $roots) { $skip += (Join-Path $r '$Recycle.Bin'); $skip += (Join-Path $r 'System Volume Information') }
    }
    else {
        $roots = @('C:\php', 'C:\xampp', 'C:\wamp', 'C:\wamp64', 'C:\laragon', 'C:\tools', 'C:\inetpub', 'C:\Bitnami',
                   $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
        $roots += @(Get-ChildItem 'C:\' -Directory -Filter 'php*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $roots += @(Get-ChildItem 'C:\Users\*\scoop' -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $roots += @(($env:Path -split ';') | Where-Object { $_ -match '(?i)php' })
        $roots = @($roots | Where-Object { $_ } | Select-Object -Unique)
    }

    $files = New-Object System.Collections.Generic.List[string]
    foreach ($r in $roots) { foreach ($f in (Find-PhpFiles $r $skip)) { if (-not $files.Contains($f)) { $files.Add($f) } } }

    # ---------------- web-serving references ----------------
    $webRefs = New-Object System.Collections.Generic.List[string]   # directories referenced by a web server / service
    $notes   = New-Object System.Collections.Generic.List[string]
    $appHost = ''
    if ($env:SystemRoot) { $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config' }
    if ($appHost -and (Test-Path $appHost)) {
        try {
            [xml]$cfg = Get-Content $appHost -Raw
            foreach ($app in $cfg.configuration.'system.webServer'.fastCgi.application) {
                $fp = [Environment]::ExpandEnvironmentVariables($app.fullPath)
                if ($fp -match '(?i)php') {
                    $webRefs.Add((Split-Path $fp -Parent)); $notes.Add("IIS FastCGI: $fp")
                    if ((Test-Path $fp) -and -not $files.Contains($fp)) { $files.Add($fp) }
                }
            }
        } catch { $notes.Add("Could not read applicationHost.config: $($_.Exception.Message)") }
    }
    $haveCim = [bool](Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
    if ($haveCim) {
    foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match '(?i)php|httpd\.exe|nginx\.exe' })) {
        $exe = ($svc.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1'
        $webRefs.Add((Split-Path $exe -Parent)); $notes.Add("Service $($svc.Name) [$($svc.State)]: $exe")
    }
    foreach ($proc in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)^(php|php-cgi|httpd|nginx)\.exe$' -and $_.ExecutablePath })) {
        $webRefs.Add((Split-Path $proc.ExecutablePath -Parent)); $notes.Add("Running: $($proc.ExecutablePath)")
        if ($proc.Name -match '(?i)^php' -and -not $files.Contains($proc.ExecutablePath)) { $files.Add($proc.ExecutablePath) }
    }
    }
    $uninstall = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    foreach ($e in (Get-ItemProperty $uninstall -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '(?i)\bPHP\b|XAMPP|WampServer|Laragon|Bitnami' })) {
        $notes.Add("Installed program: $($e.DisplayName) $($e.DisplayVersion)")
    }

    # ---------------- group files into installs (one per folder) ----------------
    $installs = @()
    foreach ($g in ($files | Group-Object { Split-Path $_ -Parent })) {
        $dir = $g.Name
        # prefer php.exe / php-cgi.exe / runtime dll for the version
        $ordered = @($g.Group | Sort-Object { if ($_ -match '(?i)\\php\.exe$') { 0 } elseif ($_ -match '(?i)\\php-cgi\.exe$') { 1 } elseif ($_ -match '(?i)ts\.dll$|\d\.dll$') { 2 } else { 3 } })
        $ver = ''
        foreach ($f in $ordered) { $ver = Get-PhpVersion $f; if ($ver) { break } }
        $web = 'No'
        foreach ($w in $webRefs) { if ($w -and ($dir -ieq $w -or $dir.StartsWith($w + '\', 'OrdinalIgnoreCase') -or $w.StartsWith($dir + '\', 'OrdinalIgnoreCase'))) { $web = 'Yes'; break } }
        if ($web -eq 'No' -and $dir -match '(?i)\\(xampp|wamp\d*|laragon|bitnami|inetpub)\\') { $web = 'Possible' }
        if ($web -eq 'No' -and $dir -match '(?i)\\Program Files( \(x86\))?\\(?!php)[^\\]+\\') { $web = 'Bundled' }
        $installs += [pscustomobject]@{
            Version = $ver
            Status  = (Get-Verdict $ver)
            Web     = $web
            Path    = $dir
            Files   = (($g.Group | ForEach-Object { Split-Path $_ -Leaf }) -join ', ')
        }
    }

    # ---------------- report ----------------
    $ts = $started.ToString('yyyy-MM-dd HH:mm')
    Write-Output "PHP2Shell host check (CVE-2026-109618 / CVE-2026-109619) - $env:COMPUTERNAME - $ts - scan mode $ScanMode"
    Write-Output "Fixed in: $FixedText"
    Write-Output ''
    if (-not $installs) {
        Write-Output 'No PHP found on this device.'
        if ($notes.Count) { Write-Output ''; Write-Output 'Related references:'; $notes | Select-Object -Unique | ForEach-Object { Write-Output "  $_" } }
        Set-Field "NO_PHP | $ts"
        exit 0
    }

    $installs | Sort-Object Status, Path | Format-Table Status, Version, Web, Path, Files -AutoSize | Out-String -Width 250 | Write-Output
    if ($notes.Count) { Write-Output 'Related references:'; $notes | Select-Object -Unique | ForEach-Object { Write-Output "  $_" } }

    $rank = @{ VULNERABLE = 0; UNSUPPORTED = 1; UNKNOWN = 2; PATCHED = 3 }
    $worst = ($installs | Sort-Object { $rank[$_.Status] } | Select-Object -First 1).Status
    $detail = ($installs | Sort-Object { $rank[$_.Status] } | ForEach-Object {
        $v = $_.Version; if (-not $v) { $v = '?' }
        "$($_.Status) $v $($_.Path) [web:$($_.Web)]"
    }) -join '; '
    Write-Output ''
    switch ($worst) {
        'VULNERABLE'  { Write-Output "ACTION: upgrade to $FixedText or later. Installs marked web:Yes/Possible are the priority; web:Bundled means the app vendor has to ship the fix." }
        'UNSUPPORTED' { Write-Output 'ACTION: PHP 8.1 or older has no upstream fix - upgrade to a supported branch or remove it.' }
        'UNKNOWN'     { Write-Output 'ACTION: PHP found but the version could not be read - check it manually (php -v).' }
        default       { Write-Output 'All PHP installs found are at or above the fixed release.' }
    }
    Set-Field "$worst | $ts | $detail"
    if ($worst -eq 'PATCHED') { exit 0 }
    exit 1
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Set-Field "ERROR | $($started.ToString('yyyy-MM-dd HH:mm')) | $($_.Exception.Message)"
    exit 2
}

<#
.SYNOPSIS
    Detects exposure to the "nginx2root" NGINX vulnerabilities (disclosed 2026-11-18) on Windows.

.DESCRIPTION
    CVE-2026-123007  HTTP/2 flow-control underflow -> RCE   (1.9.5  - 1.31.8)  needs: HTTP/2 enabled
    CVE-2026-123633  HTTP/2 use-after-free (proxying)       (1.19.7 - 1.31.8)  needs: HTTP/2 + upstream *_pass
    CVE-2026-123634  Resolver use-after-free                (0.6.18 - 1.31.8)  needs: resolver + variable proxy_pass + mirror/ssi
    CVE-2026-121810  HTTP/3 (QUIC) use-after-free           (1.25.0 - 1.31.8)  needs: quic/http3 + upstream *_pass
    CVE-2026-113425  Mail proxy use-after-free              (0.5.33 - 1.31.8)  needs: mail { proxy on; auth_http }

    Fixed in nginx 1.30.7 (stable) / 1.31.9 (mainline).
    Finds nginx.exe via running processes, services, and common install folders (optionally a
    full fixed-disk search), reads version/build flags (-v/-V) and the full loaded config (-T),
    and reports per-CVE status. Read-only: never reloads or restarts nginx.

.PARAMETER DeepScan
    Also search all fixed drives for nginx.exe (slower).
.PARAMETER NinjaField
    NinjaOne device text field to write "<OVERALL> | <timestamp> | details" to (Ninja-Property-Set).
    Default nginx2rootStatus; script variable ninjaField overrides; "none" disables.
    Only written when running under the NinjaOne agent.
.PARAMETER Json
    Output JSON instead of the text report.

.NOTES
    Exit codes: 0 = clean / no nginx, 1 = VULNERABLE, 2 = in vulnerable range, review, 3 = error.
#>
[CmdletBinding()]
param(
    [switch]$DeepScan,
    [string]$NinjaField = $(if ($env:ninjaField) { $env:ninjaField } else { 'nginx2rootStatus' }),
    [switch]$Json
)

$ErrorActionPreference = 'Continue'
$FixStable   = [version]'1.30.7'
$FixMainline = [version]'1.31.9'
$Cves = [ordered]@{
    'CVE-2026-123007' = @{ First = [version]'1.9.5';  Desc = 'HTTP/2 flow-control underflow (RCE, public PoC)' }
    'CVE-2026-123633' = @{ First = [version]'1.19.7'; Desc = 'HTTP/2 use-after-free when proxying (RCE)' }
    'CVE-2026-123634' = @{ First = [version]'0.6.18'; Desc = 'Resolver use-after-free (resolver+var proxy_pass+mirror/ssi)' }
    'CVE-2026-121810' = @{ First = [version]'1.25.0'; Desc = 'HTTP/3 QUIC use-after-free when proxying (RCE)' }
    'CVE-2026-113425' = @{ First = [version]'0.5.33'; Desc = 'Mail proxy auth_http use-after-free' }
}

function Write-Report([string]$Text) { if (-not $Json) { Write-Output $Text } }

# Run nginx.exe and capture stdout+stderr as plain text (nginx writes -v/-V/-T info to stderr)
function Invoke-Nginx([string]$Exe, [string[]]$NgArgs, [string]$Prefix) {
    # Windows nginx resolves conf/, logs/, temp/ relative to its prefix (default = exe folder)
    $prefix = if ($Prefix) { $Prefix } else { (Split-Path $Exe -Parent) + '\' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (@('-p', "`"$prefix`"") + $NgArgs) -join ' '
    $psi.WorkingDirectory = Split-Path $Exe -Parent
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(30000)) { $p.Kill(); return '' }
        return ($out.Result + "`n" + $err.Result)
    } catch { return '' }
}

# ---------------------------------------------------------------- discovery
$targets = @{}   # exe path -> @{ ConfArg; Note }

Get-CimInstance Win32_Process -Filter "Name='nginx.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.ExecutablePath) {
        $conf = if ($_.CommandLine -match '\s-c\s+"?([^"\s]+)"?') { $Matches[1] } else { '' }
        $pfx  = if ($_.CommandLine -match '\s-p\s+"?([^"]+?)"?(\s|$)') { $Matches[1] } else { '' }
        $note = if (-not (Test-Path $_.ExecutablePath)) { "Running PID $($_.ProcessId) binary no longer on disk - RESTART nginx" } else { '' }
        if (-not $targets.ContainsKey($_.ExecutablePath) -or $conf) { $targets[$_.ExecutablePath] = @{ ConfArg = $conf; Prefix = $pfx; Note = $note } }
    }
}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'nginx' } | ForEach-Object {
    if ($_.PathName -match '"?([A-Za-z]:\\[^"]*?nginx\.exe)"?') {
        $p = $Matches[1]; if ((Test-Path $p) -and -not $targets.ContainsKey($p)) { $targets[$p] = @{ ConfArg = ''; Note = "Service: $($_.Name)" } }
    }
    # NSSM / WinSW wrappers: check the AppDirectory/registry parameters
    $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\Parameters"
    if (Test-Path $reg) {
        $app = (Get-ItemProperty $reg -ErrorAction SilentlyContinue).Application
        if ($app -and $app -match 'nginx\.exe$' -and (Test-Path $app) -and -not $targets.ContainsKey($app)) { $targets[$app] = @{ ConfArg = ''; Note = "Service (wrapped): $($_.Name)" } }
    }
}
$roots = @('C:\nginx*', 'C:\tools\nginx*', 'C:\opt\nginx*', "$env:ProgramFiles\nginx*", "${env:ProgramFiles(x86)}\nginx*", 'C:\ProgramData\chocolatey\lib\nginx*', 'C:\OpenResty*', 'C:\openresty*')
foreach ($r in $roots) {
    # Resolve the wildcard to real folders first. Get-ChildItem -Path 'C:\nginx*' -Recurse would
    # otherwise treat 'nginx*' as a name filter and crawl the whole parent (all of C:\).
    Get-Item -Path $r -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -Filter nginx.exe -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not $targets.ContainsKey($_.FullName)) { $targets[$_.FullName] = @{ ConfArg = ''; Note = '' } }
        }
    }
}
if ($DeepScan) {
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' -and (New-Object System.IO.DriveInfo $_.Root).DriveType -eq 'Fixed' } | ForEach-Object {
        Get-ChildItem -Path $_.Root -Filter nginx.exe -Recurse -ErrorAction SilentlyContinue -Force | ForEach-Object {
            if (-not $targets.ContainsKey($_.FullName)) { $targets[$_.FullName] = @{ ConfArg = ''; Note = 'found by deep scan' } }
        }
    }
}

# ---------------------------------------------------------------- analysis
$results = @()
$overallRank = 0

foreach ($exe in $targets.Keys) {
    $t = $targets[$exe]
    $vOut = Invoke-Nginx $exe @('-v') $t.Prefix
    $VOut = Invoke-Nginx $exe @('-V') $t.Prefix
    $tArgs = @('-T'); if ($t.ConfArg) { $tArgs += @('-c', "`"$($t.ConfArg)`"") }
    $conf = Invoke-Nginx $exe $tArgs $t.Prefix

    $ver = if ($vOut -match 'nginx/(\d+\.\d+\.\d+)') { [version]$Matches[1] } else { $null }
    # OpenResty prints openresty/1.27.1.2 - the first three parts are the nginx core version
    $openresty = ''
    if (-not $ver -and "$vOut$VOut" -match 'openresty/(\d+\.\d+\.\d+)(\.\d+)?') { $ver = [version]$Matches[1]; $openresty = $Matches[0] }
    $plus = if ("$vOut$VOut" -match '(nginx-plus-r\d+(-p\d+)?)') { $Matches[1] } elseif ("$vOut$VOut" -match 'nginx-plus') { 'nginx-plus' } else { '' }

    $h2mod = $VOut -match '--with-http_v2_module'
    $h3mod = $VOut -match '--with-http_v3_module'
    $mailmod = $VOut -match '--with-mail(=dynamic)?(\s|$)'

    $confKnown = $conf -match 'test is successful'
    $f = @{ h2 = $false; h2off = $false; h3 = $false; up = $false; resolver = $false; varpass = $false; subreq = $false; mail = $false; mailproxy = $false; authhttp = $false }
    $listenLines = @()
    if ($confKnown) {
        # strip comments, then one statement per line
        $c = ($conf -split "`r?`n" | ForEach-Object { $_ -replace '#.*$', '' }) -join "`n"
        $c = $c -replace '([{};])', "`$1`n"
        $lines = $c -split "`n"
        $f.h2        = [bool]($lines | Where-Object { $_ -match '^\s*listen\s[^;]*\bhttp2\b' -or $_ -match '^\s*http2\s+on\s*;' })
        $f.h2off     = [bool]($lines | Where-Object { $_ -match '^\s*http2\s+off\s*;' })
        $f.h3        = [bool]($lines | Where-Object { $_ -match '^\s*listen\s[^;]*\bquic\b' -or $_ -match '^\s*http3\s+on\s*;' })
        $f.up        = [bool]($lines | Where-Object { $_ -match '^\s*(proxy|fastcgi|grpc|uwsgi|scgi|memcached)_pass\s' })
        $f.resolver  = [bool]($lines | Where-Object { $_ -match '^\s*resolver\s' })
        $f.varpass   = [bool]($lines | Where-Object { $_ -match '^\s*proxy_pass\s[^;]*\$' })
        $f.subreq    = [bool]($lines | Where-Object { $_ -match '^\s*(mirror\s+[^o;]|ssi\s+on\s*;)' })
        $f.mail      = [bool]($lines | Where-Object { $_ -match '^\s*mail\s*\{' })
        $f.mailproxy = [bool]($lines | Where-Object { $_ -match '^\s*proxy\s+on\s*;' })
        $f.authhttp  = [bool]($lines | Where-Object { $_ -match '^\s*auth_http\s' })
        $listenLines = $lines | Where-Object { $_ -match '^\s*listen\s' -and $_ -match '\b(ssl|http2)\b' }
    }

    # ALPN h2 probe (.NET SslStream, .NET Core 3+/PS7 only; skipped on Windows PowerShell 5.1)
    $alpnH2 = @()
    if ($confKnown -and $PSVersionTable.PSVersion.Major -ge 7) {
        $ports = $listenLines | ForEach-Object { if ($_ -match 'listen\s+(?:[\[\]\w.:*]*:)?(\d+)') { [int]$Matches[1] } } | Sort-Object -Unique
        foreach ($port in $ports) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                if (-not $tcp.ConnectAsync('127.0.0.1', $port).Wait(3000)) { $tcp.Dispose(); continue }
                $tcp.ReceiveTimeout = 5000; $tcp.SendTimeout = 5000
                $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
                $opt = New-Object System.Net.Security.SslClientAuthenticationOptions
                $opt.TargetHost = 'localhost'
                $opt.ApplicationProtocols = [System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]]@([System.Net.Security.SslApplicationProtocol]::Http2)
                # Synchronous handshake: a scriptblock callback cannot run on a thread-pool thread (no runspace)
                $opt.RemoteCertificateValidationCallback = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s, $c, $ch, $e) $true }
                $ssl.AuthenticateAsClient($opt)
                if ($ssl.NegotiatedApplicationProtocol -eq [System.Net.Security.SslApplicationProtocol]::Http2) { $alpnH2 += "127.0.0.1:$port" }
                $ssl.Dispose(); $tcp.Dispose()
            } catch { }
        }
        if ($alpnH2) { $f.h2 = $true }
    }

    $rank = 0
    $cveRows = foreach ($cve in $Cves.Keys) {
        $first = $Cves[$cve].First
        $status = ''; $detail = ''; $inRange = 0; $exposed = 0
        if ($plus) { $inRange = 2; $status = 'REVIEW(NGINX Plus)'; $detail = "verify $plus against F5 advisory" }
        elseif (-not $ver) { $inRange = 2; $status = 'REVIEW'; $detail = 'version could not be determined' }
        elseif ($ver -lt $first) { $status = 'NOT AFFECTED'; $detail = "older than first affected $first" }
        else {
            $fix = if ($ver -ge [version]'1.31.0') { $FixMainline } else { $FixStable }
            if ($ver -ge $fix) { $status = 'PATCHED'; $detail = ">= $fix" } else { $inRange = 1; $detail = "needs >= $fix" }
        }
        if ($inRange) {
            switch ($cve) {
                'CVE-2026-123007' { if ($h2mod -and $f.h2) { $exposed = 1 } elseif (-not $h2mod -and $VOut) { $exposed = -1 } }
                'CVE-2026-123633' { if ($h2mod -and $f.h2 -and $f.up) { $exposed = 1 } elseif (-not $h2mod -and $VOut) { $exposed = -1 } }
                'CVE-2026-123634' { if ($f.resolver -and $f.varpass -and $f.subreq) { $exposed = 1 }
                                    elseif ($f.resolver -and $f.varpass) { $detail += '; resolver+var proxy_pass present (other subrequests may reach bug)' } }
                'CVE-2026-121810' { if ($f.h3 -and $f.up) { $exposed = 1 } elseif (-not $h3mod -and $VOut) { $exposed = -1 } }
                'CVE-2026-113425' { if ($f.mail -and $f.mailproxy -and $f.authhttp) { $exposed = 1 } elseif (-not $mailmod -and $VOut -and -not $f.mail) { $exposed = -1 } }
            }
            if ($exposed -eq 1) { $status = if ($inRange -eq 2 -and $plus) { 'VULNERABLE?(Plus)' } elseif ($inRange -eq 2) { 'VULNERABLE?(ver unknown)' } else { 'VULNERABLE' }; $rank = 2 }
            elseif ($exposed -eq -1) { $status = 'IN RANGE-not built'; $detail += '; module not compiled in' }
            elseif (-not $confKnown) { $status = 'IN RANGE-cfg unknown'; if ($rank -lt 1) { $rank = 1 } }
            else { $status = 'IN RANGE-not exposed'; $detail += '; vulnerable feature not enabled in config'; if ($rank -lt 1) { $rank = 1 } }
        }
        [pscustomobject]@{ CVE = $cve; Status = $status; Detail = $detail; Description = $Cves[$cve].Desc }
    }
    if ($t.Note -match 'RESTART' -and $rank -lt 1) { $rank = 1 }
    $verdict = @('CLEAN', 'REVIEW', 'VULNERABLE')[$rank]
    if ($rank -gt $overallRank) { $overallRank = $rank }

    Write-Report ''
    Write-Report ('=' * 66)
    Write-Report " $exe$(if ($t.ConfArg) { " (-c $($t.ConfArg))" })"
    Write-Report ('=' * 66)
    Write-Report " Version     : $(if ($ver) { $ver } else { 'UNKNOWN' })$(if ($plus) { " ($plus)" })$(if ($openresty) { " (nginx core of $openresty)" })"
    if ($t.Note) { Write-Report " NOTE        : $($t.Note)" }
    Write-Report " Build       : http_v2_module=$([int]$h2mod)  http_v3_module=$([int]$h3mod)  mail=$([int]$mailmod)"
    if ($confKnown) {
        Write-Report (" Config      : http2={0} http3/quic={1} upstream_pass={2} resolver={3} var_proxy_pass={4} mirror/ssi={5} mail={6}(proxy={7} auth_http={8})" -f `
            [int]$f.h2, [int]$f.h3, [int]$f.up, [int]$f.resolver, [int]$f.varpass, [int]$f.subreq, [int]$f.mail, [int]$f.mailproxy, [int]$f.authhttp)
        if ($f.h2off -and $f.h2) { Write-Report " WARNING     : 'http2 off;' present but http2 still enabled elsewhere (listen ... http2 overrides it)" }
        if ($alpnH2) { Write-Report " ALPN probe  : h2 NEGOTIATED on $($alpnH2 -join ', ')" }
        elseif ($PSVersionTable.PSVersion.Major -lt 7) { Write-Report ' ALPN probe  : skipped (needs PowerShell 7+)' }
    } else {
        Write-Report ' Config      : COULD NOT READ (run elevated, or nginx -T failed) - exposure unknown'
    }
    Write-Report ''
    Write-Report (' {0,-16} {1,-22} {2}' -f 'CVE', 'STATUS', 'DETAIL')
    foreach ($r in $cveRows) {
        Write-Report (' {0,-16} {1,-22} {2}' -f $r.CVE, $r.Status, $r.Detail)
        if ($r.Status -like 'VULNERABLE*') { Write-Report "                  -> $($r.Description)" }
    }
    Write-Report ''
    Write-Report " RESULT      : $verdict"
    if ($rank -eq 2) {
        Write-Report " ACTION      : Upgrade to nginx $FixStable / $FixMainline. Stopgap for 123007/123633: remove 'http2' from listen"
        Write-Report "               lines AND set 'http2 off;' per server, nginx -t, then fully restart nginx (not reload)."
    }

    $results += [pscustomobject]@{
        Target = $exe; Version = "$ver"; Plus = $plus; Verdict = $verdict; Note = $t.Note
        ConfigRead = $confKnown; Cves = @($cveRows | Select-Object CVE, Status, Detail)
    }
}

# ---------------------------------------------------------------- summary
$overall = if ($results.Count -eq 0) { 'NO NGINX FOUND' } else { @('CLEAN', 'REVIEW', 'VULNERABLE')[$overallRank] }
$exitCode = @(0, 2, 1)[$overallRank]

if ($Json) {
    [pscustomobject]@{ Host = $env:COMPUTERNAME; Scanned = (Get-Date).ToUniversalTime().ToString('s') + 'Z'; Overall = $overall; Instances = $results } |
        ConvertTo-Json -Depth 5
} else {
    Write-Output ''
    Write-Output "######## nginx2root SUMMARY - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ########"
    if ($results.Count -eq 0) { Write-Output ' No nginx.exe found (use -DeepScan to search all fixed drives).' }
    foreach ($r in $results) { Write-Output " $($r.Verdict) | $($r.Target) | $($r.Version)$(if ($r.Plus) { " $($r.Plus)" })" }
    Write-Output " OVERALL: $overall"
}

if ($NinjaField -and $NinjaField -ne 'none' -and (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
    $val = "$overall | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | " + (($results | ForEach-Object { "$($_.Verdict) $($_.Target) $($_.Version)" }) -join '; ')
    try { Ninja-Property-Set $NinjaField ($val.Substring(0, [Math]::Min(1000, $val.Length))); if (-not $Json) { Write-Output "Wrote result to custom field '$NinjaField'." } }
    catch { Write-Warning "Could not write custom field '$NinjaField': $_" }
}

exit $exitCode

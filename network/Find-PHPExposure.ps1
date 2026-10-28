<#
.SYNOPSIS
    Scans IP ranges for web services running PHP and flags versions affected by the
    Oct 2026 "PHP2Shell" RCE bugs (CVE-2026-109618 / CVE-2026-109619).

.DESCRIPTION
    No nmap or other install needed - Windows PowerShell 5.1 or PowerShell 7, so it can run
    from your own machine or as a NinjaOne automation on any Windows device inside the network.

      1. TCP connect scan of the targets on common web ports (+ 9000 for exposed PHP-FPM).
      2. HTTP/HTTPS GET of "/" on every open port (follows same-host redirects, ignores cert errors).
      3. Two extra GETs per web service: /index.php and a random non-existent .php, to catch PHP
         that hides its version header.
      4. Fingerprints PHP from X-Powered-By / Server headers, PHPSESSID / laravel_session cookies,
         X-Generator, <meta name="generator"> and well-known PHP apps (WordPress, phpMyAdmin,
         Drupal, Joomla, Nextcloud, GLPI, Zabbix, FreePBX, pfSense ...).
      5. Compares any version found against the fixed releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
         8.1 and older = UNSUPPORTED (no upstream fix).

    Non-destructive: only TCP connects and plain GET requests. It sends no exploit payloads.

    Status values
      VULNERABLE          PHP version below the fixed release for its branch
      BELOW_FIX_DISTRO    below the upstream fix, but it's a distro build (Ubuntu/Debian/RHEL...) -
                          distros backport fixes without changing the version, so check the package
      UNSUPPORTED         PHP 8.1 or older - no upstream fix
      PHP_VERSION_UNKNOWN PHP detected (cookie / app / header) but the version is hidden
      POSSIBLE_PHP        weak signal only (index.php served, random .php 404s)
      REVIEW_FASTCGI      TCP 9000 open and not HTTP - possible network-exposed PHP-FPM
      PATCHED             at or above the fixed release
      NO_PHP_DETECTED     web service answered, no PHP indicators
      NOT_HTTP            port open, no HTTP(S) response

    Output (in -OutputDir): php-exposure.csv (every web service found, so it doubles as evidence of
    coverage), php-exposure.html, summary.txt.

.PARAMETER Targets
    Comma / space / newline separated: CIDR (10.0.0.0/24), range (10.0.0.10-50 or
    10.0.0.10-10.0.1.20), single IP, or hostname. Hostnames are requested by name, so name-based
    virtual hosts (e.g. a public website) are fingerprinted correctly.
    Omitted on Windows = the device's own IPv4 subnets (anything larger than /22 is cut to the /24
    around the device's address).

.NINJA SCRIPT VARIABLES (all optional)
    targets      same as -Targets (blank = local subnets)
    ports        override the port list
    ninjaField   Multi-line device custom field for the results (default phpExposure; "none" = don't
                 write). Create it in Ninja as a Multi-line field with Automations = Read/Write. It gets
                 a summary line, every PHP finding, and a compact list of every web service scanned
                 (capped at ~9,500 characters), so results can be pulled across devices without
                 touching the CSVs.
    outputDir    where reports go (default C:\ProgramData\PHP2ShellScan\<timestamp>)
    pingFirst    "true" = only port-scan hosts that answer ping (faster on big, sparse ranges;
                 misses hosts that block ICMP, which Windows does by default)

.EXAMPLE
    .\Find-PHPExposure.ps1 -Targets "10.10.0.0/24, 10.10.7.0/24"
.EXAMPLE
    .\Find-PHPExposure.ps1 -Targets "www.example.org" -Ports "80,443"

.NOTES
    Repo: shensger/tools_code
    Exit codes: 0 = nothing needing action, 1 = at least one VULNERABLE / BELOW_FIX_DISTRO /
    UNSUPPORTED / PHP_VERSION_UNKNOWN / POSSIBLE_PHP / REVIEW_FASTCGI, 2 = error.
    Only scan networks and hosts you're authorized to scan.
#>

[CmdletBinding()]
param(
    [string]$Targets          = $env:targets,
    [string]$Ports            = $(if ($env:ports) { $env:ports } else { '80,81,443,591,4443,8000,8008,8080,8081,8088,8443,8888,9000,9443' }),
    [string]$OutputDir        = $env:outputDir,
    [string]$NinjaField       = $(if ($env:ninjaField) { $env:ninjaField } else { 'phpExposure' }),
    [int]   $ConnectTimeoutMs = 800,
    [int]   $HttpTimeoutMs    = 6000,
    [int]   $Threads          = 128,
    [int]   $MaxHosts         = 4096,
    [switch]$PingFirst        = ($env:pingFirst -eq 'true'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

# Fixed releases per branch (https://www.php.net/archive/2026.php#2026-10-21-5)
$FixedIn = @{ '8.2' = 35; '8.3' = 36; '8.4' = 27; '8.5' = 12 }
$FixedText = '8.5.12 / 8.4.27 / 8.3.36 / 8.2.35'

function Set-NinjaResult([string]$Value) {
    if (-not $NinjaField -or $NinjaField -eq 'none') { return }
    if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) { return }
    try { Ninja-Property-Set $NinjaField $Value; Write-Output "Wrote results to custom field '$NinjaField'." }
    catch { Write-Output "WARNING: could not write custom field '$NinjaField' (create it as a Multi-line field with Automations = Read/Write): $($_.Exception.Message)" }
}

# ------------------------------------------------------------------------------------------------
# Network helpers (C# so the scan runs in parallel on both PS 5.1 and PS 7)
# ------------------------------------------------------------------------------------------------
if (-not ('PhpExposureScan.Scanner' -as [type])) {
Add-Type -Language CSharp -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PhpExposureScan {
    public class HttpResult {
        public string Url;
        public int StatusCode;
        public string Server;
        public string PoweredBy;
        public string SetCookie;
        public string Location;
        public string Generator;
        public string ContentType;
        public string Body;
        public string Error;
    }

    public static class Scanner {
        static bool AcceptAll(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }

        public static void Init(int threads) {
            int w, io;
            ThreadPool.GetMinThreads(out w, out io);
            if (w < threads) ThreadPool.SetMinThreads(threads, io < threads ? threads : io);
            ServicePointManager.DefaultConnectionLimit = 1000;
            ServicePointManager.Expect100Continue = false;
            try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)(12288 | 3072 | 768 | 192); }
            catch {
                try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)(3072 | 768 | 192); } catch { }
            }
        }

        static ParallelOptions Opts(int threads) {
            ParallelOptions o = new ParallelOptions();
            o.MaxDegreeOfParallelism = threads;
            return o;
        }

        public static bool PortOpen(string host, int port, int timeoutMs) {
            TcpClient c = new TcpClient(AddressFamily.InterNetwork);
            try {
                IAsyncResult ar = c.BeginConnect(host, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return false;
                c.EndConnect(ar);
                return c.Connected;
            }
            catch { return false; }
            finally { try { c.Close(); } catch { } }
        }

        public static string[] ScanPorts(string[] hosts, int[] ports, int timeoutMs, int threads) {
            List<KeyValuePair<string, int>> work = new List<KeyValuePair<string, int>>();
            foreach (string h in hosts) foreach (int p in ports) work.Add(new KeyValuePair<string, int>(h, p));
            ConcurrentBag<string> bag = new ConcurrentBag<string>();
            Parallel.ForEach(work, Opts(threads), delegate (KeyValuePair<string, int> kv) {
                if (PortOpen(kv.Key, kv.Value, timeoutMs)) bag.Add(kv.Key + "|" + kv.Value);
            });
            return bag.ToArray();
        }

        public static string[] PingSweep(string[] hosts, int timeoutMs, int threads) {
            ConcurrentBag<string> bag = new ConcurrentBag<string>();
            Parallel.ForEach(hosts, Opts(threads), delegate (string h) {
                try {
                    using (Ping p = new Ping()) {
                        if (p.Send(h, timeoutMs).Status == IPStatus.Success) bag.Add(h);
                    }
                }
                catch { }
            });
            return bag.ToArray();
        }

        static string ReadBody(HttpWebResponse resp, int max) {
            try {
                using (Stream s = resp.GetResponseStream()) {
                    if (s == null) return "";
                    MemoryStream ms = new MemoryStream();
                    byte[] buf = new byte[8192];
                    int n;
                    while (ms.Length < max && (n = s.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
            catch { return ""; }
        }

        public static HttpResult Get(string url, int timeoutMs) {
            HttpResult r = new HttpResult();
            r.Url = url;
            HttpWebResponse resp = null;
            try {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "GET";
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.AllowAutoRedirect = false;
                req.KeepAlive = false;
                req.Proxy = null;
                req.UserAgent = "Mozilla/5.0 (compatible; PHP2Shell-exposure-check)";
                req.Accept = "text/html,*/*";
                req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
                req.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AcceptAll);
                try { resp = (HttpWebResponse)req.GetResponse(); }
                catch (WebException we) {
                    resp = we.Response as HttpWebResponse;
                    if (resp == null) { r.Error = we.Status.ToString() + ": " + we.Message; return r; }
                }
                r.StatusCode  = (int)resp.StatusCode;
                r.Server      = resp.Headers["Server"];
                r.PoweredBy   = resp.Headers["X-Powered-By"];
                r.SetCookie   = resp.Headers["Set-Cookie"];
                r.Location    = resp.Headers["Location"];
                r.Generator   = resp.Headers["X-Generator"];
                r.ContentType = resp.ContentType;
                r.Body        = ReadBody(resp, 65536);
            }
            catch (Exception ex) { r.Error = ex.GetType().Name + ": " + ex.Message; }
            finally { if (resp != null) { try { resp.Close(); } catch { } } }
            return r;
        }

        public static HttpResult[] GetMany(string[] urls, int timeoutMs, int threads) {
            HttpResult[] results = new HttpResult[urls.Length];
            Parallel.For(0, urls.Length, Opts(threads), delegate (int i) { results[i] = Get(urls[i], timeoutMs); });
            return results;
        }

        public static string[] ReverseMany(string[] ips, int timeoutMs, int threads) {
            string[] names = new string[ips.Length];
            Parallel.For(0, ips.Length, Opts(threads), delegate (int i) {
                names[i] = "";
                try {
                    Task<IPHostEntry> t = Dns.GetHostEntryAsync(ips[i]);
                    if (t.Wait(timeoutMs) && t.Result.HostName != ips[i]) names[i] = t.Result.HostName;
                }
                catch { }
            });
            return names;
        }
    }
}
'@
}
[PhpExposureScan.Scanner]::Init($Threads)

# ------------------------------------------------------------------------------------------------
# Target parsing
# ------------------------------------------------------------------------------------------------
function ConvertTo-UInt32([string]$ip) {
    $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    return ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]
}
function ConvertFrom-UInt32([uint32]$n) {
    return '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255)
}
$ipRx = '^\d{1,3}(\.\d{1,3}){3}$'

function Get-LocalSubnets {
    if (-not (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue)) {
        throw 'No -Targets given and local subnets can only be auto-detected on Windows. Pass -Targets.'
    }
    $list = @()
    foreach ($a in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($a.IPAddress -like '127.*' -or $a.IPAddress -like '169.254.*') { continue }
        $len = [int]$a.PrefixLength
        if ($len -lt 22) {
            Write-Host "NOTE: $($a.IPAddress)/$len is larger than /22 - scanning only its /24. Pass -Targets to scan more."
            $len = 24
        }
        $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $len))
        $net  = (ConvertTo-UInt32 $a.IPAddress) -band $mask
        $list += "$(ConvertFrom-UInt32 $net)/$len"
    }
    return ($list | Select-Object -Unique)
}

# Returns ordered dictionary: IP -> name used in URLs (hostname if the target was a name, else IP)
function Resolve-Targets([string[]]$tokens) {
    $out = [ordered]@{}
    foreach ($t in $tokens) {
        $t = $t.Trim()
        if (-not $t) { continue }
        if ($t -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
            $len = [int]$matches[2]
            if ($len -gt 32) { throw "Bad CIDR: $t" }
            $mask  = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $len))
            $net   = (ConvertTo-UInt32 $matches[1]) -band $mask
            $count = [math]::Pow(2, 32 - $len)
            if (($out.Count + $count) -gt $MaxHosts -and -not $Force) {
                throw "$t is $count addresses; total would exceed -MaxHosts $MaxHosts. Split it up, raise -MaxHosts, or use -Force."
            }
            $first = $net; $last = [uint32]($net + $count - 1)
            if ($len -le 30) { $first++; $last-- }
            for ($n = [double]$first; $n -le $last; $n++) { $ip = ConvertFrom-UInt32 ([uint32]$n); $out[$ip] = $ip }
        }
        elseif ($t -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$') {
            $start = ConvertTo-UInt32 $matches[1]
            if ($matches[2] -match $ipRx) { $end = ConvertTo-UInt32 $matches[2] }
            else { $end = ($start -band [uint32]4294967040) + [uint32]$matches[2] }
            if ($end -lt $start) { throw "Bad range: $t" }
            if (($out.Count + ($end - $start + 1)) -gt $MaxHosts -and -not $Force) { throw "$t exceeds -MaxHosts $MaxHosts." }
            for ($n = [double]$start; $n -le $end; $n++) { $ip = ConvertFrom-UInt32 ([uint32]$n); $out[$ip] = $ip }
        }
        elseif ($t -match $ipRx) { $out[$t] = $t }
        else {
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($t) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
                if (-not $addrs) { Write-Host "WARNING: $t has no IPv4 address - skipped."; continue }
                # Scan by name (vhost-aware); one entry per name is enough
                $out["name:$t"] = $t
            }
            catch { Write-Host "WARNING: could not resolve $t - skipped." }
        }
    }
    return $out
}

# ------------------------------------------------------------------------------------------------
# Fingerprinting
# ------------------------------------------------------------------------------------------------
$AppSignatures = [ordered]@{
    'WordPress'  = 'wp-content/|wp-includes/|<meta name="generator" content="wordpress'
    'phpMyAdmin' = 'phpmyadmin'
    'Drupal'     = 'drupal-settings-json|drupal\.settings|/sites/default/files/|content="drupal'
    'Joomla'     = 'content="joomla|/media/jui/|/media/system/js/'
    'Magento'    = 'mage/cookies|static/version\d+/frontend|mage-cache'
    'Nextcloud/ownCloud' = 'nextcloud|owncloud'
    'Roundcube'  = 'roundcube'
    'Moodle'     = 'moodle'
    'MediaWiki'  = 'content="mediawiki|mediawiki'
    'GLPI'       = 'glpi'
    'Zabbix'     = 'zabbix'
    'Cacti'      = 'cacti'
    'LibreNMS'   = 'librenms'
    'FreePBX'    = 'freepbx'
    'pfSense'    = 'pfsense'
    'osTicket'   = 'osticket'
    'SuiteCRM/SugarCRM' = 'suitecrm|sugarcrm'
    'vTiger'     = 'vtiger'
    'Laravel'    = 'laravel'
    'PrestaShop' = 'prestashop'
    'OpenCart'   = 'opencart|route=common/home'
    'Craft CMS'  = 'craft cms|craftcms'
}

function Get-PhpEvidence($results) {
    $ev = @{ Version = $null; Indicators = New-Object System.Collections.Generic.List[string]; Apps = New-Object System.Collections.Generic.List[string]; Strong = $false; Server = $null; PoweredBy = $null }
    foreach ($r in $results) {
        if (-not $r -or $r.Error) { continue }
        if ($r.Server -and -not $ev.Server) { $ev.Server = $r.Server }
        if ($r.PoweredBy -and -not $ev.PoweredBy) { $ev.PoweredBy = $r.PoweredBy }
        foreach ($h in @($r.PoweredBy, $r.Server)) {
            if (-not $h) { continue }
            if ($h -match '(?i)PHP/(\d+\.\d+\.\d+[^\s,;]*)') {
                if (-not $ev.Version) { $ev.Version = $matches[1] }
                $ev.Strong = $true
                if (-not $ev.Indicators.Contains('version header')) { $ev.Indicators.Add('version header') }
            }
            elseif ($h -match '(?i)\bPHP\b') {
                $ev.Strong = $true
                if (-not $ev.Indicators.Contains('PHP header (no version)')) { $ev.Indicators.Add('PHP header (no version)') }
            }
        }
        if ($r.SetCookie -match '(?i)PHPSESSID=') { $ev.Strong = $true; if (-not $ev.Indicators.Contains('PHPSESSID cookie')) { $ev.Indicators.Add('PHPSESSID cookie') } }
        if ($r.SetCookie -match '(?i)laravel_session=') { $ev.Strong = $true; if (-not $ev.Apps.Contains('Laravel')) { $ev.Apps.Add('Laravel') } }
        $gen = ''
        if ($r.Generator) { $gen = $r.Generator }
        $body = ''
        if ($r.Body) { $body = $r.Body.ToLowerInvariant() }
        if ($body -match '<meta[^>]+name=["'']generator["''][^>]+content=["'']([^"'']+)') { $gen = "$gen $($matches[1])" }
        $hay = "$gen $body".ToLowerInvariant()
        foreach ($app in $AppSignatures.Keys) {
            if ($hay -match $AppSignatures[$app] -and -not $ev.Apps.Contains($app)) { $ev.Apps.Add($app); $ev.Strong = $true }
        }
    }
    return $ev
}

function Get-VersionVerdict([string]$ver, [string]$server) {
    if ($ver -notmatch '^(\d+)\.(\d+)\.(\d+)(.*)$') { return @('PHP_VERSION_UNKNOWN', "Couldn't parse version '$ver'.") }
    $maj = [int]$matches[1]; $min = [int]$matches[2]; $pat = [int]$matches[3]; $rest = $matches[4]
    $mm = "$maj.$min"
    $distro = ($rest -match '(?i)ubuntu|deb|\.el\d|amzn|suse|\.fc\d|\+') -or ($server -match '(?i)ubuntu|debian|centos|red ?hat|rocky|alma|amazon|suse|fedora|raspbian')
    if ($maj -lt 8 -or ($maj -eq 8 -and $min -le 1)) {
        $msg = "PHP $mm gets no upstream fix. Upgrade to a supported branch ($FixedText or later), get a vendor/LTS backport, or isolate it."
        if ($distro) { $msg += ' This looks like a distro build - the distro may ship a backported fix, so check the installed package against its advisory.' }
        return @('UNSUPPORTED', $msg)
    }
    $below = $false
    if ($FixedIn.ContainsKey($mm)) { $below = ($pat -lt $FixedIn[$mm]) }
    elseif ($mm -eq '8.6') {
        if ($rest -match '(?i)^(alpha|beta|dev)') { $below = $true }
        elseif ($rest -match '(?i)^RC(\d+)') { $below = ([int]$matches[1] -lt 4) }
    }
    if (-not $below) { return @('PATCHED', "At or above the fixed release for PHP $mm.") }
    $fix = "$mm.$($FixedIn[$mm])"
    if ($mm -eq '8.6') { $fix = '8.6.0RC4' }
    if ($distro) {
        return @('BELOW_FIX_DISTRO', "Distro build of PHP $mm (upstream fix is $fix). Distros backport fixes without changing the version number - check the installed package against the distro advisory for CVE-2026-109618/109619.")
    }
    return @('VULNERABLE', "Upgrade to $fix or later. Until then apply PHP's interim mitigations (session.upload_progress.enabled=0, low post_max_size, request-size limits at the proxy). If this is a distro package, check it first - distros backport fixes without changing the version.")
}

# ------------------------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------------------------
try {
    $portList = @($Ports -split '[,\s;]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Select-Object -Unique)
    if (-not $portList) { throw 'No valid ports.' }

    if ([string]::IsNullOrWhiteSpace($Targets)) { $tokens = @(Get-LocalSubnets) }
    else { $tokens = @($Targets -split '[,\s;]+') }
    $targetMap = Resolve-Targets $tokens
    if ($targetMap.Count -eq 0) { throw 'No targets to scan.' }

    if (-not $OutputDir) {
        $base = $env:ProgramData
        if (-not $base) { $base = (Get-Location).Path }
        $OutputDir = Join-Path $base ("PHP2ShellScan\" + $started.ToString('yyyyMMdd-HHmmss'))
        $OutputDir = $OutputDir -replace '\\', [IO.Path]::DirectorySeparatorChar
    }
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    Write-Output "PHP2Shell exposure scan (CVE-2026-109618 / CVE-2026-109619) - $($started.ToString('yyyy-MM-dd HH:mm'))"
    Write-Output "Scope : $($tokens -join ', ')"
    Write-Output "Hosts : $($targetMap.Count)   Ports: $($portList -join ',')"

    # host string to connect to -> name for URLs
    $hostToName = @{}
    foreach ($k in $targetMap.Keys) {
        $connect = $k -replace '^name:', ''
        $hostToName[$connect] = $targetMap[$k]
    }
    $hosts = [string[]]@($hostToName.Keys)

    if ($PingFirst) {
        $hosts = [string[]]@([PhpExposureScan.Scanner]::PingSweep($hosts, 700, $Threads))
        Write-Output "Ping  : $($hosts.Count) hosts answered"
    }

    # --- Phase 1: port scan --------------------------------------------------------------------
    $open = @()
    if ($hosts.Count -gt 0) { $open = @([PhpExposureScan.Scanner]::ScanPorts($hosts, [int[]]$portList, $ConnectTimeoutMs, $Threads)) }
    $liveHosts = @($open | ForEach-Object { ($_ -split '\|')[0] } | Select-Object -Unique)
    Write-Output "Open  : $($open.Count) ports on $($liveHosts.Count) hosts"

    # --- Phase 2: root request, preferred scheme then the other --------------------------------
    $tlsPorts = @(443, 4443, 8443, 9443)
    $eps = @()
    foreach ($o in $open) {
        $h, $p = $o -split '\|'
        $p = [int]$p
        $name = $hostToName[$h]
        $order = @('http', 'https')
        if ($tlsPorts -contains $p) { $order = @('https', 'http') }
        $eps += [pscustomobject]@{ Host = $h; Name = $name; Port = $p; Order = $order; Scheme = $null; Base = $null; Chain = @(); Probes = @() }
    }

    function Get-Base($ep, $scheme) {
        $defaultPort = ($scheme -eq 'http' -and $ep.Port -eq 80) -or ($scheme -eq 'https' -and $ep.Port -eq 443)
        if ($defaultPort) { return "${scheme}://$($ep.Name)" }
        return "${scheme}://$($ep.Name):$($ep.Port)"
    }

    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $batch = @($eps | Where-Object { -not $_.Scheme })
        if (-not $batch) { break }
        $urls = [string[]]@($batch | ForEach-Object { (Get-Base $_ $_.Order[$attempt]) + '/' })
        $res  = [PhpExposureScan.Scanner]::GetMany($urls, $HttpTimeoutMs, $Threads)
        for ($i = 0; $i -lt $batch.Count; $i++) {
            $r = $res[$i]; $ep = $batch[$i]
            if ($r.Error) { continue }
            $plainToTls = $ep.Order[$attempt] -eq 'http' -and $r.StatusCode -eq 400 -and $r.Body -match '(?i)https|ssl|tls'
            if ($plainToTls -and $attempt -eq 0) { continue }
            $ep.Scheme = $ep.Order[$attempt]; $ep.Base = Get-Base $ep $ep.Scheme; $ep.Chain = @($r)
        }
    }

    # --- Phase 3: follow same-host redirects (max 3) -------------------------------------------
    for ($hop = 0; $hop -lt 3; $hop++) {
        $todo = @(); $urls = @()
        foreach ($ep in ($eps | Where-Object { $_.Scheme })) {
            $last = $ep.Chain[-1]
            if ($last.StatusCode -lt 300 -or $last.StatusCode -ge 400 -or -not $last.Location) { continue }
            try { $next = New-Object System.Uri((New-Object System.Uri($last.Url)), $last.Location) } catch { continue }
            if ($next.Host -ne ([System.Uri]$last.Url).Host) { continue }
            if (@($ep.Chain | Where-Object { $_.Url -eq $next.AbsoluteUri }).Count) { continue }
            $todo += $ep; $urls += $next.AbsoluteUri
        }
        if (-not $todo) { break }
        $res = [PhpExposureScan.Scanner]::GetMany([string[]]$urls, $HttpTimeoutMs, $Threads)
        for ($i = 0; $i -lt $todo.Count; $i++) { if (-not $res[$i].Error) { $todo[$i].Chain += $res[$i] } }
    }

    # --- Phase 4: /index.php vs random .php ----------------------------------------------------
    $web = @($eps | Where-Object { $_.Scheme })
    if ($web) {
        $rand = 'zz-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '.php'
        $urls = New-Object System.Collections.Generic.List[string]
        foreach ($ep in $web) { $urls.Add("$($ep.Base)/index.php"); $urls.Add("$($ep.Base)/$rand") }
        $res = [PhpExposureScan.Scanner]::GetMany($urls.ToArray(), $HttpTimeoutMs, $Threads)
        for ($i = 0; $i -lt $web.Count; $i++) { $web[$i].Probes = @($res[2 * $i], $res[2 * $i + 1]) }
    }

    # --- Reverse DNS for hosts with something open ---------------------------------------------
    $rdns = @{}
    $ipsOnly = [string[]]@($liveHosts | Where-Object { $_ -match $ipRx -and $hostToName[$_] -eq $_ })
    if ($ipsOnly.Count) {
        $names = [PhpExposureScan.Scanner]::ReverseMany($ipsOnly, 1500, $Threads)
        for ($i = 0; $i -lt $ipsOnly.Count; $i++) { $rdns[$ipsOnly[$i]] = $names[$i] }
    }

    # --- Analyse -------------------------------------------------------------------------------
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($ep in ($eps | Sort-Object { if ($_.Host -match $ipRx) { ConvertTo-UInt32 $_.Host } else { 0 } }, Host, Port)) {
        $displayName = $ep.Name
        if ($ep.Name -eq $ep.Host -and $rdns[$ep.Host]) { $displayName = $rdns[$ep.Host] }
        $row = [ordered]@{
            Host = $ep.Host; Name = $displayName; Port = $ep.Port; Scheme = $ep.Scheme; Url = ''
            HttpStatus = ''; Server = ''; XPoweredBy = ''; PHPVersion = ''; Apps = ''; Indicators = ''
            Confidence = ''; Status = ''; Action = ''
        }
        if (-not $ep.Scheme) {
            if ($ep.Port -eq 9000) {
                $row.Status = 'REVIEW_FASTCGI'; $row.Confidence = 'Low'
                $row.Action = 'TCP 9000 open and not HTTP - may be a network-exposed PHP-FPM (FastCGI) listener. Identify the service; PHP-FPM should only listen on localhost or a socket.'
            }
            else { $row.Status = 'NOT_HTTP'; $row.Action = 'Port open but no HTTP(S) response.' }
            $rows.Add([pscustomobject]$row); continue
        }
        $first = $ep.Chain[0]; $last = $ep.Chain[-1]
        $row.Url = $last.Url; $row.HttpStatus = $last.StatusCode
        $ev = Get-PhpEvidence (@($ep.Chain) + @($ep.Probes))
        $row.Server = $ev.Server; $row.XPoweredBy = $ev.PoweredBy
        $row.Apps = ($ev.Apps -join ', ')

        # weak signal: /index.php served while a random .php is not
        $idx = $ep.Probes[0]; $rnd = $ep.Probes[1]
        $weak = $false
        if ($idx -and $rnd -and -not $idx.Error -and -not $rnd.Error) {
            $idxOk = $idx.StatusCode -eq 200 -and $idx.Body -notmatch '<\?php'
            $rndNo = $rnd.StatusCode -ge 400
            if ($idxOk -and $rndNo) { $weak = $true; $ev.Indicators.Add('index.php served') }
        }
        $row.Indicators = ($ev.Indicators -join ', ')

        if ($ev.Version) {
            $row.PHPVersion = $ev.Version; $row.Confidence = 'Confirmed'
            $v = Get-VersionVerdict $ev.Version $ev.Server
            $row.Status = $v[0]; $row.Action = $v[1]
        }
        elseif ($ev.Strong) {
            $row.Confidence = 'High'; $row.Status = 'PHP_VERSION_UNKNOWN'
            $row.Action = 'PHP in use but the version is hidden. Get it on the host (php -v / package manager) or from the vendor, then compare to ' + $FixedText + '.'
        }
        elseif ($weak) {
            $row.Confidence = 'Medium'; $row.Status = 'POSSIBLE_PHP'
            $row.Action = 'Weak signal only (index.php served). Confirm whether this app runs PHP.'
        }
        else { $row.Status = 'NO_PHP_DETECTED' }
        $rows.Add([pscustomobject]$row)
    }

    # --- Output --------------------------------------------------------------------------------
    $csv  = Join-Path $OutputDir 'php-exposure.csv'
    $html = Join-Path $OutputDir 'php-exposure.html'
    $sum  = Join-Path $OutputDir 'summary.txt'
    $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

    $count = @{}
    foreach ($s in 'VULNERABLE', 'BELOW_FIX_DISTRO', 'UNSUPPORTED', 'PHP_VERSION_UNKNOWN', 'POSSIBLE_PHP', 'REVIEW_FASTCGI', 'PATCHED', 'NO_PHP_DETECTED', 'NOT_HTTP') {
        $count[$s] = @($rows | Where-Object { $_.Status -eq $s }).Count
    }
    $actionStatuses = 'VULNERABLE', 'BELOW_FIX_DISTRO', 'UNSUPPORTED', 'PHP_VERSION_UNKNOWN', 'POSSIBLE_PHP', 'REVIEW_FASTCGI'
    $needAction = @($rows | Where-Object { $actionStatuses -contains $_.Status })
    $webCount   = @($rows | Where-Object { $_.Scheme }).Count
    $phpCount   = @($rows | Where-Object { 'VULNERABLE', 'BELOW_FIX_DISTRO', 'UNSUPPORTED', 'PHP_VERSION_UNKNOWN', 'PATCHED' -contains $_.Status }).Count
    $elapsed    = [int]((Get-Date) - $started).TotalSeconds

    $summary = @(
        "PHP2Shell exposure scan (CVE-2026-109618 / CVE-2026-109619)"
        "Run      : $($started.ToString('yyyy-MM-dd HH:mm:ss')) from $([Environment]::MachineName) ($elapsed s)"
        "Scope    : $($tokens -join ', ')"
        "Ports    : $($portList -join ',')"
        "Scanned  : $($targetMap.Count) addresses, $($liveHosts.Count) with open ports, $webCount web services"
        "PHP found: $phpCount (vulnerable $($count.VULNERABLE), distro-check $($count.BELOW_FIX_DISTRO), unsupported $($count.UNSUPPORTED), version hidden $($count.PHP_VERSION_UNKNOWN), patched $($count.PATCHED))"
        "Review   : possible PHP $($count.POSSIBLE_PHP), possible exposed PHP-FPM $($count.REVIEW_FASTCGI)"
        "Fixed in : $FixedText"
    )
    $summary | Set-Content -Path $sum -Encoding UTF8

    # HTML report
    $color = @{ VULNERABLE = '#f8d7da'; UNSUPPORTED = '#f8d7da'; BELOW_FIX_DISTRO = '#fff3cd'; PHP_VERSION_UNKNOWN = '#fff3cd'; POSSIBLE_PHP = '#fff3cd'; REVIEW_FASTCGI = '#fff3cd'; PATCHED = '#d1e7dd' }
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!doctype html><html><head><meta charset="utf-8"><title>PHP2Shell exposure scan</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #ccc;padding:5px 7px;text-align:left;vertical-align:top}th{background:#f2f2f2}pre{background:#f7f7f7;padding:10px}</style></head><body>')
    [void]$sb.Append('<h2>PHP2Shell exposure scan</h2><pre>' + (& $enc ($summary -join "`n")) + '</pre><table><tr>')
    $cols = 'Host', 'Name', 'Port', 'Url', 'HttpStatus', 'Server', 'XPoweredBy', 'PHPVersion', 'Apps', 'Indicators', 'Confidence', 'Status', 'Action'
    foreach ($c in $cols) { [void]$sb.Append("<th>$c</th>") }
    [void]$sb.Append('</tr>')
    foreach ($r in $rows) {
        $bg = $color[$r.Status]
        $style = ''
        if ($bg) { $style = " style=`"background:$bg`"" }
        [void]$sb.Append("<tr$style>")
        foreach ($c in $cols) { [void]$sb.Append('<td>' + (& $enc $r.$c) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</table></body></html>')
    [IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

    Write-Output ''
    $summary | ForEach-Object { Write-Output $_ }
    Write-Output ''
    if ($needAction) {
        Write-Output 'Needs attention:'
        $needAction | Format-Table Host, Name, Port, PHPVersion, Apps, Confidence, Status -AutoSize | Out-String -Width 220 | Write-Output
    }
    $patched = @($rows | Where-Object { $_.Status -eq 'PATCHED' })
    if ($patched) {
        Write-Output 'Patched PHP:'
        $patched | Format-Table Host, Name, Port, PHPVersion, Apps -AutoSize | Out-String -Width 220 | Write-Output
    }
    if (-not $needAction -and -not $patched) { Write-Output 'No PHP detected on any web service in scope.' }
    Write-Output "Reports: $csv"
    Write-Output "         $html"

    $state = 'OK'
    if ($needAction) { $state = 'ACTION' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$state | $($started.ToString('yyyy-MM-dd HH:mm')) | from $([Environment]::MachineName) | scope $($tokens -join ' ') | $($targetMap.Count) addresses, $($liveHosts.Count) with open ports, $webCount web services | PHP $phpCount (vuln $($count.VULNERABLE), distro $($count.BELOW_FIX_DISTRO), unsupported $($count.UNSUPPORTED), hidden $($count.PHP_VERSION_UNKNOWN), patched $($count.PATCHED), possible $($count.POSSIBLE_PHP), fpm $($count.REVIEW_FASTCGI))")
    $fmt = { param($r) "$($r.Host)$(if ($r.Name -and $r.Name -ne $r.Host) { " ($($r.Name))" }):$($r.Port) | $($r.Status) | PHP $(if ($r.PHPVersion) { $r.PHPVersion } else { '?' }) | $($r.Apps) | $($r.Indicators) | $($r.Url)" }
    if ($needAction) { $lines.Add('ATTENTION:'); foreach ($r in $needAction) { $lines.Add('  ' + (& $fmt $r)) } }
    if ($patched)    { $lines.Add('PATCHED:');   foreach ($r in $patched)    { $lines.Add('  ' + (& $fmt $r)) } }
    $other = @($rows | Where-Object { 'NO_PHP_DETECTED', 'NOT_HTTP' -contains $_.Status } | ForEach-Object {
        $tag = 'no-php'; if ($_.Status -eq 'NOT_HTTP') { $tag = 'not-http' }
        "$($_.Host):$($_.Port)=$tag" })
    if ($other) { $lines.Add('NO PHP: ' + ($other -join ', ')) }
    $lines.Add("CSV: $csv")
    $fieldValue = $lines -join "`n"
    if ($fieldValue.Length -gt 9500) { $fieldValue = $fieldValue.Substring(0, 9450) + "`n...[truncated - see CSV]" }
    Set-NinjaResult $fieldValue

    if ($needAction) { exit 1 }
    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Set-NinjaResult "ERROR | $($started.ToString('yyyy-MM-dd HH:mm')) | from $([Environment]::MachineName) | $($_.Exception.Message)"
    exit 2
}

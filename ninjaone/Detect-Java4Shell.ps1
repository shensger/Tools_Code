<#
.SYNOPSIS
    Detects exposure to Java4Shell (CVE-2026-114938) - HotSpot x86-64 Base64 intrinsic memory corruption.

.DESCRIPTION
    Based on the CISA alert (2026-11-17) and Oracle's November 2026 CPU. All three must be true for exposure:
      1. An OpenJDK-based runtime >= 17.0.6 (incl. 21, 25, 27), or Oracle 8 Enterprise Performance Pack 8u511b33-perf,
         that does NOT include the fix.
      2. x86-64 CPU with AVX-512 VBMI (Intel Ice Lake / Sapphire / Emerald / Granite Rapids, AMD Zen 4+).
      3. Mitigation flag not set (-XX:-UseBASE64Intrinsics or -XX:UseAVX=2).

    The script:
      - Finds every java.exe on fixed drives (catches JREs bundled inside apps, which OS / Ninja patching misses)
      - Reads each runtime's 'release' file (vendor + version), falling back to 'java -version'
      - Asks the JVM itself whether the CPU has avx512_vbmi (-Xlog:os+cpu); falls back to .NET 8 intrinsics via pwsh
      - Checks running java processes and JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS for the mitigation flags
      - Writes a summary to a NinjaOne custom field (optional) and exits 1 if anything is VULNERABLE

    Status values per runtime:
      VULNERABLE          Affected version, CPU has AVX-512 VBMI, no mitigation seen
      VULNERABLE-CPU?     Affected version, CPU capability could not be determined (treat as vulnerable)
      MITIGATED-FLAG      Affected version but mitigation flag found (still needs the patch)
      AFFECTED-VERSION    Affected version, CPU lacks AVX-512 VBMI (not exploitable on this host; patch anyway -
                          VM migration / hardware refresh can change this)
      CHECK-VENDOR        Vendor build (Temurin/Zulu/Microsoft/etc.) in the affected range; fixed build numbers
                          not yet published for that vendor - confirm against vendor advisory
      NOT-AFFECTED        Version outside affected range or contains the fix
      NOT-AFFECTED-X86    32-bit (or ARM64) java.exe - bug is x86-64 HotSpot only

.PARAMETER Paths
    Root paths to scan. Default: all fixed drives.

.PARAMETER NinjaField
    NinjaOne custom field (text/multiline) to write the summary to. Omit to skip.

.PARAMETER SkipDiskScan
    Only check running java processes and Program Files paths (fast mode).

.EXAMPLE
    .\Detect-Java4Shell.ps1
    .\Detect-Java4Shell.ps1 -NinjaField java4shellStatus
    .\Detect-Java4Shell.ps1 -Paths 'D:\Apps' -SkipDiskScan

.NOTES
    Version fix thresholds from Oracle Nov 2026 CPU / Qualys (2026-11-18). Update $FixedVersions as vendors publish.
    Read-only. No downloads, no changes to the system.
#>
[CmdletBinding()]
param(
    [string[]]$Paths,
    [string]$NinjaField,
    [switch]$SkipDiskScan
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------------------------
# Fixed-version table. Key = vendor match (regex on IMPLEMENTOR), value = hashtable major -> min fixed version
# ---------------------------------------------------------------------------------------------
$FixedVersions = @{
    'Oracle'  = @{ 17 = '17.0.21.1'; 21 = '21.0.13.1'; 25 = '25.0.5.1'; 27 = '27.0.1.1' }
    'Amazon'  = @{ 17 = '17.0.21.1.2' }   # Corretto - only 17 published so far
}
$AffectedMin      = [version]'17.0.6'
$LtsWithFixes     = 17, 21, 25, 27        # non-LTS majors (18-20, 22-24, 26) are EOL: no fix, always affected
$MitigationRegex  = '-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]\b'

function ConvertTo-Version([string]$s) {
    # Normalize "17.0.21.1.2", "21.0.13+11", "1.8.0_511" -> [version] (max 4 parts; [version] caps there)
    if (-not $s) { return $null }
    $s = $s -replace '^1\.8\.0_', '8.0.' -replace '[+\-_].*$', ''
    $parts = @(($s -split '\.') | Where-Object { $_ -match '^\d+$' })
    if ($parts.Count -eq 0) { return $null }
    while ($parts.Count -lt 2) { $parts += '0' }
    if ($parts.Count -gt 4) { $parts = $parts[0..3] }
    try { return [version]($parts -join '.') } catch { return $null }
}

function Compare-LongVersion([string]$a, [string]$b) {
    # Compares dotted versions of any length (Corretto uses 5 parts). Returns -1/0/1.
    $pa = @(($a -replace '[+\-_].*$', '') -split '\.' | ForEach-Object { [int]$_ })
    $pb = @(($b -replace '[+\-_].*$', '') -split '\.' | ForEach-Object { [int]$_ })
    $n = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($x -lt $y) { return -1 }; if ($x -gt $y) { return 1 }
    }
    return 0
}

function Find-JavaExe([string[]]$Roots) {
    $found = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $skip  = '\\(\$Recycle\.Bin|System Volume Information|Windows\\WinSxS|Windows\\servicing|Windows\\Installer)(\\|$)'
    foreach ($root in $Roots) {
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            if ($dir -match $skip) { continue }
            try {
                foreach ($f in [IO.Directory]::GetFiles($dir, 'java.exe')) { [void]$found.Add($f) }
                foreach ($d in [IO.Directory]::GetDirectories($dir)) {
                    $attr = [IO.File]::GetAttributes($d)
                    if (-not ($attr -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($d) }
                }
            } catch { }
        }
    }
    return $found
}

function Get-PEArch([string]$Path) {
    # Reads the PE header machine type: x86 / x64 / arm64. The bug only exists in x86-64 HotSpot.
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $br = New-Object IO.BinaryReader($fs)
            $fs.Position = 0x3C; $pe = $br.ReadInt32()
            $fs.Position = $pe + 4; $m = $br.ReadUInt16()
        } finally { $fs.Dispose() }
        switch ($m) { 0x14C { 'x86' } 0x8664 { 'x64' } 0xAA64 { 'arm64' } default { 'unknown' } }
    } catch { 'unknown' }
}

function Get-JavaInfo([string]$JavaExe) {
    $binDir  = Split-Path $JavaExe -Parent
    $jhome   = Split-Path $binDir -Parent
    $release = Join-Path $jhome 'release'
    $info = [ordered]@{ Path = $JavaExe; Home = $jhome; Vendor = ''; Version = ''; ImplVersion = ''; Arch = (Get-PEArch $JavaExe) }

    if (Test-Path $release) {
        foreach ($line in Get-Content $release) {
            if ($line -match '^\s*(\w+)\s*=\s*"?(.*?)"?\s*$') {
                switch ($Matches[1]) {
                    'IMPLEMENTOR'         { $info.Vendor = $Matches[2] }
                    'JAVA_VERSION'        { $info.Version = $Matches[2] }
                    'IMPLEMENTOR_VERSION' { $info.ImplVersion = $Matches[2] }
                }
            }
        }
    }
    if (-not $info.Version) {
        # Fallback: ask the binary (output goes to stderr)
        $out = (& $JavaExe -version 2>&1 | Out-String)
        if ($out -match 'version "([^"]+)"') { $info.Version = $Matches[1] }
        if ($out -match '(Oracle|Corretto|Temurin|Adoptium|Zulu|Microsoft|Red Hat|IBM|Semeru|Liberica|BellSoft|SapMachine)') {
            $info.Vendor = $Matches[1]
        }
        if ($out -match '(Corretto-[\d\.]+)') { $info.ImplVersion = $Matches[1] }
        if ($out -match '-perf') { $info.ImplVersion += ' perf' }
    }
    $fvi = (Get-Item $JavaExe).VersionInfo
    if (-not $info.Vendor) { $info.Vendor = $fvi.CompanyName }
    if (-not $info.Version) {
        # Last resort: file version resource (e.g. SAP JVM, where java -version may not run standalone)
        $fv = if ($fvi.ProductVersion) { $fvi.ProductVersion } else { $fvi.FileVersion }
        if ($fv -match '(\d+(\.\d+)+)') { $info.Version = $Matches[1] }
    }
    return [pscustomobject]$info
}

function Test-CpuVbmi([string[]]$JavaExes) {
    # 1) Ask HotSpot directly - it prints the CPU feature list it detected (works on PS 5.1)
    foreach ($j in $JavaExes) {
        $out = (& $j '-Xlog:os+cpu' -version 2>&1 | Out-String)
        if ($out -match 'features:|CPU:') {
            if ($out -match 'avx512_vbmi\b') { return @{ Vbmi = $true;  Source = "JVM ($j)" } }
            else                             { return @{ Vbmi = $false; Source = "JVM ($j)" } }
        }
    }
    # 2) .NET 8+ hardware intrinsics (current pwsh, or pwsh.exe if installed)
    $check = '[System.Runtime.Intrinsics.X86.Avx512Vbmi]::IsSupported'
    try {
        $t = [type]'System.Runtime.Intrinsics.X86.Avx512Vbmi'
        if ($t) { return @{ Vbmi = [bool]$t::IsSupported; Source = '.NET intrinsics' } }
    } catch { }
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($pwsh) {
        $r = (& $pwsh.Source -NoProfile -Command $check 2>$null | Out-String).Trim()
        if ($r -in 'True', 'False') { return @{ Vbmi = ($r -eq 'True'); Source = 'pwsh .NET intrinsics' } }
    }
    # 3) CPU model name (used when only Java 8 is present and no .NET 8). Lists AVX-512 VBMI families.
    $name = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    $vbmiRx = @(
        'Xeon.*(Bronze|Silver|Gold|Platinum)\s+\d[345]\d\d',   # Ice Lake-SP (x3xx), Sapphire (x4xx), Emerald (x5xx)
        'Xeon\(R\)\s*6\d{3}',                                  # Xeon 6 (Granite Rapids)
        'Xeon.*\bW-3[3-5]\d\d|Xeon.*\bw[3579]-[23]\d{3}',     # Ice Lake / Sapphire workstation
        '11th Gen Intel',                                          # Tiger Lake / Rocket Lake
        'Core\(TM\) i\d-10\d\dG\d',                           # Ice Lake client (10th gen "G")
        'EPYC\s*(9\d{3}|8\d{3}|4\d{3})',                       # Zen 4/5 EPYC
        'Ryzen.*\b(7|8|9)\d{3}|Ryzen AI|Threadripper.*(7\d{3}|9\d{3})'  # Zen 4/5 desktop/mobile
    ) -join '|'
    if ($name -match 'Apple|ARM|Snapdragon') { return @{ Vbmi = $false; Source = "CPU model ($name)" } }
    if ($name -match $vbmiRx)                { return @{ Vbmi = $true;  Source = "CPU model heuristic ($name)" } }
    if ($name -match 'Intel|AMD')            { return @{ Vbmi = $false; Source = "CPU model heuristic ($name)" } }
    return @{ Vbmi = $null; Source = 'unknown' }
}

function Get-MitigationState {
    $hits = @()
    foreach ($scope in 'Machine', 'Process') {
        foreach ($v in 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS') {
            $val = [Environment]::GetEnvironmentVariable($v, $scope)
            if ($val -match $MitigationRegex) { $hits += "$scope env $v" }
        }
    }
    $procs = Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" |
        Select-Object ProcessId, ExecutablePath, CommandLine
    return @{ GlobalHits = $hits; Processes = $procs }
}

function Get-Status($rt, $cpu, $mit) {
    $vendorUnknown = $false
    if ($rt.Arch -in 'x86', 'arm64') { return "NOT-AFFECTED-$($rt.Arch.ToUpper())" }
    $ver = ConvertTo-Version $rt.Version
    if (-not $ver) { return 'UNKNOWN-VERSION' }

    $isPerf8 = ($ver.Major -eq 8 -and ($rt.ImplVersion -match 'perf' -or $rt.Version -match 'perf'))
    if ($ver.Major -lt 17 -and -not $isPerf8) { return 'NOT-AFFECTED' }
    if ($isPerf8) {
        # Only 8u511b33-perf named as affected; fixed in 8u513-perf
        if ($ver.Build -ge 513) { return 'NOT-AFFECTED' }
    } else {
        if ($ver -lt $AffectedMin) { return 'NOT-AFFECTED' }

        $fixedKnown = $false
        foreach ($vendorKey in $FixedVersions.Keys) {
            if ($rt.Vendor -match $vendorKey -and $FixedVersions[$vendorKey].ContainsKey($ver.Major)) {
                $fixedKnown = $true
                $cmpVer = if ($vendorKey -eq 'Amazon' -and $rt.ImplVersion -match '([\d\.]+)$') { $Matches[1] } else { $rt.Version }
                if ((Compare-LongVersion $cmpVer $FixedVersions[$vendorKey][$ver.Major]) -ge 0) { return 'NOT-AFFECTED' }
            }
        }
        if (-not $fixedKnown -and $LtsWithFixes -contains $ver.Major -and $rt.Vendor -notmatch 'Oracle') {
            $vendorUnknown = $true
        }
    }

    # In affected range and not known-fixed
    $procMitigated = @($mit.Processes | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($rt.Home, [StringComparison]::OrdinalIgnoreCase) -and
        $_.CommandLine -match $MitigationRegex })
    if ($mit.GlobalHits.Count -gt 0 -or $procMitigated.Count -gt 0) { return 'MITIGATED-FLAG' }
    if ($cpu.Vbmi -eq $false) { return 'AFFECTED-VERSION' }
    if ($vendorUnknown)        { return 'CHECK-VENDOR' }
    if ($cpu.Vbmi -eq $true)   { return 'VULNERABLE' }
    return 'VULNERABLE-CPU?'
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
if (-not $Paths) {
    if ($SkipDiskScan) {
        $Paths = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ }
    } else {
        $Paths = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID)\" }
    }
}

Write-Host "Java4Shell (CVE-2026-114938) scan - $env:COMPUTERNAME - $(Get-Date -Format s)"
Write-Host "Scanning: $($Paths -join ', ')"

$javaExes = @(Find-JavaExe $Paths)
$mit = Get-MitigationState
# Include executables of running processes even if outside scanned paths
foreach ($p in $mit.Processes) {
    if ($p.ExecutablePath -and $javaExes -notcontains $p.ExecutablePath) { $javaExes += $p.ExecutablePath }
}

$cpuName = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
if (-not $javaExes) {
    $summary = "NOT-AFFECTED: no Java runtimes found | CPU: $cpuName"
    Write-Host $summary
    if ($NinjaField -and (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) { Ninja-Property-Set $NinjaField $summary }
    exit 0
}

$cpu = Test-CpuVbmi $javaExes
Write-Host ("CPU: {0} | AVX-512 VBMI: {1} (via {2})" -f $cpuName, $(if ($null -eq $cpu.Vbmi) { 'UNKNOWN' } else { $cpu.Vbmi }), $cpu.Source)
if ($mit.GlobalHits) { Write-Host "Global mitigation flags found: $($mit.GlobalHits -join '; ')" }

$results = foreach ($exe in $javaExes) {
    $rt = Get-JavaInfo $exe
    $running = @($mit.Processes | Where-Object { $_.ExecutablePath -eq $exe }).Count
    [pscustomobject]@{
        Status   = Get-Status $rt $cpu $mit
        Version  = if ($rt.ImplVersion) { "$($rt.Version) ($($rt.ImplVersion))" } else { $rt.Version }
        Vendor   = $rt.Vendor
        Arch     = $rt.Arch
        Running  = $running
        Path     = $rt.Path
    }
}

$order = 'VULNERABLE', 'VULNERABLE-CPU?', 'CHECK-VENDOR', 'MITIGATED-FLAG', 'AFFECTED-VERSION', 'UNKNOWN-VERSION', 'NOT-AFFECTED-X86', 'NOT-AFFECTED-ARM64', 'NOT-AFFECTED'
$results = $results | Sort-Object { [array]::IndexOf($order, $_.Status) }, Path
$results | Format-Table -AutoSize | Out-String -Width 300 | Write-Host

$worst = $results[0].Status
$counts = ($results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
$flagged = $results | Where-Object { $_.Status -notlike 'NOT-AFFECTED*' } |
    ForEach-Object { "$($_.Status): $($_.Vendor) $($_.Version) - $($_.Path)" }
$summary = "$worst | $counts | VBMI=$($cpu.Vbmi) | $(Get-Date -Format 'yyyy-MM-dd')"
if ($flagged) { $summary += "`n" + ($flagged -join "`n") }

if ($NinjaField -and (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
    Ninja-Property-Set $NinjaField $summary
    Write-Host "Wrote summary to Ninja field '$NinjaField'"
}

if ($worst -in 'VULNERABLE', 'VULNERABLE-CPU?', 'CHECK-VENDOR') { exit 1 } else { exit 0 }

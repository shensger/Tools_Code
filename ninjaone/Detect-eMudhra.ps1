<#
.SYNOPSIS
    Detects eMudhra software, drivers, services, processes, files and certificates on Windows.

.DESCRIPTION
    Designed to run as SYSTEM from NinjaOne. Checks:
      - Installed software (HKLM 64/32-bit + every loaded/unloaded user hive)
      - Services and kernel drivers
      - Running processes
      - Common install folders
      - Certificates issued by / issued to eMudhra in machine stores
        (Root, AuthRoot, CA, My, TrustedPublisher) and every user's personal store (read from registry)

    eMudhra-branded hits are "Confirmed". Generic DSC token middleware commonly shipped with
    eMudhra tokens (ProxKey/Watchdata, ePass2003) is reported separately as "Related".

.NINJA SCRIPT VARIABLES (optional, set as Script Variables in Ninja)
    customFieldName  - Ninja text/multiline custom field to write the result to (e.g. emudhraStatus)
    exitOnDetect     - "true" = exit 1 when eMudhra is found (for compound conditions / alerting)

.NOTES
    Repo: shensger/tools_code
#>

[CmdletBinding()]
param(
    [string]$CustomFieldName = $env:customFieldName,
    [string]$ExitOnDetect    = $env:exitOnDetect
)

$ErrorActionPreference = 'SilentlyContinue'

$Primary = 'eMudhra|emSigner|eSigner|e-Mudhra'
$Related = 'ProxKey|Watchdata|WD ?Proxkey|ePass2003|ePass ?3003|FEITIAN'
$Any     = "$Primary|$Related"

$results = New-Object System.Collections.Generic.List[object]
function Add-Hit($Category, $Name, $Detail, $Match) {
    $conf = if ("$Name $Detail" -match $Primary) { 'Confirmed' } else { 'Related' }
    $results.Add([pscustomobject]@{ Confidence = $conf; Category = $Category; Name = $Name; Detail = $Detail })
}

# ---------- 1. Installed software (machine) ----------
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($p in $uninstallPaths) {
    Get-ItemProperty $p | Where-Object { "$($_.DisplayName) $($_.Publisher)" -match $Any } | ForEach-Object {
        Add-Hit 'Software (Machine)' $_.DisplayName "Ver $($_.DisplayVersion) | Publisher: $($_.Publisher) | $($_.InstallLocation)"
    }
}

# ---------- 2. Installed software + certs (per user, incl. logged-off users) ----------
function Get-CertFromBlob([byte[]]$blob) {
    # SystemCertificates registry blob: [propId(4)][reserved(4)][len(4)][data]... ; propId 32 = encoded cert
    $i = 0
    while ($i + 12 -le $blob.Length) {
        $propId = [BitConverter]::ToUInt32($blob, $i)
        $len    = [BitConverter]::ToUInt32($blob, $i + 8)
        if ($propId -eq 32) {
            $raw = New-Object byte[] $len
            [Array]::Copy($blob, $i + 12, $raw, 0, $len)
            return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw)
        }
        $i += 12 + $len
    }
}

$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath }
foreach ($prof in $profiles) {
    $sid      = $prof.SID
    $user     = Split-Path $prof.LocalPath -Leaf
    $hiveRoot = "Registry::HKEY_USERS\$sid"
    $loadedByUs = $false

    if (-not (Test-Path $hiveRoot)) {
        $ntuser = Join-Path $prof.LocalPath 'NTUSER.DAT'
        if (Test-Path $ntuser) {
            & reg.exe load "HKU\$sid" "$ntuser" 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $loadedByUs = $true }
        }
    }

    if (Test-Path $hiveRoot) {
        Get-ItemProperty "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
            Where-Object { "$($_.DisplayName) $($_.Publisher)" -match $Any } | ForEach-Object {
                Add-Hit 'Software (User)' $_.DisplayName "User: $user | Ver $($_.DisplayVersion)"
            }

        foreach ($store in 'My','CA','Root') {
            $certKey = "$hiveRoot\Software\Microsoft\SystemCertificates\$store\Certificates"
            Get-ChildItem $certKey | ForEach-Object {
                $blob = (Get-ItemProperty $_.PSPath).Blob
                if ($blob) {
                    $c = Get-CertFromBlob $blob
                    if ($c -and "$($c.Subject) $($c.Issuer)" -match $Primary) {
                        Add-Hit "Certificate (User\$store)" $c.Subject "User: $user | Issuer: $($c.Issuer) | Expires: $($c.NotAfter.ToString('yyyy-MM-dd')) | Thumb: $($c.Thumbprint)"
                    }
                }
            }
        }
    }

    if ($loadedByUs) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$sid" 2>$null | Out-Null
    }
}

# ---------- 3. Machine certificate stores ----------
foreach ($store in 'Root','AuthRoot','CA','My','TrustedPublisher') {
    Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object { "$($_.Subject) $($_.Issuer)" -match $Primary } | ForEach-Object {
        Add-Hit "Certificate (Machine\$store)" $_.Subject "Issuer: $($_.Issuer) | Expires: $($_.NotAfter.ToString('yyyy-MM-dd')) | Thumb: $($_.Thumbprint)"
    }
}

# ---------- 4. Services & drivers ----------
Get-CimInstance Win32_Service | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $Any } | ForEach-Object {
    Add-Hit 'Service' $_.DisplayName "Name: $($_.Name) | State: $($_.State) | Path: $($_.PathName)"
}
Get-CimInstance Win32_SystemDriver | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $Any } | ForEach-Object {
    Add-Hit 'Driver' $_.DisplayName "Name: $($_.Name) | State: $($_.State) | Path: $($_.PathName)"
}
Get-CimInstance Win32_PnPSignedDriver | Where-Object { "$($_.DeviceName) $($_.Manufacturer) $($_.DriverProviderName)" -match $Any } | ForEach-Object {
    Add-Hit 'PnP Device/Driver' $_.DeviceName "Provider: $($_.DriverProviderName) | Ver $($_.DriverVersion)"
}

# ---------- 5. Processes ----------
Get-Process | Where-Object { "$($_.ProcessName) $($_.Path) $($_.Company)" -match $Any } | ForEach-Object {
    Add-Hit 'Process' $_.ProcessName "PID $($_.Id) | $($_.Path)"
}

# ---------- 6. Install folders ----------
$folderRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
$folderRoots += $profiles | ForEach-Object { Join-Path $_.LocalPath 'AppData\Local'; Join-Path $_.LocalPath 'AppData\Roaming' }
foreach ($root in ($folderRoots | Where-Object { $_ -and (Test-Path $_) })) {
    Get-ChildItem $root -Directory | Where-Object { $_.Name -match $Any } | ForEach-Object {
        Add-Hit 'Folder' $_.Name $_.FullName
    }
}

# ---------- Output ----------
$results = $results | Sort-Object Confidence, Category, Name -Unique
$confirmed = @($results | Where-Object Confidence -eq 'Confirmed')
$related   = @($results | Where-Object Confidence -eq 'Related')

$status = if ($confirmed.Count) { 'DETECTED' } elseif ($related.Count) { 'RELATED ONLY' } else { 'NOT DETECTED' }

Write-Output "eMudhra detection on $env:COMPUTERNAME : $status (Confirmed: $($confirmed.Count), Related: $($related.Count))"
if ($results) { $results | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Output }

if ($CustomFieldName) {
    $summary = "$status | $(Get-Date -Format 'yyyy-MM-dd HH:mm') | " +
               (($results | ForEach-Object { "[$($_.Confidence)] $($_.Category): $($_.Name)" }) -join '; ')
    if ($summary.Length -gt 9000) { $summary = $summary.Substring(0, 9000) + '...' }
    try { Ninja-Property-Set $CustomFieldName $summary; Write-Output "Wrote result to custom field '$CustomFieldName'." }
    catch { Write-Output "WARNING: Could not write custom field '$CustomFieldName': $($_.Exception.Message)" }
}

if ($ExitOnDetect -eq 'true' -and $confirmed.Count) { exit 1 }
exit 0

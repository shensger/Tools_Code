<#
.SYNOPSIS
    Runs `curl.exe -v` against an HTTPS test URL (default: eMudhra DV G3B test site) and writes the result
    to a NinjaOne custom field.

.DESCRIPTION
    Designed to run as SYSTEM from NinjaOne. Uses the built-in Windows curl.exe, which uses Schannel and
    therefore validates against the Windows certificate store - so the result reflects whether this machine
    trusts (or distrusts) the certificate chain served by the URL.

    Result status:
      TRUSTED     - TLS handshake succeeded and an HTTP response came back
      UNTRUSTED   - certificate chain not trusted (untrusted/distrusted root, bad chain, name mismatch)
      REVOKED     - certificate revoked
      REVOCATION? - revocation check could not complete (offline CRL/OCSP)
      TLS ERROR   - other handshake failure
      NET ERROR   - DNS / connect / timeout failure (could not test trust)

.NINJA SCRIPT VARIABLES (optional, set as Script Variables in Ninja)
    url              - URL to test (default https://dv-g3b-emudhra.we-have-a-problem.com/)
    customFieldName  - Ninja custom field to write to (default: emudhraTlsTest)
    includeVerbose   - "true" = append the full curl -v output (needs a Multi-line or WYSIWYG field)
    timeoutSeconds   - curl --max-time (default 20)

.NOTES
    Repo: shensger/tools_code
    Exit codes: 0 = TRUSTED, 1 = UNTRUSTED/REVOKED/TLS ERROR, 2 = NET ERROR / curl missing
#>

[CmdletBinding()]
param(
    [string]$Url             = $(if ($env:url) { $env:url } else { 'https://dv-g3b-emudhra.we-have-a-problem.com/' }),
    [string]$CustomFieldName = $(if ($env:customFieldName) { $env:customFieldName } else { 'emudhraTlsTest' }),
    [string]$IncludeVerbose  = $env:includeVerbose,
    [int]   $TimeoutSeconds  = $(if ($env:timeoutSeconds) { [int]$env:timeoutSeconds } else { 20 })
)

$ErrorActionPreference = 'Continue'

function Set-Field([string]$Value) {
    if (-not $CustomFieldName) { return }
    if ($Value.Length -gt 9500) { $Value = $Value.Substring(0, 9500) + "`n...[truncated]" }
    try { Ninja-Property-Set $CustomFieldName $Value; Write-Output "Wrote result to custom field '$CustomFieldName'." }
    catch { Write-Output "WARNING: Could not write custom field '$CustomFieldName': $($_.Exception.Message)" }
}

# ---------- Locate curl.exe (handle 32-bit host on 64-bit OS) ----------
$curl = @("$env:SystemRoot\Sysnative\curl.exe", "$env:SystemRoot\System32\curl.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $curl) {
    $msg = "NET ERROR | $(Get-Date -Format 'yyyy-MM-dd HH:mm') | curl.exe not found (requires Windows 10 1803+ / Server 2019+)"
    Write-Output $msg; Set-Field $msg; exit 2
}

# ---------- Run curl -v (via cmd so stderr merges cleanly on PS 5.1) ----------
$cmdLine = "`"$curl`" -v -s -o NUL --max-time $TimeoutSeconds -w `"HTTPCODE:%{http_code}`" `"$Url`" 2>&1"
$raw      = cmd.exe /c $cmdLine
$exitCode = $LASTEXITCODE
$text     = ($raw | ForEach-Object { "$_" }) -join "`n"

# ---------- Parse ----------
$httpCode = if ($text -match 'HTTPCODE:(\d{3})') { $Matches[1] } else { '000' }
$ip       = if ($text -match 'Connected to \S+ \(([^)]+)\)') { $Matches[1] } else { '' }
$errLine  = ($raw | ForEach-Object { "$_" } | Where-Object { $_ -match 'schannel:|curl: \(\d+\)|SEC_E_|CRYPT_E_|CERT_E_' } |
            Select-Object -Last 1)

$status = switch -Regex ($text) {
    'CRYPT_E_REVOKED'                                                      { 'REVOKED'; break }
    'CRYPT_E_NO_REVOCATION_CHECK|CRYPT_E_REVOCATION_OFFLINE'               { 'REVOCATION?'; break }
    'SEC_E_UNTRUSTED_ROOT|CERT_E_UNTRUSTEDROOT|CERT_E_CHAINING|SEC_E_CERT_EXPIRED|CERT_E_EXPIRED|SEC_E_WRONG_PRINCIPAL|CERT_E_CN_NO_MATCH|TRUST_E_|CERT_E_' { 'UNTRUSTED'; break }
    default {
        if ($httpCode -ne '000')                         { 'TRUSTED' }
        elseif ($exitCode -in 6, 7, 28)                  { 'NET ERROR' }    # resolve / connect / timeout
        elseif ($exitCode -in 35, 51, 53, 58, 60, 77, 80) { 'TLS ERROR' }
        else                                             { 'NET ERROR' }
    }
}

$summary = "$status | $(Get-Date -Format 'yyyy-MM-dd HH:mm') | HTTP $httpCode | curl exit $exitCode" +
           $(if ($ip) { " | $ip" } else { '' }) +
           $(if ($status -ne 'TRUSTED' -and $errLine) { " | $($errLine.Trim())" } else { '' }) +
           " | $Url"

Write-Output "TLS test on $env:COMPUTERNAME : $summary"
Write-Output '----- curl -v output -----'
Write-Output $text

$fieldValue = if ($IncludeVerbose -eq 'true') { "$summary`n`n$text" } else { $summary }
Set-Field $fieldValue

switch ($status) {
    'TRUSTED'   { exit 0 }
    'NET ERROR' { exit 2 }
    default     { exit 1 }
}

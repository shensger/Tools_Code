<#
.SYNOPSIS
    Windows equivalent of:
        curl -sS https://dv-g3b-emudhra.we-have-a-problem.com/ ; echo "exit=$?"

.DESCRIPTION
    Hits the eMudhra G3 test host (chained to the compromised EM DV TLS CA - G3B)
    using the Windows certificate store (Schannel). A TLS/certificate failure is the
    GOOD result: it means this machine no longer trusts the compromised chain.

    Uses the built-in curl.exe (Windows 10 1803+ / Server 2019+). Note it calls
    curl.exe explicitly, because in Windows PowerShell 5.1 "curl" is an alias for
    Invoke-WebRequest. Falls back to Invoke-WebRequest if curl.exe is missing.

    Prints the output, "exit=N", and a one-line verdict.

    NinjaOne: when run by the Ninja agent, writes a one-line result to a device
    text custom field (default 'emudhraG3Status'), e.g.
        OK | exit=60 | curl.exe | 2026-10-22 09:20
    The first word is always OK, VULNERABLE or INCONCLUSIVE, so you can filter or
    alert on "starts with". Create the field as Text, device scope, Automations =
    Read/Write. Override the name with script variable ninjaField; "none" disables.

    Exit code: outside Ninja, curl's own exit code (fallback: 0 connected, 60 cert
    rejected, 1 other). Under Ninja, the verdict instead - 0 OK, 1 VULNERABLE,
    2 INCONCLUSIVE - so a good result doesn't show as a failed run.
    Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Test-EmudhraG3.ps1
#>
param(
    [string]$Url = 'https://dv-g3b-emudhra.we-have-a-problem.com/',
    [string]$NinjaField = $(if ($env:ninjaField) { $env:ninjaField } else { 'emudhraG3Status' })
)

$curl = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1

if ($curl) {
    $tool = 'curl.exe'
    & $curl.Source -sS --max-time 15 $Url
    $rc = $LASTEXITCODE
    # 0 = connected; 35 = Schannel handshake fail; 51/58/60/77 = cert problems.
    # Note: Schannel curl also returns 35 when it can't reach the CRL/OCSP server
    # (CRYPT_E_REVOCATION_OFFLINE) - check the error text if you get 35.
    switch ($rc) {
        0                          { $verdict = 'VULNERABLE: connected - this host still trusts the compromised chain' }
        { $_ -in 35,51,58,60,77 }  { $verdict = 'OK: TLS/certificate rejected - compromised chain not trusted' }
        default                    { $verdict = 'INCONCLUSIVE: curl failed for a non-TLS reason (DNS/network/timeout?)' }
    }
}
else {
    $tool = 'Invoke-WebRequest'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $resp.Content
        $rc = 0
        $verdict = 'VULNERABLE: connected - this host still trusts the compromised chain'
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg += ' | ' + $_.Exception.InnerException.Message }
        Write-Output "Invoke-WebRequest: $msg"
        if ($msg -match 'trust relationship|SSL|TLS|certificate|secure channel') {
            $rc = 60
            $verdict = 'OK: TLS/certificate rejected - compromised chain not trusted'
        }
        else {
            $rc = 1
            $verdict = 'INCONCLUSIVE: request failed for a non-TLS reason (DNS/network/timeout?)'
        }
    }
}

Write-Output ''
Write-Output "exit=$rc"
Write-Output "[Windows / $tool] $verdict"

# --- NinjaOne custom field -------------------------------------------------
$inNinja = [bool](Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)
$status  = ($verdict -split ':')[0]
if ($inNinja -and $NinjaField -and $NinjaField -ne 'none') {
    $value = '{0} | exit={1} | {2} | {3}' -f $status, $rc, $tool, (Get-Date -Format 'yyyy-MM-dd HH:mm')
    # Ninja-Property-Set reports problems (missing field, no write permission) as output text, not exceptions
    $result = Ninja-Property-Set $NinjaField $value 2>&1 | Out-String
    if ($result.Trim()) {
        Write-Output "NinjaOne field write failed: $($result.Trim()). Check that text field '$NinjaField' exists, applies to this device, and has Automations = Write."
    } else {
        Write-Output "Wrote to NinjaOne field '$NinjaField': $value"
    }
}

if ($inNinja) {
    switch ($status) { 'OK' { exit 0 } 'VULNERABLE' { exit 1 } default { exit 2 } }
}
exit $rc

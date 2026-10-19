<#
.SYNOPSIS
    NinjaOne automation: reports AD users whose passwords have expired or are about to,
    writes the results to NinjaOne custom fields, and exits non-zero when anyone needs an alert.

.DESCRIPTION
    Run on a domain controller (or a server with RSAT AD tools) as SYSTEM.

    Uses msDS-UserPasswordExpiryTimeComputed, so expiry dates are correct for the
    Default Domain Policy and for Fine-Grained Password Policies (PSOs).

    Status per user:
        Expired       - expiry date has passed
        ExpiringSoon  - expires within warningDays
        MustChange    - "User must change password at next logon" (pwdLastSet = 0)
        OK / NeverExpires are counted but not listed

    NinjaOne custom fields (device scope, Automations = Write; leave blank or 'none' to skip):
        summaryField (Text)       e.g. "2 expiring, 1 expired, 0 must change (14-day window) - 2026-10-19 09:45"
        detailField  (Multi-line) one line per alertable user

    Script variables (NinjaOne passes these as environment variables; parameters also work):
        warningDays      Days before expiry to flag ExpiringSoon. Default 14.
        searchBase       OU distinguished name to scope the search. Default: whole domain.
        includeDisabled  'true' to include disabled accounts. Default false.
        includeMustChange 'true' to count MustChange users as alertable. Default true.
        summaryField     Custom field name for the summary. Default 'adPasswordExpirySummary'.
        detailField      Custom field name for the detail list. Default 'adPasswordExpiryDetail'.

    Exit codes:
        0  ran OK, nobody needs an alert
        1  error (AD module missing, query failed, etc.)
        2  ran OK, one or more users are Expired / ExpiringSoon / MustChange

    Use exit code 2 (or a condition on the summary field) to trigger a NinjaOne alert/notification.

.NOTES
    Requires the ActiveDirectory PowerShell module.
#>
[CmdletBinding()]
param(
    [int]$WarningDays       = $(if ($env:warningDays) { [int]$env:warningDays } else { 14 }),
    [string]$SearchBase     = $env:searchBase,
    [switch]$IncludeDisabled = ($env:includeDisabled -eq 'true'),
    [string]$IncludeMustChange = $(if ($env:includeMustChange) { $env:includeMustChange } else { 'true' }),
    [string]$SummaryField   = $(if ($env:summaryField) { $env:summaryField } else { 'adPasswordExpirySummary' }),
    [string]$DetailField    = $(if ($env:detailField)  { $env:detailField }  else { 'adPasswordExpiryDetail' })
)

function Write-Log([string]$Message) { Write-Output $Message }

function Set-NinjaField([string]$Name, [string]$Value) {
    if (-not $Name -or $Name -eq 'none') { return }
    if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
        Write-Log "Ninja-Property-Set not available (not running under the NinjaOne agent) - skipping field '$Name'."
        return
    }
    try {
        # Ninja-Property-Set reports problems (missing field, no write permission) as output text, not exceptions
        $result = Ninja-Property-Set $Name $Value 2>&1 | Out-String
        if ($result -match 'error|not found|denied|invalid|unable|fail') {
            Write-Log "NinjaOne field write failed for '$Name': $($result.Trim()). Check the field exists, is assigned to this device's role, and has Automations = Write."
        } else {
            Write-Log "Wrote NinjaOne field '$Name'."
        }
    } catch {
        Write-Log "NinjaOne field write failed for '$Name': $($_.Exception.Message)"
    }
}

if ($WarningDays -lt 1 -or $WarningDays -gt 365) {
    Write-Log "ERROR: warningDays must be between 1 and 365 (got $WarningDays)."; exit 1
}
$countMustChange = $IncludeMustChange -ne 'false'

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Log "ERROR: ActiveDirectory module not available. Run this on a domain controller or a server with RSAT AD tools."
    exit 1
}

$now = Get-Date
$adParams = @{
    Filter     = if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' }
    Properties = @('DisplayName', 'mail', 'PasswordLastSet', 'pwdLastSet',
                   'PasswordNeverExpires', 'msDS-UserPasswordExpiryTimeComputed')
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }

try {
    $users = Get-ADUser @adParams -ErrorAction Stop
} catch {
    Write-Log "ERROR: AD query failed: $($_.Exception.Message)"
    exit 1
}

$neverValue = [Int64]::MaxValue
$results = foreach ($u in $users) {
    $expiryRaw  = $u.'msDS-UserPasswordExpiryTimeComputed'
    $expiryDate = $null
    $daysLeft   = $null

    if ($u.pwdLastSet -eq 0) {
        $status = 'MustChange'
    } elseif ($u.PasswordNeverExpires -or -not $expiryRaw -or $expiryRaw -eq $neverValue) {
        $status = 'NeverExpires'
    } else {
        $expiryDate = [datetime]::FromFileTime($expiryRaw)
        $daysLeft   = [math]::Floor(($expiryDate - $now).TotalDays)
        $status = if ($expiryDate -le $now) { 'Expired' }
                  elseif ($daysLeft -le $WarningDays) { 'ExpiringSoon' }
                  else { 'OK' }
    }

    [PSCustomObject]@{
        User     = $u.SamAccountName
        Name     = $u.DisplayName
        Email    = $u.mail
        LastSet  = $u.PasswordLastSet
        Expires  = $expiryDate
        DaysLeft = $daysLeft
        Status   = $status
    }
}

$alertStatuses = @('Expired', 'ExpiringSoon')
if ($countMustChange) { $alertStatuses += 'MustChange' }

$alertable = @($results | Where-Object { $_.Status -in $alertStatuses } |
    Sort-Object @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { $_.DaysLeft } } }, User)

$count = @{}
foreach ($s in 'Expired', 'ExpiringSoon', 'MustChange', 'OK', 'NeverExpires') {
    $count[$s] = @($results | Where-Object Status -eq $s).Count
}

$summary = "{0} expiring, {1} expired, {2} must change ({3}-day window) - {4}" -f `
    $count.ExpiringSoon, $count.Expired, $count.MustChange, $WarningDays, $now.ToString('yyyy-MM-dd HH:mm')

Write-Log "AD password expiry check on $env:COMPUTERNAME"
Write-Log "Users checked: $(@($results).Count) | Expired: $($count.Expired) | ExpiringSoon: $($count.ExpiringSoon) | MustChange: $($count.MustChange) | OK: $($count.OK) | NeverExpires: $($count.NeverExpires)"
Write-Log ""

# Compact one-line-per-user output so it reads cleanly in the Ninja activity log
$lines = foreach ($r in $alertable) {
    $when = switch ($r.Status) {
        'Expired'      { "expired $($r.Expires.ToString('yyyy-MM-dd')) ($([math]::Abs($r.DaysLeft))d ago)" }
        'ExpiringSoon' { "expires $($r.Expires.ToString('yyyy-MM-dd')) (in $($r.DaysLeft)d)" }
        'MustChange'   { 'must change at next logon' }
    }
    $last  = if ($r.LastSet) { $r.LastSet.ToString('yyyy-MM-dd') } else { 'never' }
    $email = if ($r.Email) { $r.Email } else { 'no email' }
    "[$($r.Status)] $($r.User) <$email> - $when, last set $last"
}

if ($lines) {
    Write-Log "Users needing attention:"
    $lines | ForEach-Object { Write-Log "  $_" }
} else {
    Write-Log "No users need attention."
}
Write-Log ""

# Custom fields
Set-NinjaField $SummaryField $summary
$detail = if ($lines) { $lines -join "`n" } else { "None - $summary" }
if ($detail.Length -gt 9500) {
    $detail = $detail.Substring(0, 9500) + "`n... (truncated, see activity log)"
}
Set-NinjaField $DetailField $detail

if ($alertable.Count -gt 0) {
    Write-Log "Result: $($alertable.Count) user(s) need attention - exiting 2."
    exit 2
}
Write-Log "Result: no users need attention."
exit 0

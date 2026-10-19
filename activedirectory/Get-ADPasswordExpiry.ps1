<#
.SYNOPSIS
    Reports each AD user's last password change and when their password expires.

.DESCRIPTION
    Uses msDS-UserPasswordExpiryTimeComputed, so the expiry date is correct for both the
    Default Domain Policy and any Fine-Grained Password Policies (PSOs).

    Outputs one object per user with a Status field so the results can be piped straight
    into an alerting / email step later, e.g.:

        .\Get-ADPasswordExpiry.ps1 -WarningDays 14 |
            Where-Object Status -eq 'ExpiringSoon' |
            ForEach-Object { <send alert to $_.EmailAddress> }

    Status values:
        Expired          - expiry date has passed
        ExpiringSoon     - expires within -WarningDays
        OK               - expires later than -WarningDays
        NeverExpires     - PasswordNeverExpires set, or no max age in effect
        MustChange       - "User must change password at next logon" (pwdLastSet = 0)

.PARAMETER SearchBase
    OU distinguished name to scope the search. Defaults to the whole domain.

.PARAMETER Server
    Domain controller or domain to query. Defaults to the current domain.

.PARAMETER WarningDays
    Number of days before expiry that a user is flagged ExpiringSoon. Default 14.

.PARAMETER IncludeDisabled
    Include disabled accounts (excluded by default).

.PARAMETER OnlyAlertable
    Return only users with Status Expired, ExpiringSoon, or MustChange.

.PARAMETER CsvPath
    Optional path to export the results to CSV.

.EXAMPLE
    .\Get-ADPasswordExpiry.ps1 | Format-Table -AutoSize

.EXAMPLE
    .\Get-ADPasswordExpiry.ps1 -SearchBase "OU=Staff,DC=contoso,DC=com" -WarningDays 7 -OnlyAlertable

.EXAMPLE
    .\Get-ADPasswordExpiry.ps1 -CsvPath C:\Reports\PasswordExpiry.csv

.NOTES
    Requires the ActiveDirectory module (RSAT) and read access to user objects.
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$Server,
    [ValidateRange(1, 365)]
    [int]$WarningDays = 14,
    [switch]$IncludeDisabled,
    [switch]$OnlyAlertable,
    [string]$CsvPath
)

Import-Module ActiveDirectory -ErrorAction Stop

$now = Get-Date

# ---- Build Get-ADUser query ----
$adParams = @{
    Filter     = if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' }
    Properties = @(
        'DisplayName', 'mail', 'Enabled', 'PasswordLastSet', 'pwdLastSet',
        'PasswordNeverExpires', 'PasswordExpired', 'msDS-UserPasswordExpiryTimeComputed',
        'LastLogonDate'
    )
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }
if ($Server)     { $adParams.Server     = $Server }

Write-Verbose "Querying AD users..."
$users = Get-ADUser @adParams

# 0x7FFFFFFFFFFFFFFF = "never" in AD large-integer attributes
$neverValue = [Int64]::MaxValue

$results = foreach ($u in $users) {
    $expiryRaw  = $u.'msDS-UserPasswordExpiryTimeComputed'
    $expiryDate = $null
    $daysLeft   = $null

    if ($u.pwdLastSet -eq 0) {
        $status = 'MustChange'
    }
    elseif ($u.PasswordNeverExpires -or -not $expiryRaw -or $expiryRaw -eq 0 -or $expiryRaw -eq $neverValue) {
        $status = 'NeverExpires'
    }
    else {
        $expiryDate = [datetime]::FromFileTime($expiryRaw)
        $daysLeft   = [math]::Floor(($expiryDate - $now).TotalDays)

        $status = if ($expiryDate -le $now)        { 'Expired' }
                  elseif ($daysLeft -le $WarningDays) { 'ExpiringSoon' }
                  else                              { 'OK' }
    }

    $passwordAge = if ($u.PasswordLastSet) {
        [math]::Floor(($now - $u.PasswordLastSet).TotalDays)
    } else { $null }

    [PSCustomObject]@{
        SamAccountName  = $u.SamAccountName
        DisplayName     = $u.DisplayName
        EmailAddress    = $u.mail
        Enabled         = $u.Enabled
        PasswordLastSet = $u.PasswordLastSet
        PasswordAgeDays = $passwordAge
        PasswordExpires = $expiryDate
        DaysUntilExpiry = $daysLeft
        Status          = $status
        LastLogonDate   = $u.LastLogonDate
        DistinguishedName = $u.DistinguishedName
    }
}

if ($OnlyAlertable) {
    $results = $results | Where-Object { $_.Status -in 'Expired', 'ExpiringSoon', 'MustChange' }
}

# Soonest-expiring first; NeverExpires/MustChange at the end
$results = $results | Sort-Object @{ Expression = { if ($null -eq $_.DaysUntilExpiry) { [int]::MaxValue } else { $_.DaysUntilExpiry } } }, SamAccountName

if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $(@($results).Count) users to $CsvPath"
}

# Quick summary to the host (doesn't pollute the pipeline)
$summary = $results | Group-Object Status | Sort-Object Name |
    ForEach-Object { "{0}: {1}" -f $_.Name, $_.Count }
Write-Host ("Summary (warning window {0} days) - {1}" -f $WarningDays, ($summary -join ' | ')) -ForegroundColor Cyan

$results

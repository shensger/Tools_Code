<#
.SYNOPSIS
    Finds which Exchange Online object owns an email address (primary or alias)
    and who has access to it, forwards to it, or receives mail sent to it.

.DESCRIPTION
    Checks, in order:
      1. Any recipient (user/shared/room mailbox, group, M365 group, contact, mail user)
         that has the address as primary SMTP or as an alias (proxy address)
      2. Soft-deleted mailboxes holding the address
      3. Prefix match (e.g. cloudberry@ under another domain) if no exact hit
      4. For mailboxes: FullAccess, SendAs, SendOnBehalf delegates
      5. For groups: members
      6. Mailboxes that forward to the address

    Read-only. Runs in Azure Cloud Shell (admin center) or any PowerShell 7 session.

.EXAMPLE
    ./Find-EmailAddressOwner.ps1
    ./Find-EmailAddressOwner.ps1 -Address someone@yellowbrick.com -SkipForwardingScan
#>
[CmdletBinding()]
param(
    [string]$Address = 'cloudberry@yellowbrick.com',
    [switch]$SkipForwardingScan   # forwarding scan reads every mailbox; skip in very large tenants
)

$ErrorActionPreference = 'Stop'

# --- Connect --------------------------------------------------------------
if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement
if (-not (Get-ConnectionInformation | Where-Object State -eq 'Connected')) {
    Connect-ExchangeOnline -ShowBanner:$false
}

$filter = "EmailAddresses -eq 'smtp:$Address'"
$smtpList = { ($_.EmailAddresses | Where-Object { $_ -like 'smtp:*' }) -replace '^smtp:', '' -join '; ' }

# --- 1. Exact match on any recipient --------------------------------------
Write-Host "`n=== Recipients with $Address (primary or alias) ===" -ForegroundColor Cyan
$owners = @(Get-Recipient -Filter $filter -ResultSize Unlimited)
if ($owners) {
    $owners | Select-Object DisplayName, RecipientTypeDetails, PrimarySmtpAddress,
        @{n = 'IsPrimary'; e = { $_.PrimarySmtpAddress -eq $Address } },
        @{n = 'AllSmtpAddresses'; e = $smtpList } | Format-List
} else {
    Write-Host "No active recipient has this address." -ForegroundColor Yellow
}

# --- 2. Soft-deleted mailboxes --------------------------------------------
Write-Host "=== Soft-deleted mailboxes ===" -ForegroundColor Cyan
$deleted = @(Get-Mailbox -SoftDeletedMailbox -Filter $filter -ResultSize Unlimited -ErrorAction SilentlyContinue)
if ($deleted) {
    $deleted | Select-Object DisplayName, RecipientTypeDetails, PrimarySmtpAddress, WhenSoftDeleted | Format-List
} else { Write-Host "None." }

# --- 3. Prefix match if nothing exact --------------------------------------
if (-not $owners -and -not $deleted) {
    $local = $Address.Split('@')[0]
    Write-Host "=== Prefix match: smtp:$local* ===" -ForegroundColor Cyan
    $partial = @(Get-Recipient -Filter "EmailAddresses -like 'smtp:$local*'" -ResultSize Unlimited)
    if ($partial) {
        $partial | Select-Object DisplayName, RecipientTypeDetails, PrimarySmtpAddress,
            @{n = 'AllSmtpAddresses'; e = $smtpList } | Format-List
    } else { Write-Host "Nothing found. If the address still receives mail, check mail flow rules and accepted domains." }
}

# --- 4/5. Access and membership for each owner -----------------------------
foreach ($o in $owners) {
    $id = $o.PrimarySmtpAddress
    Write-Host "`n=== Access to $($o.DisplayName) [$($o.RecipientTypeDetails)] ===" -ForegroundColor Cyan

    switch -Wildcard ($o.RecipientTypeDetails) {
        '*Mailbox' {
            Write-Host "-- FullAccess --"
            Get-MailboxPermission -Identity $id |
                Where-Object { -not $_.IsInherited -and $_.User -notlike 'NT AUTHORITY\*' -and $_.User -notlike 'S-1-5-*' } |
                Select-Object User, AccessRights, Deny | Format-Table -AutoSize

            Write-Host "-- SendAs --"
            Get-RecipientPermission -Identity $id |
                Where-Object { $_.Trustee -notlike 'NT AUTHORITY\*' } |
                Select-Object Trustee, AccessRights | Format-Table -AutoSize

            Write-Host "-- SendOnBehalf --"
            (Get-Mailbox -Identity $id).GrantSendOnBehalfTo | ForEach-Object { (Get-Recipient $_).DisplayName }

            Write-Host "-- Forwarding set on this mailbox --"
            Get-Mailbox -Identity $id | Select-Object ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward | Format-List
        }
        'GroupMailbox' {
            Write-Host "-- Owners --"
            Get-UnifiedGroupLinks -Identity $id -LinkType Owners | Select-Object DisplayName, PrimarySmtpAddress | Format-Table -AutoSize
            Write-Host "-- Members --"
            Get-UnifiedGroupLinks -Identity $id -LinkType Members -ResultSize Unlimited | Select-Object DisplayName, PrimarySmtpAddress | Format-Table -AutoSize
        }
        '*Group' {
            Write-Host "-- Members --"
            Get-DistributionGroupMember -Identity $id -ResultSize Unlimited | Select-Object DisplayName, RecipientTypeDetails, PrimarySmtpAddress | Format-Table -AutoSize
        }
        default { Write-Host "No delegate/membership checks for this recipient type." }
    }
}

# --- 6. Mailboxes forwarding to the address -------------------------------
if (-not $SkipForwardingScan) {
    Write-Host "`n=== Mailboxes forwarding TO $Address ===" -ForegroundColor Cyan
    $ownerIds = $owners | ForEach-Object { $_.Identity.ToString() }
    $fwd = Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress |
        Where-Object {
            $_.ForwardingSmtpAddress -like "*$Address" -or
            ($_.ForwardingAddress -and $ownerIds -contains $_.ForwardingAddress.ToString())
        }
    if ($fwd) {
        $fwd | Select-Object DisplayName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress | Format-Table -AutoSize
    } else { Write-Host "None." }
}

Write-Host "`nDone." -ForegroundColor Green

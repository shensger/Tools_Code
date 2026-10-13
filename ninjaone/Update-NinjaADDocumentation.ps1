<#
.SYNOPSIS
    Collects Active Directory facts from a domain controller and writes them into a
    NinjaOne Documentation (Apps & Services) document built from the "Active Directory" template.

.DESCRIPTION
    Run as a NinjaOne automation script (System context) on ONE domain controller per client,
    ad hoc or on a schedule. Fills these template fields:

        AD Short Name, AD Level, Domain Admins, Domain Controller(s), DNS Server(s),
        DHCP Server(s), Schema Master, Read Only Domain Controllers, AD Servers

    It never touches "Directory Services Restore Mode password" or "TOTP" - enter those by hand.

    PREREQUISITES (one-time, in NinjaOne):
      1. The document must already exist (create it in the UI or via
         Administration > Apps > Documentation > Manage Templates > Import Document(s) from CSV).
      2. Each field above must allow Automation = Write (template editor > field > Permissions).
      3. Field machine names must match $FieldMap below. Check them in the template editor
         (each field's "Name"), and edit the right-hand values if they differ.

    NinjaOne script variables (optional, override the defaults below):
      templateName  - template ID or name   (default: "Active Directory")
      documentName  - document to update    (default: "<NetBIOS domain> Active Directory")
      whatIf        - "true" = only print what would be written

.NOTES
    Requires the ActiveDirectory module (present on DCs). DHCP lookup uses the DhcpServer
    module if installed, otherwise falls back to an AD query for authorized DHCP servers.
#>
[CmdletBinding()]
param(
    [string]$TemplateName = $(if ($env:templateName) { $env:templateName } else { 'Active Directory' }),
    [string]$DocumentName = $env:documentName,
    [switch]$WhatIfMode   = ($env:whatIf -eq 'true'),
    [string]$Separator    = '; ',
    [int]$StaleDays       = 90
)

# Template field label -> NinjaOne field machine name. Edit the right side to match your template.
$FieldMap = [ordered]@{
    'AD Short Name'                = 'adShortName'
    'AD Level'                     = 'adLevel'
    'Domain Admins'                = 'domainAdmins'
    'Domain Controller(s)'         = 'domainControllerS'
    'DNS Server(s)'                = 'dnsServerS'
    'DHCP Server(s)'               = 'dhcpServerS'
    'Schema Master'                = 'schemaMaster'
    'Read Only Domain Controllers'  = 'readOnlyDomainControllers'
    'AD Servers'                   = 'adServers'
}

$ErrorActionPreference = 'Stop'
try { Import-Module ActiveDirectory } catch { Write-Error "ActiveDirectory module not available - run this on a domain controller."; exit 1 }

$domain = Get-ADDomain
$forest = Get-ADForest
if (-not $DocumentName) { $DocumentName = "$($domain.NetBIOSName) Active Directory" }

function Format-Host($h) {
    $ip = try { ([System.Net.Dns]::GetHostAddresses($h) | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1).IPAddressToString } catch { $null }
    if ($ip) { "$h ($ip)" } else { $h }
}

# --- Collect ---------------------------------------------------------------
$dcs   = @(Get-ADDomainController -Filter * | Sort-Object HostName)
$rwDCs = @($dcs | Where-Object { -not $_.IsReadOnly })
$roDCs = @($dcs | Where-Object { $_.IsReadOnly })

$dcText   = ($rwDCs | ForEach-Object { "$($_.HostName) ($($_.IPv4Address), $($_.OperatingSystem))" }) -join $Separator
$rodcText = if ($roDCs) { ($roDCs | ForEach-Object { "$($_.HostName) ($($_.IPv4Address))" }) -join $Separator } else { 'None' }

$daSid  = "$($domain.DomainSID)-512"
$admins = @(Get-ADGroupMember -Identity $daSid -Recursive | Where-Object objectClass -eq 'user' |
            ForEach-Object { $_.SamAccountName } | Sort-Object -Unique)

# DNS: NS records for the AD zone (AD-integrated DNS servers)
$dns = try {
    @(Resolve-DnsName -Name $domain.DNSRoot -Type NS -DnsOnly | Where-Object Type -eq 'NS' |
      ForEach-Object { Format-Host $_.NameHost } | Sort-Object -Unique) -join $Separator
} catch { '' }
if (-not $dns) { $dns = ($rwDCs | ForEach-Object { Format-Host $_.HostName }) -join $Separator }

# DHCP: servers authorized in AD
$dhcp = try {
    @(Get-DhcpServerInDC | ForEach-Object { "$($_.DnsName) ($($_.IPAddress))" }) -join $Separator
} catch {
    try {
        $cfg = (Get-ADRootDSE).configurationNamingContext
        @(Get-ADObject -SearchBase "CN=NetServices,CN=Services,$cfg" -Filter "objectClass -eq 'dHCPClass' -and name -ne 'DhcpRoot'" |
          ForEach-Object { $_.Name }) -join $Separator
    } catch { '' }
}
if (-not $dhcp) { $dhcp = 'None authorized in AD (DHCP likely on firewall/router)' }

$cutoff  = (Get-Date).AddDays(-$StaleDays)
$servers = @(Get-ADComputer -Filter "OperatingSystem -like '*Server*' -and Enabled -eq 'True'" -Properties OperatingSystem, IPv4Address, LastLogonDate |
             Where-Object { $_.LastLogonDate -gt $cutoff } | Sort-Object Name |
             ForEach-Object { "$($_.Name) ($($_.IPv4Address), $($_.OperatingSystem))" })

$values = [ordered]@{
    'AD Short Name'                = $domain.NetBIOSName
    'AD Level'                     = "Domain: $($domain.DomainMode) / Forest: $($forest.ForestMode) ($($domain.DNSRoot))"
    'Domain Admins'                = $admins -join $Separator
    'Domain Controller(s)'         = $dcText
    'DNS Server(s)'                = $dns
    'DHCP Server(s)'               = $dhcp
    'Schema Master'                = $forest.SchemaMaster
    'Read Only Domain Controllers'  = $rodcText
    'AD Servers'                   = $servers -join $Separator
}

# --- Write -----------------------------------------------------------------
Write-Output "Template: $TemplateName | Document: $DocumentName | WhatIf: $WhatIfMode"
$failed = 0
foreach ($label in $FieldMap.Keys) {
    $field = $FieldMap[$label]
    $value = [string]$values[$label]
    Write-Output ("{0,-30} [{1}] = {2}" -f $label, $field, $value)
    if ($WhatIfMode) { continue }
    try {
        Ninja-Property-Docs-Set -TemplateId $TemplateName -DocumentName $DocumentName -AttributeName $field -AttributeValue $value
    } catch {
        $failed++
        Write-Warning "Failed to set '$label' ($field): $($_.Exception.Message)"
    }
}

if ($failed) {
    Write-Warning "$failed field(s) failed. Check the field machine names in `$FieldMap, Automation=Write permission, and that '$DocumentName' exists in '$TemplateName'."
    exit 1
}
Write-Output 'Done.'

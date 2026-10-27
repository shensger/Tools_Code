<#
.SYNOPSIS
    Removes stale docking-station device entries and dock driver packages so Windows re-detects
    and reinstalls them cleanly on the next connect.

.DESCRIPTION
    Targets ONLY dock-related items - never the laptop's own Thunderbolt controllers, Wi-Fi, GPU, etc.:
      1. Device nodes for docks / dock components (Lenovo TB4 dock DMC & audio, DisplayLink, Realtek USB NICs,
         dock audio endpoints) that are NOT present or are in an error state.
      2. Third-party driver packages for those components (DisplayLink, Realtek USB Ethernet) - optional.
      3. Triggers a Plug and Play rescan.

    DEFAULT IS REPORT-ONLY. Nothing changes unless -Apply is passed (or Ninja script variable/env "Apply" = true).

    Recommended sequence:
      - Have the user UNPLUG the dock.
      - Run with -Apply (add -RemoveDriverPackages for a full driver reset).
      - Reboot.
      - Plug the dock in and let Windows / Lenovo System Update install drivers.

.PARAMETER Apply
    Actually remove things. Without it, only lists what would be removed.

.PARAMETER RemoveDriverPackages
    Also delete DisplayLink and Realtek USB Ethernet driver packages from the driver store
    (pnputil /delete-driver /uninstall /force). Windows inbox drivers or Lenovo System Update
    reinstall them on reconnect.

.NOTES
    Run as SYSTEM from NinjaOne. Requires Windows 10 2004+ (pnputil /remove-device, /scan-devices).
    Ninja: create script variables (checkbox) named "Apply" and "RemoveDriverPackages", or pass as parameters.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$RemoveDriverPackages
)

$ErrorActionPreference = 'Continue'
# Ninja script variables arrive as env vars ("true"/"false")
if ($env:Apply -eq 'true')                { $Apply = $true }
if ($env:RemoveDriverPackages -eq 'true') { $RemoveDriverPackages = $true }

$mode = if ($Apply) { 'APPLY' } else { 'REPORT-ONLY (pass -Apply to make changes)' }
Write-Output "Mode: $mode   RemoveDriverPackages: $([bool]$RemoveDriverPackages)"
Write-Output ""

# ---------------- What counts as "dock" ----------------
# Hardware ID patterns
$idPatterns = @(
    'VID_17EF&PID_A5D9',     # Lenovo TB4 Smart Dock Gen 2 DMC
    'VID_17EF&PID_30B[0-9A-F]', # Lenovo TB / USB-C dock USB audio family
    'VID_17EF&PID_A3[0-9A-F]{2}', # Lenovo dock hubs / controllers
    'VID_17E9&',             # DisplayLink (incl. Kensington DisplayLink docks)
    'VID_0BDA&PID_815[0-9A-F]' # Realtek USB GbE / 2.5GbE (dock NICs)
)
$namePattern = 'Dock|DisplayLink|USB GbE|USB 2\.5GbE|Realtek USB'

# Never touch these, even if a name matches
$protectPattern = 'Thunderbolt\(TM\) Controller|Thunderbolt\(TM\) HSA|Retimer|System Firmware|Embedded controller|Wi-Fi|Bluetooth'

function Test-IsDockDevice($dev) {
    if ($dev.FriendlyName -match $protectPattern) { return $false }
    foreach ($p in $idPatterns) { if ($dev.InstanceId -match $p) { return $true } }
    if ($dev.FriendlyName -match $namePattern) { return $true }
    return $false
}

# ---------------- 1. Device nodes ----------------
Write-Output "=== DOCK DEVICE NODES (not present or in error) ==="
$all = Get-PnpDevice
$targets = $all | Where-Object { (Test-IsDockDevice $_) -and ( -not $_.Present -or $_.Status -eq 'Error' ) }

# Also dock audio endpoints (SWD\MMDEVAPI) named after dock/DisplayLink that are not present
$targets += $all | Where-Object {
    $_.InstanceId -like 'SWD\MMDEVAPI\*' -and -not $_.Present -and $_.FriendlyName -match 'DisplayLink|Dock|ThinkPad'
}
$targets = $targets | Sort-Object InstanceId -Unique

if (-not $targets) { Write-Output "None found." }
$removedDevs = 0; $failedDevs = 0
foreach ($d in $targets) {
    $line = "{0,-8} {1,-7} {2,-18} {3}  [{4}]" -f $d.Status, $d.Present, $d.Class, $d.FriendlyName, $d.InstanceId
    if ($Apply) {
        $out = & pnputil.exe /remove-device "$($d.InstanceId)" 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Output "REMOVED  $line"; $removedDevs++ }
        else { Write-Output "FAILED   $line  -> $($out -join ' ')"; $failedDevs++ }
    } else {
        Write-Output "WOULD REMOVE  $line"
    }
}
Write-Output ""

# ---------------- 2. Driver packages ----------------
Write-Output "=== DOCK DRIVER PACKAGES IN DRIVER STORE ==="
$pkgs = Get-WindowsDriver -Online | Where-Object {
    ($_.ProviderName -match 'DisplayLink') -or
    ($_.ClassName -eq 'Net' -and $_.ProviderName -match 'Realtek' -and $_.OriginalFileName -match '\\rtu|\\rtux|usb') -or
    ($_.OriginalFileName -match '\\dl[a-z]*\.inf$')
}
if (-not $pkgs) { Write-Output "None found." }
foreach ($p in $pkgs) {
    $line = "{0,-12} {1,-12} {2,-16} {3}" -f $p.Driver, $p.ProviderName, $p.Version, (Split-Path $p.OriginalFileName -Leaf)
    if ($Apply -and $RemoveDriverPackages) {
        $out = & pnputil.exe /delete-driver $p.Driver /uninstall /force 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Output "DELETED  $line" } else { Write-Output "FAILED   $line -> $($out -join ' ')" }
    } elseif ($RemoveDriverPackages) {
        Write-Output "WOULD DELETE  $line"
    } else {
        Write-Output "FOUND (kept; use -RemoveDriverPackages to delete)  $line"
    }
}
Write-Output ""

# ---------------- 3. Rescan ----------------
if ($Apply) {
    Write-Output "=== PNP RESCAN ==="
    & pnputil.exe /scan-devices | Write-Output
    Write-Output ""
    Write-Output "Device nodes removed: $removedDevs   failed: $failedDevs"
    Write-Output "NEXT: reboot, then connect the dock (on its own power) and wait ~1 minute for drivers to install."
    Write-Output "      Then run Lenovo System Update / Lenovo Dock Manager for dock firmware."
} else {
    Write-Output "Report only - nothing changed."
}
exit 0

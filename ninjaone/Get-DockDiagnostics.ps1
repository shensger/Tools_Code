<#
.SYNOPSIS
    Read-only docking station / Thunderbolt / USB4 diagnostic for Windows laptops (built for Lenovo ThinkPads).

.DESCRIPTION
    Run from NinjaOne as SYSTEM. Collects everything needed to answer "why won't the dock work":
      - Model, BIOS version/date, OS build (flags Insider builds)
      - Thunderbolt / USB4 controllers and their device status / problem codes
      - Any Plug and Play device in an error state
      - Connected docks (Lenovo / ThinkPad / DisplayLink / Realtek USB NIC / USB hubs)
      - Thunderbolt security level & Kernel DMA Protection
      - Monitors / display adapters
      - Recent Thunderbolt / USB / Kernel-PnP / display driver events (last 7 days)
      - Recently installed drivers (last 30 days) - catches a driver update that broke it
    Makes no changes.

.NOTES
    Exit 0 always; read the output in the Ninja activity log.
#>

$ErrorActionPreference = 'SilentlyContinue'
function Section($t) { Write-Output ""; Write-Output ("=" * 70); Write-Output " $t"; Write-Output ("=" * 70) }

# ---------- System ----------
Section "SYSTEM"
$cs   = Get-CimInstance Win32_ComputerSystem
$csp  = Get-CimInstance Win32_ComputerSystemProduct
$bios = Get-CimInstance Win32_BIOS
$os   = Get-CimInstance Win32_OperatingSystem
$cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[pscustomobject]@{
    Model        = "$($cs.Manufacturer) $($cs.Model) ($($csp.Version))"
    BIOS         = "$($bios.SMBIOSBIOSVersion)  released $($bios.ReleaseDate.ToString('yyyy-MM-dd'))"
    OS           = "$($os.Caption) build $($cv.CurrentBuild).$($cv.UBR)  ($($cv.DisplayVersion))"
    LastBoot     = $os.LastBootUpTime
} | Format-List | Out-String -Width 200 | Write-Output

$flight = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability'
if ($flight.BranchName -or [int]$cv.CurrentBuild -ge 26200) {
    Write-Output "!! Insider / pre-release build detected. Branch: '$($flight.BranchName)'  Ring: '$($flight.Ring)'"
    Write-Output "!! OEM Thunderbolt/USB4/dock drivers are frequently broken on Insider builds."
}

# ---------- Problem devices ----------
Section "PNP DEVICES IN ERROR STATE"
$bad = Get-PnpDevice | Where-Object { $_.Status -ne 'OK' -and $_.Present }
if ($bad) {
    $bad | ForEach-Object {
        $code = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode').Data
        [pscustomobject]@{ Status=$_.Status; Class=$_.Class; Name=$_.FriendlyName; ProblemCode=$code; Id=$_.InstanceId }
    } | Format-Table -AutoSize | Out-String -Width 300 | Write-Output
} else { Write-Output "None - all present devices report OK." }

# ---------- Thunderbolt / USB4 ----------
Section "THUNDERBOLT / USB4 CONTROLLERS & DEVICES"
Get-PnpDevice | Where-Object {
    $_.FriendlyName -match 'Thunderbolt|USB4|USB 4|Host Router|Connection Manager' -or $_.Class -match 'Thunderbolt|USB4'
} | Select-Object Status, Present, Class, FriendlyName, InstanceId |
    Format-Table -AutoSize | Out-String -Width 300 | Write-Output

Section "THUNDERBOLT / USB4 DRIVER VERSIONS"
Get-CimInstance Win32_PnPSignedDriver | Where-Object {
    $_.DeviceName -match 'Thunderbolt|USB4|USB 4|Host Router|xHCI|USB Root Hub \(USB 3|DisplayLink|USB GbE|Realtek USB|Ethernet Adapter'
} | Select-Object DeviceName, DriverVersion, @{n='Date';e={$_.DriverDate.ToString('yyyy-MM-dd')}}, DriverProviderName |
    Sort-Object DeviceName | Format-Table -AutoSize | Out-String -Width 300 | Write-Output

Section "THUNDERBOLT SECURITY / DMA PROTECTION"
$tbKeys = 'HKLM:\SYSTEM\CurrentControlSet\Services\ThunderboltService\TbtServiceSettings',
          'HKLM:\SYSTEM\CurrentControlSet\Services\nhi\Parameters'
foreach ($k in $tbKeys) { if (Test-Path $k) { Write-Output "$k"; Get-ItemProperty $k | Format-List | Out-String | Write-Output } }
$svc = Get-Service ThunderboltService
if ($svc) { Write-Output "ThunderboltService: $($svc.Status) / $($svc.StartType)" } else { Write-Output "ThunderboltService: not installed (normal for native USB4/inbox driver)" }
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
Write-Output "DeviceGuard AvailableSecurityProperties: $($dg.AvailableSecurityProperties -join ',')  (7 = Kernel DMA Protection)"
try {
    $msinfo = "$env:TEMP\msinfo_dma.txt"
    Start-Process msinfo32.exe -ArgumentList "/report `"$msinfo`" /categories SystemSummary" -Wait -WindowStyle Hidden
    Select-String -Path $msinfo -Pattern 'Kernel DMA Protection' | ForEach-Object { Write-Output $_.Line.Trim() }
    Remove-Item $msinfo -Force
} catch {}

# ---------- Dock hardware ----------
Section "DOCK-RELATED DEVICES SEEN (present now)"
Get-PnpDevice -PresentOnly | Where-Object {
    $_.FriendlyName -match 'Dock|ThinkPad|Lenovo|DisplayLink|USB GbE|Realtek USB|USB Hub|Billboard|Generic SuperSpeed'
} | Select-Object Status, Class, FriendlyName | Sort-Object Class, FriendlyName |
    Format-Table -AutoSize | Out-String -Width 300 | Write-Output

Section "DOCK-RELATED DEVICES SEEN HISTORICALLY (not present now)"
Get-PnpDevice | Where-Object { -not $_.Present -and $_.FriendlyName -match 'Dock|DisplayLink|USB GbE|Realtek USB|Thunderbolt|USB4' } |
    Select-Object Class, FriendlyName, InstanceId | Sort-Object FriendlyName -Unique |
    Format-Table -AutoSize | Out-String -Width 300 | Write-Output

Section "NETWORK ADAPTERS"
Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, DriverVersion |
    Format-Table -AutoSize | Out-String -Width 300 | Write-Output

# ---------- Display ----------
Section "DISPLAY ADAPTERS & MONITORS"
Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, @{n='DriverDate';e={$_.DriverDate}}, Status |
    Format-Table -AutoSize | Out-String -Width 300 | Write-Output
Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID | ForEach-Object {
    $name = ($_.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join ''
    "Monitor: $name  Active=$($_.Active)"
} | Write-Output

# ---------- Events ----------
Section "RELEVANT EVENTS (last 7 days, Warning/Error)"
$since = (Get-Date).AddDays(-7)
$providers = 'Microsoft-Windows-Kernel-PnP','Microsoft-Windows-USB-USBHUB3','Microsoft-Windows-USB-USBXHCI',
             'Microsoft-Windows-USB-UCMUCSICX','Microsoft-Windows-USB4','nhi','ThunderboltService','Display','DisplayLink','Microsoft-Windows-Kernel-Power'
$ev = Get-WinEvent -FilterHashtable @{ LogName='System'; Level=1,2,3; StartTime=$since } -MaxEvents 3000 |
      Where-Object { $p = $_.ProviderName; $providers | Where-Object { $p -like "*$_*" } } |
      Select-Object -First 40 TimeCreated, ProviderName, Id, @{n='Msg';e={($_.Message -split "`n")[0]}}
if ($ev) { $ev | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Write-Output } else { Write-Output "No matching warnings/errors." }

foreach ($log in 'Microsoft-Windows-Kernel-PnP/Configuration','Microsoft-Windows-USB-UCMUCSICX/Operational') {
    $e2 = Get-WinEvent -FilterHashtable @{ LogName=$log; Level=1,2,3; StartTime=$since } -MaxEvents 20
    if ($e2) { Write-Output "--- $log ---"; $e2 | Select-Object TimeCreated, Id, @{n='Msg';e={($_.Message -split "`n")[0]}} | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Write-Output }
}

# ---------- Recent driver installs ----------
Section "DRIVERS INSTALLED / UPDATED IN LAST 30 DAYS"
$cut = (Get-Date).AddDays(-30)
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Kernel-PnP/Configuration'; Id=400,410,411; StartTime=$cut } -MaxEvents 500 |
    ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated; Id=$_.Id; Msg=($_.Message -split "`n")[0] } } |
    Where-Object { $_.Msg -match 'Thunderbolt|USB4|USB|Display|Graphics|Dock|Ethernet' } |
    Select-Object -First 30 | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Write-Output
Get-WindowsDriver -Online | Where-Object { $_.Date -ge $cut } |
    Select-Object ProviderName, ClassName, Version, Date, OriginalFileName | Format-Table -AutoSize | Out-String -Width 300 | Write-Output

Section "DONE"
exit 0

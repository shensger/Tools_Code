<#
.SYNOPSIS
    Collects performance diagnostics from a slow Windows laptop and writes them to a
    text report you can paste into Claude for analysis.

.DESCRIPTION
    Follows the "Laptop running slow" troubleshooting flow:
      1. Uptime / restart (and Fast Startup)
      2. CPU, memory and disk saturation + top processes
      3. Startup apps, logon tasks and third-party services
      4. Disk free space, disk type/health, cleanable folders
      5. Windows Update / Defender / AV scan activity
    Plus extras that commonly explain slowness: power mode, battery wear, thermals,
    RAM configuration, boot-time degradation, recent system/app errors and
    crashes (bugcheck code + name + likely driver, crash-dump configuration).

    READ-ONLY. Makes no changes to the machine.
    Run as Administrator for complete results (Defender, disk reliability, boot log).
    Also works as SYSTEM (e.g. NinjaOne) - it targets the logged-on user's profile.

.PARAMETER OutputPath
    Folder to write the report to. Default: C:\Temp

.PARAMETER SampleSeconds
    How long to sample live CPU/memory/disk counters. Default: 15

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-SlowPCReport.ps1
    powershell -ExecutionPolicy Bypass -File .\Get-SlowPCReport.ps1 -SampleSeconds 30 -OutputPath "$env:USERPROFILE\Desktop"
#>
[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\Temp',
    [ValidateRange(3, 300)][int]$SampleSeconds = 15
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
$sb    = New-Object System.Text.StringBuilder
$Flags = New-Object System.Collections.ArrayList

function Add-Line    { param([string]$Text = '') [void]$sb.AppendLine($Text) }
function Add-Section { param([string]$Title) Add-Line; Add-Line ('=' * 90); Add-Line "  $Title"; Add-Line ('=' * 90) }
function Add-Sub     { param([string]$Title) Add-Line; Add-Line "--- $Title ---" }
function Add-Flag    { param([string]$Text) Add-Line "  [!] $Text"; [void]$Flags.Add($Text) }
function Add-Table {
    param($Data)
    if ($Data) { Add-Line (($Data | Format-Table -AutoSize -Wrap | Out-String -Width 260).TrimEnd()) }
    else       { Add-Line '  (none / not available)' }
}
function Limit-Text { param([string]$Text, [int]$Max = 120)
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t.Substring(0, $Max) + '...' } else { $t }
}
function Get-FolderSizeGB { param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object Length -Sum).Sum
    [math]::Round(($sum / 1GB), 2)
}
function Invoke-Safe { param([string]$Name, [scriptblock]$Block)
    try { & $Block } catch { Add-Line "  (section '$Name' failed: $($_.Exception.Message))" }
}

# ---------------------------------------------------------------------------
# Context: admin / SYSTEM / target user
# ---------------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem  = $identity.User.Value -eq 'S-1-5-18'

$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS
$logical    = [int]$cs.NumberOfLogicalProcessors
$totalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

# Work out whose profile/registry hive to inspect (matters when run as SYSTEM via RMM)
$profilePath = $env:USERPROFILE
$userHive    = 'HKCU:'
$targetUser  = "$env:USERDOMAIN\$env:USERNAME"
if ($isSystem) {
    $prof = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.Loaded -and $_.LocalPath -like '*\Users\*' } |
            Sort-Object LastUseTime -Descending | Select-Object -First 1
    if ($prof) {
        $profilePath = $prof.LocalPath
        $userHive    = "Registry::HKEY_USERS\$($prof.SID)"
        $targetUser  = if ($cs.UserName) { $cs.UserName } else { $prof.LocalPath }
    }
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile = Join-Path $OutputPath "SlowPC_$($env:COMPUTERNAME)_$stamp.txt"

Write-Host "Collecting diagnostics on $env:COMPUTERNAME (about $($SampleSeconds + 15)-60 seconds)..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 0. SYSTEM
# ---------------------------------------------------------------------------
Invoke-Safe 'System' {
    Add-Section '0. SYSTEM'
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Add-Line "Computer        : $env:COMPUTERNAME"
    Add-Line "Run as          : $($identity.Name)  (Admin: $isAdmin, SYSTEM: $isSystem)"
    Add-Line "Target user     : $targetUser  ($profilePath)"
    Add-Line "Model           : $($cs.Manufacturer) $($cs.Model)"
    Add-Line "BIOS            : $($bios.SMBIOSBIOSVersion)  (released $($bios.ReleaseDate))"
    Add-Line "OS              : $($os.Caption) $($cv.DisplayVersion)  build $($os.BuildNumber).$($cv.UBR)"
    Add-Line "OS installed    : $($os.InstallDate)"
    Add-Line "CPU             : $($cpu.Name.Trim())  ($($cpu.NumberOfCores) cores / $logical threads, max $($cpu.MaxClockSpeed) MHz)"
    Add-Line "RAM             : $totalRAMGB GB"

    $dimms = Get-CimInstance Win32_PhysicalMemory
    if ($dimms) {
        $dimmInfo = $dimms | ForEach-Object { "{0}GB@{1}MHz" -f ([math]::Round($_.Capacity / 1GB)), $_.ConfiguredClockSpeed }
        Add-Line "RAM modules     : $(@($dimms).Count) -> $($dimmInfo -join ', ')"
    }
    if ($totalRAMGB -lt 8) { Add-Flag "Only $totalRAMGB GB RAM - low for modern Windows + browser + Teams/Office." }
}

# ---------------------------------------------------------------------------
# 1. RESTART / UPTIME
# ---------------------------------------------------------------------------
Invoke-Safe 'Uptime' {
    Add-Section '1. RESTARTED IN THE LAST FEW DAYS?'
    $uptime = (Get-Date) - $os.LastBootUpTime
    $hiber  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
    Add-Line "Last boot       : $($os.LastBootUpTime)"
    Add-Line ("Uptime          : {0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
    Add-Line "Fast Startup    : $(if ($hiber -eq 1) { 'Enabled (Shut down does NOT reset uptime - must Restart)' } else { 'Disabled' })"

    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')      { $pending += 'CBS (servicing)' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')     { $pending += 'Windows Update' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations)  { $pending += 'Pending file renames' }
    Add-Line "Pending reboot  : $(if ($pending) { $pending -join ', ' } else { 'No' })"

    if ($uptime.TotalDays -gt 3) { Add-Flag ("Uptime is {0:N1} days - restart before anything else." -f $uptime.TotalDays) }
    if ($pending)               { Add-Flag "Reboot pending ($($pending -join ', '))." }
}

# ---------------------------------------------------------------------------
# 2. CPU / MEMORY / DISK SATURATION
# ---------------------------------------------------------------------------
$procCpuAll = @()
Invoke-Safe 'Utilization' {
    Add-Section "2. IS CPU, MEMORY OR DISK AT 100%?  (sampled over $SampleSeconds s)"
    Write-Host "  Sampling performance counters for $SampleSeconds seconds..."
    $counters = @(
        '\Processor(_Total)\% Processor Time',
        '\Processor Information(_Total)\% Processor Performance',
        '\Memory\Available MBytes',
        '\Memory\% Committed Bytes In Use',
        '\Memory\Pages/sec',
        '\PhysicalDisk(_Total)\% Idle Time',
        '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer',
        '\PhysicalDisk(_Total)\Current Disk Queue Length'
    )
    $samples = Get-Counter -Counter $counters -SampleInterval 1 -MaxSamples $SampleSeconds -ErrorAction SilentlyContinue

    $S = @{}
    foreach ($g in ($samples.CounterSamples | Group-Object { $_.Path -replace '^\\\\[^\\]+', '' })) {
        $m = $g.Group | Measure-Object CookedValue -Average -Maximum -Minimum
        $S[$g.Name] = $m
    }
    function St($k) { $S[$k] }

    $cpuBusy = St '\processor(_total)\% processor time'
    $cpuPerf = St '\processor information(_total)\% processor performance'
    $memAvail = St '\memory\available mbytes'
    $memComm = St '\memory\% committed bytes in use'
    $pages   = St '\memory\pages/sec'
    $dIdle   = St '\physicaldisk(_total)\% idle time'
    $dLat    = St '\physicaldisk(_total)\avg. disk sec/transfer'
    $dQ      = St '\physicaldisk(_total)\current disk queue length'

    $rows = @()
    if ($cpuBusy)  { $rows += [pscustomobject]@{Metric='CPU busy %';                     Avg=[math]::Round($cpuBusy.Average,1);  Peak=[math]::Round($cpuBusy.Maximum,1)} }
    if ($cpuPerf)  { $rows += [pscustomobject]@{Metric='CPU speed % of base (<60 = throttled/power-saving)'; Avg=[math]::Round($cpuPerf.Average,1); Peak=[math]::Round($cpuPerf.Maximum,1)} }
    if ($memAvail) { $rows += [pscustomobject]@{Metric='Memory available MB (Peak = lowest)'; Avg=[math]::Round($memAvail.Average); Peak=[math]::Round($memAvail.Minimum)} }
    if ($memComm)  { $rows += [pscustomobject]@{Metric='Memory committed %';             Avg=[math]::Round($memComm.Average,1);  Peak=[math]::Round($memComm.Maximum,1)} }
    if ($pages)    { $rows += [pscustomobject]@{Metric='Hard page faults/sec';           Avg=[math]::Round($pages.Average);      Peak=[math]::Round($pages.Maximum)} }
    if ($dIdle)    { $rows += [pscustomobject]@{Metric='Disk busy %';                    Avg=[math]::Round(100 - $dIdle.Average,1); Peak=[math]::Round(100 - $dIdle.Minimum,1)} }
    if ($dLat)     { $rows += [pscustomobject]@{Metric='Disk latency ms (>20 slow, >50 bad)'; Avg=[math]::Round($dLat.Average * 1000,1); Peak=[math]::Round($dLat.Maximum * 1000,1)} }
    if ($dQ)       { $rows += [pscustomobject]@{Metric='Disk queue length';              Avg=[math]::Round($dQ.Average,2);       Peak=[math]::Round($dQ.Maximum,2)} }
    Add-Table $rows

    if ($cpuBusy  -and $cpuBusy.Average -gt 80) { Add-Flag ("CPU averaged {0:N0}% busy during sampling." -f $cpuBusy.Average) }
    if ($memComm  -and $memComm.Average -gt 85) { Add-Flag ("Memory commit at {0:N0}% - likely paging to disk." -f $memComm.Average) }
    if ($memAvail -and $memAvail.Minimum -lt ($cs.TotalPhysicalMemory / 1MB * 0.10)) { Add-Flag ("Available RAM dropped to {0:N0} MB (<10% of total)." -f $memAvail.Minimum) }
    if ($dIdle    -and (100 - $dIdle.Average) -gt 70) { Add-Flag ("Disk averaged {0:N0}% busy." -f (100 - $dIdle.Average)) }
    if ($dLat     -and ($dLat.Average * 1000) -gt 50) { Add-Flag ("Disk latency averaged {0:N0} ms - very slow storage response." -f ($dLat.Average * 1000)) }
    if ($cpuPerf -and $cpuBusy -and $cpuPerf.Average -lt 60 -and $cpuBusy.Average -gt 25) {
        Add-Flag ("CPU running at {0:N0}% of base speed while busy - thermal/power throttling or power-saving mode." -f $cpuPerf.Average)
    }

    # Per-process CPU and disk I/O (aggregated by process name, e.g. all chrome.exe instances together)
    Write-Host "  Sampling per-process CPU and disk I/O..."
    $procSamples = Get-Counter '\Process(*)\% Processor Time', '\Process(*)\IO Data Bytes/sec' -SampleInterval 1 -MaxSamples 3 -ErrorAction SilentlyContinue
    $n = [math]::Max(@($procSamples).Count, 1)
    $all = $procSamples.CounterSamples | Where-Object { $_.InstanceName -notin '_total', 'idle' }

    $script:procCpuAll = $all | Where-Object { $_.Path -like '*\% processor time' } |
        Group-Object { $_.InstanceName -replace '#\d+$', '' } | ForEach-Object {
            [pscustomobject]@{ Process = $_.Name; CPU_Pct = [math]::Round((($_.Group | Measure-Object CookedValue -Sum).Sum / $n) / $logical, 1) }
        } | Sort-Object CPU_Pct -Descending

    $procIo = $all | Where-Object { $_.Path -like '*\io data bytes/sec' } |
        Group-Object { $_.InstanceName -replace '#\d+$', '' } | ForEach-Object {
            [pscustomobject]@{ Process = $_.Name; IO_MBps = [math]::Round((($_.Group | Measure-Object CookedValue -Sum).Sum / $n) / 1MB, 2) }
        } | Sort-Object IO_MBps -Descending | Select-Object -First 12

    Add-Sub 'Top processes by CPU (% of total CPU)'
    Add-Table ($script:procCpuAll | Select-Object -First 15)

    Add-Sub 'Top processes by memory'
    $memTop = Get-Process | Group-Object ProcessName | ForEach-Object {
        [pscustomobject]@{
            Process    = $_.Name
            Count      = $_.Count
            Private_MB = [math]::Round((($_.Group | Measure-Object PrivateMemorySize64 -Sum).Sum) / 1MB)
            WorkSet_MB = [math]::Round((($_.Group | Measure-Object WorkingSet64 -Sum).Sum) / 1MB)
        }
    } | Sort-Object Private_MB -Descending | Select-Object -First 15
    Add-Table $memTop

    Add-Sub 'Top processes by disk/IO (MB/s)'
    Add-Table $procIo

    $procs = Get-Process
    Add-Line ("Total processes: {0}   Total handles: {1:N0}   Total threads: {2:N0}" -f @($procs).Count, ($procs | Measure-Object HandleCount -Sum).Sum, ($procs | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum)

    $pf = Get-CimInstance Win32_PageFileUsage
    if ($pf) { Add-Line ("Page file: {0} - allocated {1} MB, current use {2} MB, peak {3} MB" -f $pf.Name, $pf.AllocatedBaseSize, $pf.CurrentUsage, $pf.PeakUsage) }
}

# ---------------------------------------------------------------------------
# 3. STARTUP APPS
# ---------------------------------------------------------------------------
Invoke-Safe 'Startup' {
    Add-Section '3. LOTS OF APPS STARTING WITH WINDOWS?'
    # StartupApproved: first byte odd = disabled in Task Manager
    $approvedKeys = @(
        "$userHive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        "$userHive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        "$userHive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    )
    $disabled = @{}
    foreach ($k in $approvedKeys) {
        $item = Get-Item -Path $k -ErrorAction SilentlyContinue
        if ($item) {
            foreach ($v in $item.GetValueNames()) {
                $b = $item.GetValue($v)
                if ($b -is [byte[]] -and $b.Length -gt 0 -and ($b[0] -band 1)) { $disabled[$v] = $true }
            }
        }
    }

    $startup = Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $isOff = $disabled[$_.Name] -or $disabled[$_.Command] -or $disabled["$($_.Name).lnk"]
        [pscustomobject]@{
            State    = if ($isOff) { 'Disabled' } else { 'Enabled' }
            Name     = $_.Name
            Location = $_.Location
            User     = $_.User
            Command  = Limit-Text $_.Command 110
        }
    } | Sort-Object State, Name
    $enabledCount = @($startup | Where-Object State -eq 'Enabled').Count
    Add-Line "Startup items: $(@($startup).Count) total, $enabledCount enabled"
    Add-Table $startup
    if ($enabledCount -gt 10) { Add-Flag "$enabledCount startup apps enabled - trim in Task Manager > Startup apps." }

    Add-Sub 'Non-Microsoft scheduled tasks that run at logon/boot'
    $tasks = Get-ScheduledTask | Where-Object {
        $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and
        ($_.Triggers | Where-Object { $_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger' })
    } | ForEach-Object {
        [pscustomobject]@{ Task = $_.TaskName; Path = $_.TaskPath; Runs = Limit-Text (($_.Actions | ForEach-Object { $_.Execute }) -join '; ') 100 }
    }
    Add-Table $tasks

    Add-Sub 'Running third-party services (security agents, updaters, OEM bloat)'
    $svc3p = Get-CimInstance Win32_Service | Where-Object {
        $_.State -eq 'Running' -and $_.PathName -and
        $_.PathName -notmatch '\\Windows\\(System32|SysWOW64|servicing|Microsoft\.NET|WinSxS)\\' -and
        $_.PathName -notmatch 'svchost\.exe'
    } | Sort-Object DisplayName | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; DisplayName = Limit-Text $_.DisplayName 50; Path = Limit-Text ($_.PathName -replace '"', '') 90 }
    }
    Add-Line "Count: $(@($svc3p).Count)"
    Add-Table $svc3p
}

# ---------------------------------------------------------------------------
# 4. DISK SPACE / DISK HEALTH
# ---------------------------------------------------------------------------
Invoke-Safe 'Disk' {
    Add-Section '4. IS THE DISK ALMOST FULL?  (plus disk type & health)'
    $vols = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [pscustomobject]@{
            Drive   = $_.DeviceID
            Label   = $_.VolumeName
            Size_GB = [math]::Round($_.Size / 1GB, 1)
            Free_GB = [math]::Round($_.FreeSpace / 1GB, 1)
            Free_Pct = if ($_.Size) { [math]::Round($_.FreeSpace / $_.Size * 100, 1) } else { 0 }
        }
    }
    Add-Table $vols
    $sysVol = $vols | Where-Object Drive -eq $env:SystemDrive
    if ($sysVol -and ($sysVol.Free_Pct -lt 10 -or $sysVol.Free_GB -lt 15)) {
        Add-Flag "System drive $($sysVol.Drive) has only $($sysVol.Free_GB) GB ($($sysVol.Free_Pct)%) free."
    }

    Add-Sub 'Physical disks'
    $sysDiskNum = (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | Get-Disk).Number
    $pd = Get-PhysicalDisk | ForEach-Object {
        [pscustomobject]@{
            Id          = $_.DeviceId
            Name        = $_.FriendlyName
            Media       = $_.MediaType
            Bus         = $_.BusType
            Size_GB     = [math]::Round($_.Size / 1GB)
            Health      = $_.HealthStatus
            Operational = ($_.OperationalStatus -join ',')
            SystemDisk  = ([string]$_.DeviceId -eq [string]$sysDiskNum)
        }
    }
    Add-Table $pd
    foreach ($d in $pd) {
        if ($d.SystemDisk -and $d.Media -eq 'HDD') { Add-Flag "Windows is on a spinning hard drive ($($d.Name)) - an SSD upgrade is the single biggest speed fix." }
        if ($d.Health -and $d.Health -ne 'Healthy') { Add-Flag "Disk '$($d.Name)' health = $($d.Health)." }
    }

    if ($isAdmin) {
        Add-Sub 'Disk reliability counters'
        $rel = Get-PhysicalDisk | ForEach-Object {
            $r = $_ | Get-StorageReliabilityCounter
            [pscustomobject]@{
                Disk          = $_.FriendlyName
                Wear_Pct      = $r.Wear
                Temp_C        = $r.Temperature
                ReadErrUncorr = $r.ReadErrorsUncorrected
                WriteErrUncorr= $r.WriteErrorsUncorrected
                PowerOnHours  = $r.PowerOnHours
            }
        }
        Add-Table $rel
        foreach ($r in $rel) {
            if ($r.Wear -ge 80)            { Add-Flag "Disk '$($r.Disk)' wear is $($r.Wear)%." }
            if ($r.ReadErrUncorr -gt 0)    { Add-Flag "Disk '$($r.Disk)' has $($r.ReadErrUncorr) uncorrected read errors - possible failing drive." }
        }
    }

    Add-Sub 'Cleanable / large folders (GB)'
    Write-Host "  Measuring folder sizes..."
    $folders = [ordered]@{
        'User Downloads'                  = Join-Path $profilePath 'Downloads'
        'User Temp'                       = Join-Path $profilePath 'AppData\Local\Temp'
        'Windows Temp'                    = "$env:SystemRoot\Temp"
        'Recycle Bin (all users)'         = "$env:SystemDrive\`$Recycle.Bin"
        'Windows Update download cache'   = "$env:SystemRoot\SoftwareDistribution\Download"
        'Windows.old'                     = "$env:SystemDrive\Windows.old"
    }
    $fRows = foreach ($k in $folders.Keys) { [pscustomobject]@{ Folder = $k; Size_GB = Get-FolderSizeGB $folders[$k]; Path = $folders[$k] } }
    Add-Table $fRows
    foreach ($f in @('pagefile.sys', 'hiberfil.sys', 'swapfile.sys')) {
        $i = Get-Item -LiteralPath "$env:SystemDrive\$f" -Force
        if ($i) { Add-Line ("{0,-14}: {1:N1} GB" -f $f, ($i.Length / 1GB)) }
    }
}

# ---------------------------------------------------------------------------
# 5. UPDATES / SCANS
# ---------------------------------------------------------------------------
Invoke-Safe 'Updates' {
    Add-Section '5. IS AN UPDATE OR A SCAN RUNNING?'
    $watch = 'TiWorker', 'TrustedInstaller', 'wuauclt', 'MoUsoCoreWorker', 'usocoreworker', 'MsMpEng', 'MpCmdRun',
             'MpDefenderCoreService', 'NisSrv', 'SearchIndexer', 'SearchProtocolHost', 'CompatTelRunner', 'DismHost',
             'OneDrive', 'msiexec', 'WmiPrvSE', 'svchost', 'CSFalconService', 'bdservicehost', 'epsecurityservice',
             'ir_agent', 'SentinelAgent', 'NinjaRMMAgent', 'ninjarmm-agent'
    $active = $procCpuAll | Where-Object { $watch -contains $_.Process }
    Add-Sub 'Update / scan / indexing / agent processes (CPU % during sample)'
    Add-Table $active
    foreach ($a in $active) {
        if ($a.CPU_Pct -ge 10 -and $a.Process -ne 'svchost') { Add-Flag "$($a.Process) using $($a.CPU_Pct)% CPU - update, scan or indexing in progress." }
    }

    Add-Sub 'Antivirus products registered (Security Center)'
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
          Select-Object displayName, @{n='ProductState'; e={ '0x{0:X6}' -f $_.productState }}, pathToSignedReportingExe
    Add-Table $av
    if (@($av).Count -gt 1) { Add-Line '  Note: more than one AV registered - check two real-time engines are not both active.' }

    Add-Sub 'Microsoft Defender'
    $mp = Get-MpComputerStatus
    if ($mp) {
        Add-Line "Running mode         : $($mp.AMRunningMode)"
        Add-Line "Real-time protection : $($mp.RealTimeProtectionEnabled)"
        Add-Line "Signatures updated   : $($mp.AntivirusSignatureLastUpdated)"
        Add-Line "Quick scan start/end : $($mp.QuickScanStartTime)  ->  $($mp.QuickScanEndTime)"
        Add-Line "Full scan start/end  : $($mp.FullScanStartTime)  ->  $($mp.FullScanEndTime)"
        $pref = Get-MpPreference
        if ($pref) { Add-Line "Scan CPU limit       : $($pref.ScanAvgCPULoadFactor)%   Scheduled scan day: $($pref.ScanScheduleDay)  time: $($pref.ScanScheduleTime)" }
        if ($mp.QuickScanStartTime -and (-not $mp.QuickScanEndTime -or $mp.QuickScanStartTime -gt $mp.QuickScanEndTime)) { Add-Flag 'Defender quick scan appears to be running now.' }
        if ($mp.FullScanStartTime  -and (-not $mp.FullScanEndTime  -or $mp.FullScanStartTime  -gt $mp.FullScanEndTime))  { Add-Flag 'Defender full scan appears to be running now.' }
    } else {
        Add-Line '  (Defender status unavailable - not admin, or third-party AV has replaced it)'
    }

    Add-Sub 'Most recent installed updates'
    Add-Table (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 6 HotFixID, Description, InstalledOn)

    Add-Sub 'Windows Update activity (last 3 days)'
    $wu = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; StartTime = (Get-Date).AddDays(-3) } -MaxEvents 15 |
          Select-Object TimeCreated, Id, @{n='Message'; e={ Limit-Text $_.Message 130 }}
    Add-Table $wu

    if ($isAdmin) {
        Add-Sub 'Active BITS transfers (background downloads)'
        Add-Table (Get-BitsTransfer -AllUsers | Select-Object DisplayName, JobState, @{n='MB_Done'; e={ [math]::Round($_.BytesTransferred / 1MB) }}, @{n='MB_Total'; e={ [math]::Round($_.BytesTotal / 1MB) }})
    }
}

# ---------------------------------------------------------------------------
# 6. POWER / BATTERY / THERMALS
# ---------------------------------------------------------------------------
Invoke-Safe 'Power' {
    Add-Section '6. POWER, BATTERY & THERMALS'
    Add-Line "Power plan      : $((powercfg /getactivescheme) -join ' ')"
    $pk = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
    $overlay = @{
        '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency'
        '00000000-0000-0000-0000-000000000000' = 'Balanced'
        '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Better performance'
        'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance'
    }
    $acMode = if ($pk.ActiveOverlayAcPowerScheme) { $overlay[$pk.ActiveOverlayAcPowerScheme] } else { 'Balanced (default)' }
    $dcMode = if ($pk.ActiveOverlayDcPowerScheme) { $overlay[$pk.ActiveOverlayDcPowerScheme] } else { 'Balanced (default)' }
    Add-Line "Power mode (AC) : $acMode"
    Add-Line "Power mode (DC) : $dcMode"

    $batt = Get-CimInstance Win32_Battery | Select-Object -First 1
    if ($batt) {
        $onBattery = $batt.BatteryStatus -eq 1
        Add-Line "Power source    : $(if ($onBattery) { 'BATTERY' } else { 'AC adapter' })   Charge: $($batt.EstimatedChargeRemaining)%"
        $full   = (Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity | Select-Object -First 1).FullChargedCapacity
        $design = (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData        | Select-Object -First 1).DesignedCapacity
        if ($full -and $design) {
            $health = [math]::Round($full / $design * 100, 1)
            Add-Line "Battery health  : $health% of design capacity ($full / $design mWh)"
            if ($health -lt 60) { Add-Flag "Battery at $health% of design capacity - some OEMs (Dell/HP/Lenovo) throttle the CPU with a worn battery." }
        }
        if ($onBattery) { Add-Flag 'Laptop was on battery during the test - performance is often limited on battery.' }
        if (($onBattery -and $dcMode -eq 'Best power efficiency') -or (-not $onBattery -and $acMode -eq 'Best power efficiency')) {
            Add-Flag "Power mode is 'Best power efficiency' - CPU is deliberately limited."
        }
    } else {
        Add-Line 'Battery         : none detected'
    }

    $tz = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature
    if ($tz) {
        Add-Sub 'ACPI thermal zones (not always the CPU core; some OEMs report fixed values)'
        $tzRows = $tz | ForEach-Object { [pscustomobject]@{ Zone = ($_.InstanceName -split '\\')[-1]; Temp_C = [math]::Round($_.CurrentTemperature / 10 - 273.15, 1) } }
        Add-Table $tzRows
        foreach ($t in $tzRows) { if ($t.Temp_C -ge 90) { Add-Flag "Thermal zone $($t.Zone) at $($t.Temp_C) C - overheating/throttling likely (vents, fan, dust)." } }
    }
}

# ---------------------------------------------------------------------------
# 7. BOOT PERFORMANCE & ERRORS
# ---------------------------------------------------------------------------
Invoke-Safe 'Events' {
    Add-Section '7. BOOT PERFORMANCE & RECENT ERRORS (last 7 days)'
    $since = (Get-Date).AddDays(-7)

    $boots = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 5
    if ($boots) {
        Add-Sub 'Recent boot durations'
        $bRows = $boots | ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}; foreach ($e in $x.Event.EventData.Data) { $d[$e.Name] = $e.'#text' }
            [pscustomobject]@{ Time = $_.TimeCreated; Boot_s = [math]::Round([int]$d['BootTime'] / 1000, 1); MainPath_s = [math]::Round([int]$d['MainPathBootTime'] / 1000, 1); PostBoot_s = [math]::Round([int]$d['BootPostBootTime'] / 1000, 1) }
        }
        Add-Table $bRows
    }
    $degr = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101..110; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 15
    if ($degr) {
        Add-Sub 'Boot/shutdown degradation culprits (last 30 days)'
        Add-Table ($degr | Select-Object TimeCreated, Id, @{n='Message'; e={ Limit-Text $_.Message 160 }})
    }

    foreach ($log in 'System', 'Application') {
        Add-Sub "$log log - errors/criticals grouped"
        $ev = Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 1, 2; StartTime = $since } -MaxEvents 3000
        $grp = $ev | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
            $f = $_.Group | Select-Object -First 1
            [pscustomobject]@{ Count = $_.Count; Last = $f.TimeCreated; Source = $f.ProviderName; Id = $f.Id; Sample = Limit-Text $f.Message 110 }
        }
        Add-Table $grp

        if ($log -eq 'System') {
            $kp   = @($ev | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 }).Count
            # volmgr is excluded on purpose: its errors (45/46/161) are crash-dump failures, not drive faults
            $disk = @($ev | Where-Object { $_.ProviderName -match '^(disk|stornvme|storahci|Ntfs|Microsoft-Windows-Ntfs)$' }).Count
            $dumpFail = @($ev | Where-Object { $_.ProviderName -eq 'volmgr' -and $_.Id -in 45, 46, 161 }).Count
            $whea = @($ev | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WHEA-Logger' }).Count
            $rex  = @($ev | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Resource-Exhaustion-Detector' }).Count
            if ($kp)   { Add-Flag "$kp unexpected shutdown(s) (Kernel-Power 41) in 7 days." }
            if ($disk) { Add-Flag "$disk disk/storage/NTFS error event(s) in 7 days - check drive health." }
            if ($dumpFail) { Add-Flag "$dumpFail crash dump(s) failed to write (volmgr) in 7 days - no dump to analyze; check dump settings below." }
            if ($whea) { Add-Flag "$whea WHEA hardware error event(s) in 7 days." }
            if ($rex)  { Add-Flag "$rex low-virtual-memory (Resource-Exhaustion) event(s) in 7 days." }
        }
        if ($log -eq 'Application') {
            $hangs = @($ev | Where-Object { $_.ProviderName -eq 'Application Hang' }).Count
            if ($hangs -ge 5) { Add-Flag "$hangs application hang events in 7 days." }
        }
    }
}

# ---------------------------------------------------------------------------
# 8. CRASHES (BUGCHECKS) & DUMP CONFIG
# ---------------------------------------------------------------------------
Invoke-Safe 'Crashes' {
    Add-Section '8. CRASHES / BLUE SCREENS (last 30 days)'
    $bcNames = @{
        '0x0000000A' = 'IRQL_NOT_LESS_OR_EQUAL (driver)';             '0x0000001E' = 'KMODE_EXCEPTION_NOT_HANDLED (driver)'
        '0x0000003B' = 'SYSTEM_SERVICE_EXCEPTION (driver/GPU)';       '0x00000050' = 'PAGE_FAULT_IN_NONPAGED_AREA (driver/RAM)'
        '0x0000007E' = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (driver)'; '0x0000007F' = 'UNEXPECTED_KERNEL_MODE_TRAP (hardware/driver)'
        '0x0000009F' = 'DRIVER_POWER_STATE_FAILURE (sleep/dock/USB)'; '0x000000D1' = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL (driver, often network)'
        '0x000000EF' = 'CRITICAL_PROCESS_DIED';                        '0x00000101' = 'CLOCK_WATCHDOG_TIMEOUT (CPU/firmware)'
        '0x00000116' = 'VIDEO_TDR_FAILURE (GPU driver)';               '0x00000117' = 'VIDEO_TDR_TIMEOUT_DETECTED (GPU driver)'
        '0x00000124' = 'WHEA_UNCORRECTABLE_ERROR (hardware: CPU/RAM/heat)'; '0x00000133' = 'DPC_WATCHDOG_VIOLATION (driver hogging CPU: NVMe firmware/storage, GPU, USB4/dock)'
        '0x00000139' = 'KERNEL_SECURITY_CHECK_FAILURE (driver/RAM)';  '0x0000013A' = 'KERNEL_MODE_HEAP_CORRUPTION (driver)'
        '0x00000154' = 'UNEXPECTED_STORE_EXCEPTION (storage/RAM)';    '0x0000015F' = 'CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP'
        '0x000001A8' = 'BUGCODE_NDIS_DRIVER_LIVE_DUMP (network)';     '0x00000193' = 'VIDEO_DXGKRNL_LIVEDUMP (GPU)'
    }
    $wer = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50
    $crashes = foreach ($e in ($wer | Where-Object Id -eq 1001)) {
        $code = if ($e.Message -match 'bugcheck was:\s*(0x[0-9a-fA-F]+)') { '0x{0:X8}' -f [Convert]::ToUInt32($matches[1], 16) } else { '?' }
        $parm = if ($e.Message -match 'bugcheck was:\s*0x[0-9a-fA-F]+\s*\(([^)]*)\)') { $matches[1] } else { '' }
        [pscustomobject]@{ Time = $e.TimeCreated; Code = $code; Name = $bcNames[$code]; Params = Limit-Text $parm 90 }
    }
    $drivers = foreach ($e in ($wer | Where-Object Id -eq 1019)) {
        if ($e.Message -match 'related driver:\s*(\S+?)\.?\s*$') { $matches[1] }
    }
    Add-Table $crashes
    if ($drivers) { Add-Line "Possibly related driver(s) reported by Windows: $(($drivers | Sort-Object -Unique) -join ', ')  (ntoskrnl.exe = Windows couldn't identify the driver)" }

    foreach ($g in ($crashes | Group-Object Code)) {
        $nm = $bcNames[$g.Name]; if (-not $nm) { $nm = 'see Microsoft bug check reference' }
        $drv = ($drivers | Where-Object { $_ -ne 'ntoskrnl.exe' } | Sort-Object -Unique) -join ', '
        Add-Flag ("{0} crash(es) with bugcheck {1} {2}{3}" -f $g.Count, $g.Name, $nm, $(if ($drv) { " - possibly related driver: $drv" } else { '' }))
    }

    Add-Sub 'Crash dump configuration'
    $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $dumpType = @{ 0 = 'None'; 1 = 'Complete'; 2 = 'Kernel'; 3 = 'Small (minidump)'; 7 = 'Automatic' }[[int]$cc.CrashDumpEnabled]
    Add-Line "Dump type       : $dumpType ($($cc.CrashDumpEnabled))"
    Add-Line "Dump file       : $($cc.DumpFile)   Minidump dir: $($cc.MinidumpDir)"
    Add-Line "Overwrite       : $($cc.Overwrite)   AlwaysKeepMemoryDump: $($cc.AlwaysKeepMemoryDump)   DedicatedDumpFile: $($cc.DedicatedDumpFile)"
    $mini = Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    $mem  = Get-Item "$env:SystemRoot\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
    Add-Line "Minidumps       : $(@($mini).Count)$(if ($mini) { "  (newest $($mini[0].Name) $($mini[0].LastWriteTime))" })"
    Add-Line "MEMORY.DMP      : $(if ($mem) { '{0:N1} GB, {1}' -f ($mem.Length / 1GB), $mem.LastWriteTime } else { 'none' })"
    if ($crashes -and -not $mini) { Add-Line '  Note: crashes recorded but no minidumps on disk - set Startup and Recovery > Small memory dump so the next crash can be analyzed.' }
}

# ---------------------------------------------------------------------------
# Write report: header + quick flags + detail
# ---------------------------------------------------------------------------
$header = New-Object System.Text.StringBuilder
[void]$header.AppendLine('SLOW PC DIAGNOSTIC REPORT')
[void]$header.AppendLine("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   Computer: $env:COMPUTERNAME   Sample window: $SampleSeconds s")
[void]$header.AppendLine('Prompt    : Analyze this report and tell me the most likely reasons this laptop is slow, in priority order, with the fix for each.')
[void]$header.AppendLine()
[void]$header.AppendLine('QUICK FLAGS (automatic threshold checks)')
[void]$header.AppendLine('-' * 90)
if ($Flags.Count) { foreach ($f in $Flags) { [void]$header.AppendLine("  [!] $f") } }
else              { [void]$header.AppendLine('  No thresholds tripped - see detail below. Re-run while the slowness is actually happening.') }
if (-not $isAdmin) { [void]$header.AppendLine('  (Not run as Administrator - some sections are incomplete.)') }

($header.ToString() + $sb.ToString()) | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host ''
Write-Host "Report saved: $reportFile" -ForegroundColor Green
Write-Host "Flags found : $($Flags.Count)" -ForegroundColor $(if ($Flags.Count) { 'Yellow' } else { 'Green' })
if (-not $isSystem) {
    try { Get-Content -LiteralPath $reportFile -Raw | Set-Clipboard; Write-Host 'Report copied to clipboard - paste it straight into Claude.' -ForegroundColor Cyan } catch {}
}

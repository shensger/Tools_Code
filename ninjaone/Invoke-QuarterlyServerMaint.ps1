<#
.SYNOPSIS
    Quarterly server maintenance: runs the checklist tasks, collects metrics, and records the
    results in the client's "Quarterly Site & Systems Maintenance Schedule" workbook.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1) but also runs interactively on
    the server. One worksheet per server; the sheet is picked by -SheetName (defaults to the
    computer name, e.g. HAC-FS02 / HAC-RDS / HAC-VEEAM).

    Rows are matched by their label text in column B, not by row number, so it works across
    sheets with different layouts. A new column is filled in to the right of the last date
    (or today's column is overwritten if the script already ran today). Formatting is copied
    from the previous column.

    Checklist row               -> What the script does / writes
    --------------------------------------------------------------------------------------
    O/S and Applications        -> Collects OS build, uptime, stopped auto services, critical
                                   System events (7d). Writes X; details go in the notes row.
    AntiVirus & Definitions     -> Detects Bitdefender/Defender/CrowdStrike/SentinelOne;
                                   updates Defender signatures if Defender is active.
                                   X = AV running (and Defender defs <= 3 days), else CHECK.
    Update device drivers       -> Not automated (left blank for the tech).
    Disk space - <L>:           -> Free GB on that drive (number, 1 decimal).
    Free memory                 -> Free RAM in GB.
    Available memory            -> Free RAM as a fraction (0.241 = 24.1%).
    Memory utilization          -> Used RAM as a fraction.
    CPU utilization             -> 30-second average, as a fraction.
    Boot, Rescue or ERD disk    -> Not automated (left blank for the tech).
    Delete old .zip/.chk/.tmp   -> Deletes files older than N days in Windows\Temp and each
                                   profile's Temp, plus chkdsk *.chk in found.### folders.
                                   Does NOT touch .zip files on data volumes. Writes X.
    Browser history & tmp files -> Clears IE/Edge/Chrome/Firefox cache (not history) older than
                                   N days for every profile. Writes X.
    Scandisk & Defrag           -> Repair-Volume -Scan (online, read-only) on NTFS volumes;
                                   Optimize-Volume only with -RunDiskOptimize. X or ERR.
    Run Windows Update          -> Counts pending updates (does not install; Ninja patching
                                   does that). X if none pending, otherwise "N pending".
    Reboot System               -> "No Need" or "Pending" (never reboots the server).
    Other/Notes row 1           -> One-line summary (OS, uptime, updates, cleanup, AV).

    A JSON copy of every run is always saved to C:\ProgramData\Netrique\Maint\, so nothing is
    lost if the workbook is locked (open in Excel) or unreachable.

.PARAMETER WorkbookPath
    Full path to the .xlsx. Use a UNC path when run from Ninja. SYSTEM uses the computer
    account (e.g. HAC-RDS$), which needs Modify rights on the share and the folder.
    Ninja script variable: workbookPath

.PARAMETER TechInitials
    Written in the initials row above the checklist. Ninja variable: techInitials (default AUTO).

.PARAMETER SheetName
    Worksheet to update. Defaults to $env:COMPUTERNAME. Ninja variable: sheetName

.PARAMETER GraphSheet
    Optional. Name of a drive-history sheet (rows like "C-Drive: 505GB", dates in row 1) to
    append free-GB values to. Ninja variable: graphSheet

.PARAMETER RunDiskOptimize
    Also run Optimize-Volume (defrag on HDD / retrim on SSD). Heavy I/O, so use it after hours.
    Ninja checkbox: runDiskOptimize

.PARAMETER CleanupAgeDays
    Age threshold for temp/cache deletion. Default 7. Ninja variable: cleanupAgeDays

.PARAMETER DryRun
    Collect and print only. No cleanup, no signature update, no workbook write.
    Ninja checkbox: dryRun

.EXAMPLE
    .\Invoke-QuarterlyServerMaint.ps1 -WorkbookPath '\\HAC-FS02\IT$\Maint\HAC-Maint.xlsx' -TechInitials MJ

.NOTES
    Requires the ImportExcel module (installed automatically from PSGallery if missing).
    Excel does not need to be installed. A timestamped backup of the workbook is made before
    every save.
#>
[CmdletBinding()]
param(
    [string]$WorkbookPath   = $env:workbookPath,
    [string]$TechInitials   = $env:techInitials,
    [string]$SheetName      = $env:sheetName,
    [string]$GraphSheet     = $env:graphSheet,
    [switch]$RunDiskOptimize,
    [int]$CleanupAgeDays    = 0,
    [switch]$DryRun,
    # Internal/testing: skip collection and write these results (JSON file) to the workbook.
    [string]$ResultsJson
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ---- Ninja script variables arrive as env vars; checkboxes come in as "true"/"false" -------
if ($env:runDiskOptimize -eq 'true') { $RunDiskOptimize = $true }
if ($env:dryRun -eq 'true')          { $DryRun = $true }
if ($CleanupAgeDays -le 0) {
    $CleanupAgeDays = 7
    if ($env:cleanupAgeDays -match '^\d+$') { $CleanupAgeDays = [int]$env:cleanupAgeDays }
}
if ([string]::IsNullOrWhiteSpace($TechInitials)) { $TechInitials = 'AUTO' }
if ([string]::IsNullOrWhiteSpace($SheetName))    { $SheetName = $env:COMPUTERNAME }

if ($env:ProgramData) { $LogDir = Join-Path $env:ProgramData 'Netrique\Maint' }
else { $LogDir = Join-Path ([IO.Path]::GetTempPath()) 'Netrique-Maint' }

function Write-Log([string]$Msg) { Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg) }

#region ---------------------------- Collection / maintenance ----------------------------

function Get-CpuFraction {
    param([int]$Samples = 30)
    try {
        $s = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples $Samples -ErrorAction Stop).CounterSamples.CookedValue
        return [math]::Round((($s | Measure-Object -Average).Average) / 100, 3)
    } catch {
        # Localized OS or perf counters broken: fall back to WMI, sampled a few times.
        $vals = 1..10 | ForEach-Object {
            (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
            Start-Sleep -Seconds 1
        }
        return [math]::Round((($vals | Measure-Object -Average).Average) / 100, 3)
    }
}

function Get-MemoryInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $totalGB = $os.TotalVisibleMemorySize / 1MB
    $freeGB  = $os.FreePhysicalMemory / 1MB
    [pscustomobject]@{
        TotalGB      = [math]::Round($totalGB, 1)
        FreeGB       = [math]::Round($freeGB, 1)
        FreeFraction = [math]::Round($freeGB / $totalGB, 3)
        UsedFraction = [math]::Round(1 - ($freeGB / $totalGB), 3)
    }
}

function Get-DiskInfo {
    $h = @{}
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        $l = $_.DeviceID.Substring(0, 1).ToUpper()
        $h[$l] = [pscustomobject]@{
            Letter = $l
            SizeGB = [math]::Round($_.Size / 1GB, 1)
            FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
            FileSystem = $_.FileSystem
        }
    }
    $h
}

function Get-OsSummary {
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    $stopped = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" |
        Where-Object { $_.Name -notmatch '^(gupdate|edgeupdate|MapsBroker|sppsvc|RemoteRegistry|CDPSvc|tiledatamodelsvc|WbioSrvc|GoogleUpdater.*|MicrosoftEdgeElevationService|clr_optimization.*|TrustedInstaller|ShellHWDetection|BITS|wuauserv|UsoSvc|dmwappushservice)' } |
        Select-Object -ExpandProperty Name)
    $crit = 0
    try {
        $crit = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = (Get-Date).AddDays(-7) } -ErrorAction Stop).Count
    } catch { $crit = 0 }   # "No events found" throws
    [pscustomobject]@{
        Caption        = $os.Caption -replace 'Microsoft ', ''
        Build          = $os.Version
        UptimeDays     = [math]::Round($uptime.TotalDays, 1)
        LastBoot       = $os.LastBootUpTime
        StoppedAutoSvc = $stopped
        SysErrors7d    = $crit
    }
}

function Get-AvStatus {
    param([switch]$UpdateDefender)
    $found = @()
    $svcMap = [ordered]@{
        'Bitdefender' = 'EPSecurityService'
        'CrowdStrike' = 'CSFalconService'
        'SentinelOne' = 'SentinelAgent'
        'Sophos'      = 'Sophos Endpoint Defense Service'
    }
    foreach ($k in $svcMap.Keys) {
        $s = Get-Service -Name $svcMap[$k] -ErrorAction SilentlyContinue
        if ($s) { $found += [pscustomobject]@{ Product = $k; Running = ($s.Status -eq 'Running'); DefAgeDays = $null } }
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AntivirusEnabled -and $mp.AMRunningMode -notmatch 'Passive') {
            if ($UpdateDefender) {
                try { Update-MpSignature -ErrorAction Stop; $mp = Get-MpComputerStatus } catch { }
            }
            $found += [pscustomobject]@{ Product = 'Defender'; Running = [bool]$mp.RealTimeProtectionEnabled; DefAgeDays = $mp.AntivirusSignatureAge }
        }
    } catch { }   # Defender not installed / passive

    $ok = $false
    foreach ($f in $found) {
        if ($f.Running -and ($null -eq $f.DefAgeDays -or $f.DefAgeDays -le 3)) { $ok = $true }
    }
    $desc = ($found | ForEach-Object {
        $t = $_.Product + $(if ($_.Running) { '' } else { '(STOPPED)' })
        if ($null -ne $_.DefAgeDays) { $t += " defs $($_.DefAgeDays)d" }
        $t
    }) -join ', '
    if (-not $desc) { $desc = 'none detected' }
    [pscustomobject]@{ Ok = $ok; Summary = $desc }
}

function Get-WindowsUpdateStatus {
    $r = [pscustomobject]@{ Pending = $null; Titles = @(); LastInstall = $null; Error = $null }
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $srch = $sess.CreateUpdateSearcher()
        $res  = $srch.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $r.Pending = $res.Updates.Count
        $r.Titles  = @(for ($i = 0; $i -lt [math]::Min($res.Updates.Count, 5); $i++) { $res.Updates.Item($i).Title })
        $n = $srch.GetTotalHistoryCount()
        if ($n -gt 0) {
            $hist = $srch.QueryHistory(0, [math]::Min($n, 50)) | Where-Object { $_.ResultCode -eq 2 -and $_.Operation -eq 1 }
            $r.LastInstall = ($hist | Sort-Object Date -Descending | Select-Object -First 1).Date
        }
    } catch { $r.Error = $_.Exception.Message }
    if (-not $r.LastInstall) {
        try { $r.LastInstall = (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn } catch { }
    }
    $r
}

function Get-PendingRebootReasons {
    $why = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $why += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $why += 'WindowsUpdate' }
    try {
        $cn  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
        $pcn = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
        if ($cn -ne $pcn) { $why += 'Rename' }
    } catch { }
    try {
        $ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($ccm.RebootPending -or $ccm.IsHardRebootPending) { $why += 'ConfigMgr' }
    } catch { }
    # PendingFileRenameOperations is deliberately ignored: AV and installers set it constantly.
    $why
}

function Remove-OldFiles {
    param([string[]]$Paths, [datetime]$Cutoff, [string[]]$Include = @('*'))
    $bytes = 0; $count = 0
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        Get-ChildItem -LiteralPath $p -Recurse -Force -File -Include $Include -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Cutoff -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
            ForEach-Object {
                $len = $_.Length
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; $bytes += $len; $count++ } catch { }  # in use: skip
            }
    }
    [pscustomobject]@{ Files = $count; MB = [math]::Round($bytes / 1MB, 1) }
}

function Get-ProfilePaths {
    Get-CimInstance Win32_UserProfile -Filter 'Special=False' -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) } |
        Select-Object -ExpandProperty LocalPath
}

function Invoke-TempCleanup {
    param([int]$AgeDays)
    $cut = (Get-Date).AddDays(-$AgeDays)
    $paths = @("$env:windir\Temp")
    foreach ($pp in Get-ProfilePaths) { $paths += (Join-Path $pp 'AppData\Local\Temp') }
    $a = Remove-OldFiles -Paths $paths -Cutoff $cut

    # chkdsk leftovers (found.000\*.chk) in fixed-volume roots
    $chkDirs = foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
        Get-ChildItem -LiteralPath ($d.DeviceID + '\') -Directory -Force -Filter 'found.*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    $b = Remove-OldFiles -Paths @($chkDirs) -Cutoff $cut -Include '*.chk'
    [pscustomobject]@{ Files = $a.Files + $b.Files; MB = $a.MB + $b.MB }
}

function Invoke-BrowserCacheCleanup {
    param([int]$AgeDays)
    $cut = (Get-Date).AddDays(-$AgeDays)
    $rel = @(
        'AppData\Local\Microsoft\Windows\INetCache',
        'AppData\Local\Microsoft\Windows\Temporary Internet Files',
        'AppData\Local\Microsoft\Edge\User Data\*\Cache',
        'AppData\Local\Microsoft\Edge\User Data\*\Code Cache',
        'AppData\Local\Google\Chrome\User Data\*\Cache',
        'AppData\Local\Google\Chrome\User Data\*\Code Cache',
        'AppData\Local\Mozilla\Firefox\Profiles\*\cache2'
    )
    $paths = foreach ($pp in Get-ProfilePaths) {
        foreach ($r in $rel) {
            Resolve-Path -Path (Join-Path $pp $r) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProviderPath
        }
    }
    Remove-OldFiles -Paths @($paths) -Cutoff $cut
}

function Invoke-DiskCheck {
    param([switch]$Optimize)
    $out = @()
    $vols = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' }
    foreach ($v in $vols) {
        $scan = 'n/a'
        try { $scan = [string](Repair-Volume -DriveLetter $v.DriveLetter -Scan -ErrorAction Stop) } catch { $scan = 'ScanFailed' }
        $opt = ''
        if ($Optimize) {
            try { Optimize-Volume -DriveLetter $v.DriveLetter -ErrorAction Stop; $opt = 'optimized' } catch { $opt = 'optimize failed' }
        }
        $out += [pscustomobject]@{ Drive = $v.DriveLetter; Scan = $scan; Optimize = $opt }
    }
    $out
}

function Invoke-Collection {
    Write-Log "Collecting on $env:COMPUTERNAME (DryRun=$DryRun, Optimize=$RunDiskOptimize, CleanupAge=$CleanupAgeDays d)"
    $os   = Get-OsSummary;              Write-Log "OS: $($os.Caption) $($os.Build), up $($os.UptimeDays)d"
    $av   = Get-AvStatus -UpdateDefender:(-not $DryRun); Write-Log "AV: $($av.Summary)"

    $tmp = [pscustomobject]@{ Files = 0; MB = 0 }; $brw = [pscustomobject]@{ Files = 0; MB = 0 }; $dsk = @()
    if (-not $DryRun) {
        $tmp = Invoke-TempCleanup -AgeDays $CleanupAgeDays;         Write-Log "Temp cleanup: $($tmp.Files) files, $($tmp.MB) MB"
        $brw = Invoke-BrowserCacheCleanup -AgeDays $CleanupAgeDays; Write-Log "Browser cache: $($brw.Files) files, $($brw.MB) MB"
        $dsk = Invoke-DiskCheck -Optimize:$RunDiskOptimize
        $dsk | ForEach-Object { Write-Log "Volume $($_.Drive): scan=$($_.Scan) $($_.Optimize)" }
    }

    # Measure after cleanup so disk numbers reflect the post-maintenance state
    $disks = Get-DiskInfo
    $disks.Values | Sort-Object Letter | ForEach-Object { Write-Log "Disk $($_.Letter): $($_.FreeGB) GB free of $($_.SizeGB) GB" }
    $mem  = Get-MemoryInfo;   Write-Log "Memory: $($mem.FreeGB) GB free of $($mem.TotalGB) GB (used $([math]::Round($mem.UsedFraction*100,1))%)"
    Write-Log 'Sampling CPU for 30 seconds...'
    $cpu  = Get-CpuFraction;  Write-Log "CPU avg: $([math]::Round($cpu*100,1))%"
    Write-Log 'Checking Windows Update (can take a few minutes)...'
    $wu   = Get-WindowsUpdateStatus
    Write-Log ("Windows Update: pending={0} lastInstall={1} {2}" -f $wu.Pending, $wu.LastInstall, $wu.Error)
    $rb   = @(Get-PendingRebootReasons); Write-Log ("Pending reboot: " + $(if ($rb.Count) { $rb -join ',' } else { 'no' }))

    # ---- Build cell values --------------------------------------------------------------
    $scanBad = @($dsk | Where-Object { $_.Scan -ne 'NoErrorsFound' })
    $wuCell = if ($null -eq $wu.Pending) { 'WU ERR' } elseif ($wu.Pending -eq 0) { 'X' } else { "$($wu.Pending) pending" }

    $noteParts = @(
        "$($os.Caption) $($os.Build)",
        "up $($os.UptimeDays)d",
        "AV: $($av.Summary)",
        $(if ($null -ne $wu.Pending) { "WU pending $($wu.Pending)" } else { "WU check failed" }),
        $(if ($wu.LastInstall) { "last patch {0:M/d/yy}" -f [datetime]$wu.LastInstall }),
        $(if (-not $DryRun) { "cleaned $([math]::Round($tmp.MB + $brw.MB,0)) MB" }),
        $(if ($os.SysErrors7d) { "$($os.SysErrors7d) sys errors/7d" }),
        $(if ($os.StoppedAutoSvc.Count) { "stopped auto svc: " + ($os.StoppedAutoSvc -join ',') }),
        $(if ($scanBad.Count) { "disk scan issues: " + (($scanBad | ForEach-Object { "$($_.Drive):$($_.Scan)" }) -join ',') }),
        $(if ($rb.Count) { "reboot pending ($($rb -join ','))" })
    ) | Where-Object { $_ }

    [ordered]@{
        Computer     = $env:COMPUTERNAME
        Date         = (Get-Date).ToString('yyyy-MM-dd')
        Initials     = $TechInitials
        DryRun       = [bool]$DryRun
        Disks        = @($disks.Values | Sort-Object Letter | ForEach-Object { [ordered]@{ Letter = $_.Letter; FreeGB = $_.FreeGB; SizeGB = $_.SizeGB } })
        Memory       = $mem
        Cpu          = $cpu
        Cells        = [ordered]@{
            OsApps      = 'X'
            AntiVirus   = $(if ($av.Ok) { 'X' } else { 'CHECK' })
            Cleanup     = $(if ($DryRun) { $null } else { 'X' })
            Browser     = $(if ($DryRun) { $null } else { 'X' })
            ScanDefrag  = $(if ($DryRun) { $null } elseif ($scanBad.Count) { 'ERR' } else { 'X' })
            WinUpdate   = $wuCell
            Reboot      = $(if ($rb.Count) { 'Pending' } else { 'No Need' })
        }
        Note         = ($noteParts -join '; ')
    }
}
#endregion

#region ---------------------------- Workbook update -------------------------------------

function Initialize-ImportExcel {
    if (Get-Module -ListAvailable -Name ImportExcel) { Import-Module ImportExcel; return }
    Write-Log 'Installing ImportExcel module from PSGallery...'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
    }
    Install-Module -Name ImportExcel -Scope AllUsers -Force -AllowClobber
    Import-Module ImportExcel
}

function Wait-FileUnlocked {
    param([string]$Path, [int]$Tries = 12)
    for ($i = 1; $i -le $Tries; $i++) {
        try { $fs = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None'); $fs.Close(); return $true }
        catch { Write-Log "Workbook locked (open in Excel or another server is writing), retry $i/$Tries"; Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 25) }
    }
    $false
}

function Get-CellText($ws, [int]$r, [int]$c) {
    $v = $ws.Cells[$r, $c].Value
    if ($null -eq $v) { return '' }
    ([string]$v).Trim()
}

function Find-Row($ws, [string]$Pattern, [int]$Col = 2) {
    $maxR = $ws.Dimension.End.Row
    for ($r = 1; $r -le $maxR; $r++) {
        if ((Get-CellText $ws $r $Col) -match $Pattern) { return $r }
    }
    0
}

function Set-Cell($ws, [int]$r, [int]$c, $Value) {
    if ($null -eq $Value -or $r -le 0) { return }
    if ($c -gt 3) { $ws.Cells[$r, $c].StyleID = $ws.Cells[$r, ($c - 1)].StyleID }   # copy format from previous column
    $ws.Cells[$r, $c].Value = $Value
}

function Update-MaintSheet($ws, $Res) {
    $dateRow = Find-Row $ws '^Date:'
    if (-not $dateRow) { throw "Sheet '$($ws.Name)' has no 'Date:' row in column B." }
    $initRow = $dateRow + 1
    $today = [datetime]::ParseExact($Res.Date, 'yyyy-MM-dd', $null)

    # Pick the column: reuse today's if it already exists, else first empty date cell from C
    $col = 3
    while ($true) {
        $v = $ws.Cells[$dateRow, $col].Value
        if ($null -eq $v -or [string]$v -eq '') { break }
        $d = $null
        if ($v -is [datetime]) { $d = $v } elseif ($v -is [double]) { $d = [datetime]::FromOADate($v) }
        if ($d -and $d.Date -eq $today.Date) { break }
        $col++
    }
    $colLetter = [OfficeOpenXml.ExcelCellAddress]::GetColumnLetter($col)
    Write-Log "Sheet '$($ws.Name)': writing column $colLetter (date row $dateRow)"

    Set-Cell $ws $dateRow $col $today
    $ws.Cells[$dateRow, $col].Style.Numberformat.Format = 'm/d/yy;@'
    Set-Cell $ws $initRow $col $Res.Initials

    $c = $Res.Cells
    $map = [ordered]@{
        'O/S and Applications'      = $c.OsApps
        'AntiVirus'                 = $c.AntiVirus
        '^Delete old'               = $c.Cleanup
        'browser history'           = $c.Browser
        'Scandisk|Defrag'           = $c.ScanDefrag
        'Run Windows Update'        = $c.WinUpdate
        '^Reboot'                   = $c.Reboot
        'free memory'               = $Res.Memory.FreeGB
        'available memory'          = $Res.Memory.FreeFraction
        'memory utilization'        = $Res.Memory.UsedFraction
        'CPU utilization'           = $Res.Cpu
    }
    foreach ($k in $map.Keys) {
        $row = Find-Row $ws $k
        if ($row) { Set-Cell $ws $row $col $map[$k] }
    }

    # Disk rows: "Check & evaluate available disk space - C:  249 GB"
    $maxR = $ws.Dimension.End.Row
    for ($r = 1; $r -le $maxR; $r++) {
        $t = Get-CellText $ws $r 2
        if ($t -match 'disk space\s*-\s*([A-Z]):') {
            $L = $Matches[1]
            $disk = $Res.Disks | Where-Object { $_.Letter -eq $L }
            if ($disk) { Set-Cell $ws $r $col ([double]$disk.FreeGB) }
            else { Write-Log "  Drive ${L}: on sheet but not found on this server" }
        }
    }

    # Notes: first numbered line under "Other/Notes:"
    $notesHdr = Find-Row $ws '^Other/Notes'
    if ($notesHdr -and $Res.Note) {
        $ws.Cells[($notesHdr + 1), $col].Value = ("{0:M/d}: {1}" -f $today, $Res.Note)
    }
}

function Update-GraphSheet($ws, $Res) {
    $today = [datetime]::ParseExact($Res.Date, 'yyyy-MM-dd', $null)
    $col = 2
    while ($true) {
        $v = $ws.Cells[1, $col].Value
        if ($null -eq $v -or [string]$v -eq '') { break }
        $d = $null
        if ($v -is [datetime]) { $d = $v } elseif ($v -is [double]) { $d = [datetime]::FromOADate($v) }
        if ($d -and $d.Date -eq $today.Date) { break }
        $col++
    }
    Set-Cell $ws 1 $col $today
    $maxR = $ws.Dimension.End.Row
    for ($r = 2; $r -le $maxR; $r++) {
        if ((Get-CellText $ws $r 1) -match '^([A-Z])-Drive') {
            $disk = $Res.Disks | Where-Object { $_.Letter -eq $Matches[1] }
            if ($disk) { Set-Cell $ws $r $col ([double]$disk.FreeGB) }
        }
    }
    Write-Log "Graph sheet '$($ws.Name)': appended column $([OfficeOpenXml.ExcelCellAddress]::GetColumnLetter($col))"
}

function Update-Workbook($Res) {
    if (-not (Test-Path -LiteralPath $WorkbookPath)) { throw "Workbook not found or not reachable as $(whoami): $WorkbookPath" }
    Initialize-ImportExcel
    if (-not (Wait-FileUnlocked $WorkbookPath)) { throw 'Workbook stayed locked; results saved to JSON only.' }

    # Backup next to the workbook (keeps the last 10)
    $dir  = Split-Path -Parent $WorkbookPath
    $bdir = Join-Path $dir '_backup'
    if (-not (Test-Path $bdir)) { New-Item -ItemType Directory -Path $bdir | Out-Null }
    $base = [IO.Path]::GetFileNameWithoutExtension($WorkbookPath)
    Copy-Item -LiteralPath $WorkbookPath -Destination (Join-Path $bdir ("{0}_{1:yyyyMMdd-HHmmss}_{2}.xlsx" -f $base, (Get-Date), $Res.Computer))
    Get-ChildItem $bdir -Filter "${base}_*.xlsx" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 10 | Remove-Item -Force -ErrorAction SilentlyContinue

    $pkg = Open-ExcelPackage -Path $WorkbookPath
    try {
        $ws = $pkg.Workbook.Worksheets | Where-Object { $_.Name -eq $SheetName } | Select-Object -First 1
        if (-not $ws) {
            throw ("No sheet named '$SheetName'. Sheets: " + (($pkg.Workbook.Worksheets | ForEach-Object Name) -join ', '))
        }
        Update-MaintSheet $ws $Res
        if ($GraphSheet) {
            $g = $pkg.Workbook.Worksheets | Where-Object { $_.Name -eq $GraphSheet } | Select-Object -First 1
            if ($g) { Update-GraphSheet $g $Res } else { Write-Log "Graph sheet '$GraphSheet' not found, skipped." }
        }
        Close-ExcelPackage $pkg
        Write-Log "Saved $WorkbookPath"
    } catch {
        Close-ExcelPackage $pkg -NoSave
        throw
    }
}
#endregion

# ------------------------------------- Main ----------------------------------------------
$exit = 0
try {
    if ($ResultsJson) {
        $Res = Get-Content -Raw $ResultsJson | ConvertFrom-Json
    } else {
        $Res = [pscustomobject](Invoke-Collection)
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        $json = Join-Path $LogDir ("{0}_{1}.json" -f $Res.Computer, $Res.Date)
        $Res | ConvertTo-Json -Depth 5 | Set-Content -Path $json -Encoding UTF8
        Write-Log "Results saved: $json"
    }
    Write-Log "Notes: $($Res.Note)"

    if ($DryRun) {
        Write-Log 'DryRun: workbook not modified.'
    } elseif ([string]::IsNullOrWhiteSpace($WorkbookPath)) {
        Write-Log 'No workbookPath set: results recorded in JSON only.'
    } else {
        Update-Workbook $Res
    }
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    $exit = 1
}
exit $exit

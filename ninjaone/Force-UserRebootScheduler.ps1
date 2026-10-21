<#
.SYNOPSIS
    NinjaOne Reboot Manager - prompts the signed-in user to restart now or schedule a restart.
    Postponements re-display the prompt after RepromptDelayMinutes; after
    DeferralLimit postponements the restart becomes mandatory.
    Companion scripts: Invoke-NinjaOneUptimeRebootManager.ps1 (excessive uptime),
    Invoke-NinjaOneFailedPatchRebootManager.ps1 (failed patches, same-day).

.DESCRIPTION
    Designed to run from NinjaOne as SYSTEM. Trigger it from any condition or
    automation (e.g. the built-in reboot pending condition, post-patching, or ad hoc).

    Architecture (v2 - persistent prompt):
      1. Main script (this file, SYSTEM, exits within seconds):
         - Handles deferral state, builds schedule options, writes all support
           files, launches the prompt in the user's session, registers the
           response processor task, then exits. NinjaOne never waits on the user.
      2. Prompt (user session, launched via wscript shim so no console appears):
         - Normal mode: prominent idle timer. No selection within
           IdleAutoScheduleMinutes auto-schedules a restart for 15 minutes
           before the end of the working day. Closing the window auto-schedules
           a restart CloseAutoScheduleMinutes later. Remind me later postpones;
           the prompt returns after RepromptDelayMinutes (self-scheduled).
         - Force mode (postponement limit reached): no postpone button;
           countdown timer; no selection auto-schedules a restart.
         - Every automatically scheduled restart is confirmed to the user in
           an on-screen notice showing the exact time.
      3. Response processor (SYSTEM scheduled task, runs every minute for up to 14 days):
         - Acts on the user's choice: restart now, register the scheduled
           restart, or record the postponement. Cleans up and removes itself.
      4. Queued reboot wrapper (SYSTEM, runs at the scheduled time):
         - Skips the restart if a genuine boot (not a Fast Startup power-on)
           has already occurred since it was scheduled.

    Escalation model:
      - Every prompt self-resolves within IdleAutoScheduleMinutes: the user
        restarts, schedules, postpones, or a restart is scheduled for them.
      - Each postponement brings the prompt back after RepromptDelayMinutes;
        after DeferralLimit postponements the restart becomes mandatory.
      - If a restart is already scheduled and pending, this script exits
        without prompting again. Any genuine restart resets the counter.

    Deferral state: HKLM:\SOFTWARE\NinjaOne\RebootManager (resets after a genuine restart).
    Log file: C:\ProgramData\NinjaOne\RebootManager\reboot_manager.log
    Optional NinjaOne text custom field: rebootPromptStatus

.NOTES
    Run as: SYSTEM (set on BOTH the script library entry and the automation)
    Tested on: Windows 10/11, Windows PowerShell 5.1
#>

param(
    # Postponements allowed before the restart becomes mandatory
    [int]$DeferralLimit = 3,

    # Minutes after a postponement before the prompt is displayed again
    # (the script schedules its own re-run - no further trigger needed)
    [int]$RepromptDelayMinutes = 10,

    # FORCE MODE ONLY: minutes the prompt stays open before auto-scheduling
    [int]$ForcePopupTimeoutMinutes = 15,

    # In force mode, the furthest ahead a user may schedule (hours)
    [int]$ForceWindowHours = 4,

    # In force mode with no response, restart this many minutes from now (window-clamped)
    [int]$ForcedFallbackMinutes = 60,

    # If the prompt is closed without a selection, a restart is automatically
    # scheduled this many minutes later (window-clamped) and a notice window
    # confirms the time to the user
    [int]$CloseAutoScheduleMinutes = 60,

    # If the prompt is left open with no selection for this many minutes, a
    # restart is automatically scheduled for 15 minutes before the end of the
    # working day (rolling to tomorrow if that has already passed). 0 disables.
    [int]$IdleAutoScheduleMinutes = 15,

    # Restart immediately if nobody is signed in
    [bool]$RebootIfNoUser = $true,

    # Scheduled restarts are only offered between these times (24h 'HH:mm')
    [string]$ScheduleWindowStart = '09:00',
    [string]$ScheduleWindowEnd   = '17:00',

    # After showing the prompt, wait up to this long to report the user's
    # choice in the script output (NinjaOne activity log). If the user has
    # not responded by then, the script exits and the outcome is recorded in
    # rebootPromptStatus and the device log instead. Keep this comfortably
    # below the NinjaOne script timeout.
    [int]$OutputWaitMinutes = 5
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Guard: must run as SYSTEM (or at minimum elevated)
# ---------------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: This script is running as '$($identity.Name)' without elevation."
    Write-Output "It must run as SYSTEM. In NinjaOne, set 'Run As' to System on the script"
    Write-Output "AND on the automation that triggers it, then run it again."
    exit 1
}

# ---------------------------------------------------------------------------
# Constants and paths
# ---------------------------------------------------------------------------
$WorkDir           = 'C:\ProgramData\NinjaOne\RebootManager'
$UserDropDir       = Join-Path $WorkDir 'user'
$PopupScript       = Join-Path $WorkDir 'Show-RebootPopup.ps1'
$LauncherVbs       = Join-Path $WorkDir 'launch_popup.vbs'
$ConfigFile        = Join-Path $WorkDir 'config.json'
$ResponseFile      = Join-Path $UserDropDir 'response.json'
$PidFile           = Join-Path $UserDropDir 'popup.pid'
$ProcessorScript   = Join-Path $WorkDir 'Invoke-ResponseProcessor.ps1'
$ProcessorConfig   = Join-Path $WorkDir 'processor_config.json'
$RebootWrapper     = Join-Path $WorkDir 'Invoke-QueuedReboot.ps1'
$LogFile           = Join-Path $WorkDir 'reboot_manager.log'
$RegPath           = 'HKLM:\SOFTWARE\NinjaOne\RebootManager'
$PopupTaskName     = 'NinjaOne Reboot Prompt'
$RebootTaskName    = 'NinjaOne Scheduled Reboot'
$ProcessorTaskName = 'NinjaOne Reboot Response Processor'
$RepromptTaskName  = 'NinjaOne Reboot Re-prompt'

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Output $line
    try { Add-Content -Path $LogFile -Value $line } catch { }
}

function Set-NinjaField {
    param([string]$Value)
    try {
        if (Get-Command 'Ninja-Property-Set' -ErrorAction SilentlyContinue) {
            Ninja-Property-Set rebootPromptStatus $Value | Out-Null
        }
    } catch { }
}

# ---------------------------------------------------------------------------
# Working directory security model:
#   - $WorkDir holds scripts executed as SYSTEM. It is locked to
#     SYSTEM/Administrators (full) and Users (read-only) so a standard user
#     can never modify anything SYSTEM will execute.
#   - $UserDropDir is the ONLY user-writable location, holding just the
#     prompt's response.json and popup.pid.
# ---------------------------------------------------------------------------
if (-not (Test-Path $WorkDir))     { New-Item -Path $WorkDir     -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $UserDropDir)) { New-Item -Path $UserDropDir -ItemType Directory -Force | Out-Null }

function Set-LockedAcl {
    param([string]$Path, [string]$UsersRights)
    $a = Get-Acl $Path
    $a.SetAccessRuleProtection($true, $false)   # discard inherited rules
    foreach ($existing in @($a.Access)) { [void]$a.RemoveAccessRule($existing) }
    foreach ($id in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
        $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Users', $UsersRights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    try { $a.SetOwner([System.Security.Principal.NTAccount]'BUILTIN\Administrators') } catch { }
    Set-Acl -Path $Path -AclObject $a
}

Set-LockedAcl -Path $WorkDir     -UsersRights 'ReadAndExecute'
Set-LockedAcl -Path $UserDropDir -UsersRights 'Modify'

# ---------------------------------------------------------------------------
# Boot time. LastBootUpTime is only reset by a genuine boot - Fast Startup
# power-ons do NOT reset it.
# ---------------------------------------------------------------------------
$lastBoot   = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime


# ---------------------------------------------------------------------------
# Keep a copy of this script so re-prompt tasks have a stable path to run
# (NinjaOne executes from a temporary path that will not exist later)
# ---------------------------------------------------------------------------
$SelfCopy = Join-Path $WorkDir 'NinjaOne-Reboot-Manager.ps1'
try {
    if ($PSCommandPath -and ($PSCommandPath -ne $SelfCopy)) {
        Copy-Item -Path $PSCommandPath -Destination $SelfCopy -Force
    }
} catch { }

# ---------------------------------------------------------------------------
# If a restart is already scheduled and pending, do not prompt again
# ---------------------------------------------------------------------------
$existingReboot = Get-ScheduledTask -TaskName $RebootTaskName -ErrorAction SilentlyContinue
if ($existingReboot) {
    $info = $existingReboot | Get-ScheduledTaskInfo
    Write-Log ("A restart is already scheduled (next run: {0}). Exiting without prompting." -f $info.NextRunTime)
    Set-NinjaField ("Restart already scheduled for {0:dd/MM HH:mm}" -f $info.NextRunTime)
    exit 0
}

# ---------------------------------------------------------------------------
# Deferral state - reset if the device has genuinely restarted since
# ---------------------------------------------------------------------------
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }

$deferralCount = 0
try { $deferralCount = [int](Get-ItemProperty -Path $RegPath -Name DeferralCount -ErrorAction Stop).DeferralCount } catch { }

try {
    $lastDeferral = [datetime](Get-ItemProperty -Path $RegPath -Name LastDeferralTime -ErrorAction Stop).LastDeferralTime
    if ($lastBoot -gt $lastDeferral) {
        $deferralCount = 0
        Set-ItemProperty -Path $RegPath -Name DeferralCount -Value 0
        Write-Log 'Device has restarted since the last postponement - counter reset.'
    }
} catch { }

# ---------------------------------------------------------------------------
# Detect an unanswered prompt from a previous run
# ---------------------------------------------------------------------------
$staleProcessor = Get-ScheduledTask -TaskName $ProcessorTaskName -ErrorAction SilentlyContinue
if ($staleProcessor) {
    $lastPrompt = $null
    try { $lastPrompt = [datetime](Get-ItemProperty -Path $RegPath -Name LastPromptTime -ErrorAction Stop).LastPromptTime } catch { }

    if (Test-Path $ResponseFile) {
        Write-Log 'Previous prompt was answered but not yet processed - response will be superseded. Not counted as a postponement.'
    } elseif ($lastPrompt -and ($lastBoot -gt $lastPrompt)) {
        Write-Log 'Previous prompt predates the last genuine restart - not counted as a postponement.'
    } else {
        $deferralCount++
        Set-ItemProperty -Path $RegPath -Name DeferralCount -Value $deferralCount
        Set-ItemProperty -Path $RegPath -Name LastDeferralTime -Value (Get-Date).ToString('o')
        Write-Log "Previous prompt was never answered - counted as postponement $deferralCount of $DeferralLimit."
        Set-NinjaField ("Unanswered prompt - postponement {0}/{1}" -f $deferralCount, $DeferralLimit)
    }

    # Close any stale prompt window still on screen
    if (Test-Path $PidFile) {
        try {
            $stalePid  = [int](Get-Content $PidFile -Raw).Trim()
            $staleProc = Get-Process -Id $stalePid -ErrorAction SilentlyContinue
            # Only ever kill a PowerShell process - the PID file is
            # user-writable and must not become an arbitrary-kill primitive
            if ($staleProc -and $staleProc.ProcessName -like 'powershell*') {
                $staleProc | Stop-Process -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

# Clean up all prompt-cycle artefacts from any previous run
foreach ($t in @($PopupTaskName, $ProcessorTaskName, $RepromptTaskName)) {
    Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-Item $ResponseFile, $ConfigFile, $PidFile -Force -ErrorAction SilentlyContinue

$forceMode = ($deferralCount -ge $DeferralLimit)
Write-Log "Postponements used: $deferralCount of $DeferralLimit. Force mode: $forceMode"

# ---------------------------------------------------------------------------
# Mode-specific wording
# ---------------------------------------------------------------------------
$NormalHeadline  = 'Restart required to complete updates'
$NormalBody      = 'This device must be restarted to complete the installation of important updates.'
$ShutdownMessage = 'This device is restarting to complete the installation of updates. Please save your work now.'
Set-Content -Path (Join-Path $WorkDir 'reboot_message.txt') -Value $ShutdownMessage -Encoding UTF8

# ---------------------------------------------------------------------------
# Is anyone signed in?
# ---------------------------------------------------------------------------
$loggedOnUser = $null
try {
    $explorer = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue |
                Select-Object -First 1
    if ($explorer) {
        $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner
        if ($owner.ReturnValue -eq 0) { $loggedOnUser = "$($owner.Domain)\$($owner.User)" }
    }
} catch { }

if (-not $loggedOnUser) {
    if ($RebootIfNoUser) {
        Write-Log 'No interactive user signed in - restarting immediately.'
        Set-NinjaField ("Restarted (no user signed in) {0:dd/MM HH:mm}" -f (Get-Date))
        shutdown.exe /r /f /t 60 /c "$ShutdownMessage"
        exit 0
    } else {
        Write-Log 'No interactive user signed in and RebootIfNoUser is false - exiting.'
        Set-NinjaField 'Skipped - no user signed in'
        exit 0
    }
}
Write-Log "Signed-in user: $loggedOnUser"

# ---------------------------------------------------------------------------
# Build the schedule options (restricted to the schedule window)
# ---------------------------------------------------------------------------
$winStart = $null; $winEnd = $null
try {
    $winStart = [TimeSpan]::Parse($ScheduleWindowStart)
    $winEnd   = [TimeSpan]::Parse($ScheduleWindowEnd)
} catch { }
if (-not $winStart -or -not $winEnd -or
    $winStart -lt [TimeSpan]::Zero -or $winEnd -ge [TimeSpan]::FromDays(1) -or
    $winStart -ge $winEnd) {
    Write-Log "WARNING: Invalid schedule window ('$ScheduleWindowStart' - '$ScheduleWindowEnd'). Use 24h 'HH:mm' format. Falling back to 09:00-17:00."
    $winStart = [TimeSpan]::FromHours(9)
    $winEnd   = [TimeSpan]::FromHours(17)
}

function Test-InWindow([datetime]$Time) {
    ($Time.TimeOfDay -ge $winStart) -and ($Time.TimeOfDay -le $winEnd)
}
function Get-NextWindowTime([datetime]$Time) {
    if (Test-InWindow $Time) { return $Time }
    if ($Time.TimeOfDay -lt $winStart) { return $Time.Date.Add($winStart) }
    return $Time.Date.AddDays(1).Add($winStart)
}

$now = Get-Date
$options = New-Object System.Collections.Generic.List[object]

function Add-Option([datetime]$Time, [string]$Label) {
    if ($Time -le $now.AddMinutes(10)) { return }
    if (-not (Test-InWindow $Time)) { return }
    if ($forceMode -and $Time -gt $now.AddHours($ForceWindowHours)) { return }
    if ($options | Where-Object { $_.time -eq $Time.ToString('o') }) { return }
    $options.Add(@{ label = $Label; time = $Time.ToString('o') })
}

Add-Option $now.AddHours(1) 'In 1 hour'
Add-Option $now.AddHours(2) 'In 2 hours'
Add-Option $now.AddHours(4) 'In 4 hours'

# Fixed slots every 2 hours from the start of the schedule window, plus the
# window end itself, offered for today and again for tomorrow. Past and
# out-of-window times are filtered by Add-Option automatically.
foreach ($dayOffset in 0, 1) {
    $day    = (Get-Date).Date.AddDays($dayOffset)
    $prefix = if ($dayOffset -eq 0) { 'Today' } else { 'Tomorrow' }
    for ($ts = $winStart; $ts -le $winEnd; $ts = $ts.Add([TimeSpan]::FromHours(2))) {
        $slotTime = $day.Add($ts)
        Add-Option $slotTime ('{0} at {1:HH:mm}' -f $prefix, $slotTime)
    }
    $endSlot = $day.Add($winEnd)
    Add-Option $endSlot ('{0} at {1:HH:mm}' -f $prefix, $endSlot)
}

if ($options.Count -eq 0) {
    $fallback = Get-NextWindowTime $now.AddMinutes(30)
    $options.Add(@{
        label = ('{0:dddd} at {0:HH:mm}' -f $fallback)
        time  = $fallback.ToString('o')
    })
}

# ---------------------------------------------------------------------------
# Prompt configuration
# ---------------------------------------------------------------------------
@{
    forceMode      = $forceMode
    allowDefer     = (-not $forceMode)
    timeoutMinutes = $ForcePopupTimeoutMinutes
    deferralsUsed  = $deferralCount
    deferralLimit  = $DeferralLimit
    options        = $options
    responseFile   = $ResponseFile
    pidFile        = $PidFile
    headline       = $NormalHeadline
    bodyText       = $NormalBody
    closeAutoMinutes = $CloseAutoScheduleMinutes
    idleMinutes      = $IdleAutoScheduleMinutes
    repromptMinutes  = $RepromptDelayMinutes
    windowStartMinutes = [int]$winStart.TotalMinutes
    windowEndMinutes   = [int]$winEnd.TotalMinutes
} | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigFile -Encoding UTF8

# ---------------------------------------------------------------------------
# Prompt script (runs in the user's session)
# ---------------------------------------------------------------------------
$popupContent = @'
# NinjaOne Reboot Manager - user prompt. Launched in the interactive session.
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$workDir      = 'C:\ProgramData\NinjaOne\RebootManager'
$config       = Get-Content (Join-Path $workDir 'config.json') -Raw | ConvertFrom-Json
$responseFile = $config.responseFile

# Record our PID so a later run can close a stale prompt
try { $PID | Set-Content -Path $config.pidFile -Encoding ASCII } catch { }

function Write-Response($obj) {
    $obj | ConvertTo-Json | Set-Content -Path $responseFile -Encoding UTF8
}

$deferVisibility = if ($config.allowDefer) { 'Visible' } else { 'Collapsed' }
$headline = if ($config.forceMode) {
    'Restart required'
} else {
    $config.headline
}
$bodyText = if ($config.forceMode) {
    'The postponement limit for this restart has been reached.'
} else {
    $config.bodyText
}

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NinjaOne Reboot Manager - Restart required"
        Width="460" SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        Topmost="True" ResizeMode="NoResize" WindowStyle="ToolWindow"
        FontFamily="Arial" FontSize="13" Background="#FFFFFF">
  <StackPanel Margin="24">
    <Grid Margin="0,0,0,4">
      <TextBlock x:Name="Headline" FontSize="18" FontWeight="Bold" Foreground="#1F2937" TextWrapping="Wrap" VerticalAlignment="Center"/>
    </Grid>
    <TextBlock x:Name="Body" Margin="0,10,0,14" TextWrapping="Wrap" Foreground="#333333"/>
    <Border x:Name="TimerPanel" Background="#FDF3E7" BorderBrush="#E4A34E" BorderThickness="1" CornerRadius="4" Padding="12" Margin="0,0,0,14" Visibility="Collapsed">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="TimerDigits" FontSize="32" FontWeight="Bold" Foreground="#D97706" VerticalAlignment="Center" Margin="2,0,16,0"/>
        <TextBlock x:Name="TimerInfo" Grid.Column="1" TextWrapping="Wrap" Foreground="#5A4632" FontSize="12" VerticalAlignment="Center"/>
      </Grid>
    </Border>
    <TextBlock Text="Scheduled restart time:" FontWeight="Bold" Margin="0,0,0,6" Foreground="#333333"/>
    <ComboBox x:Name="TimeCombo" Height="30" Margin="0,0,0,10" VerticalContentAlignment="Center" Padding="8,0,4,0"/>
    <Border Background="#F4F6F8" CornerRadius="4" Padding="10" Margin="0,0,0,12">
      <TextBlock x:Name="SleepNote" TextWrapping="Wrap" Foreground="#444444" FontSize="11"/>
    </Border>
    <TextBlock x:Name="DeferInfo" Margin="0,0,0,12" Foreground="#777777" FontSize="11" TextWrapping="Wrap"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="DeferBtn" Content="Remind me later" Width="125" Height="34" Margin="0,0,8,0"
              Background="#6B7280" Foreground="White" FontWeight="SemiBold"
              BorderThickness="0" VerticalContentAlignment="Center" Padding="0"/>
      <Button x:Name="ScheduleBtn" Content="Schedule restart" Width="125" Height="34" Margin="0,0,8,0"
              Background="#2563EB" Foreground="White" FontWeight="SemiBold"
              BorderThickness="0" VerticalContentAlignment="Center" Padding="0"/>
      <Button x:Name="NowBtn" Content="Restart now" Width="125" Height="34"
              Background="#D97706" Foreground="White" FontWeight="SemiBold"
              BorderThickness="0" VerticalContentAlignment="Center" Padding="0"/>
    </StackPanel>
    <TextBlock x:Name="Countdown" Margin="0,14,0,0" Foreground="#999999" FontSize="11" HorizontalAlignment="Center" TextWrapping="Wrap"/>
  </StackPanel>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$headlineTb = $window.FindName('Headline');  $headlineTb.Text = $headline
$bodyTb     = $window.FindName('Body');      $bodyTb.Text = $bodyText
$combo      = $window.FindName('TimeCombo')
$deferBtn   = $window.FindName('DeferBtn');  $deferBtn.Visibility = $deferVisibility
$scheduleBtn= $window.FindName('ScheduleBtn')
$nowBtn     = $window.FindName('NowBtn')
$deferInfo  = $window.FindName('DeferInfo')
$countdown  = $window.FindName('Countdown')
$sleepNote  = $window.FindName('SleepNote')
$timerPanel = $window.FindName('TimerPanel')
$timerDigits= $window.FindName('TimerDigits')
$timerInfo  = $window.FindName('TimerInfo')
$sleepNote.Text = "A 5 minute notification is displayed before any restart. A sleeping device will wake and restart on schedule; a powered-off device will restart when next turned on, if still required. Closing this window without a selection schedules a restart in $($config.closeAutoMinutes) minutes."

if ($config.allowDefer) {
    $remaining = $config.deferralLimit - $config.deferralsUsed
    $deferInfo.Text = "Remind me later postpones for $($config.repromptMinutes) minutes, up to $remaining more time(s)."
} else {
    $deferInfo.Text = 'Postponement is no longer available for this restart.'
}

foreach ($opt in $config.options) { [void]$combo.Items.Add($opt.label) }
if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }

$script:responded  = $false
$script:noticeTime = $null

function Get-ClampedTime([datetime]$t) {
    $ws = [TimeSpan]::FromMinutes($config.windowStartMinutes)
    $we = [TimeSpan]::FromMinutes($config.windowEndMinutes)
    if (($t.TimeOfDay -ge $ws) -and ($t.TimeOfDay -le $we)) { return $t }
    if ($t.TimeOfDay -lt $ws) { return $t.Date.Add($ws) }
    return $t.Date.AddDays(1).Add($ws)
}

function Invoke-AutoSchedule {
    $t = Get-ClampedTime (Get-Date).AddMinutes($config.closeAutoMinutes)
    $script:noticeTime = $t
    Write-Response @{ action = 'Schedule'; time = $t.ToString('o'); auto = $true }
}

function Get-IdleTarget {
    # 15 minutes before the end of the working day; tomorrow if already passed
    $t = (Get-Date).Date.Add([TimeSpan]::FromMinutes($config.windowEndMinutes)).AddMinutes(-15)
    if ($t -le (Get-Date).AddMinutes(10)) { $t = $t.AddDays(1) }
    return $t
}

function Invoke-IdleAutoSchedule {
    $t = Get-IdleTarget
    $script:noticeTime = $t
    Write-Response @{ action = 'Schedule'; time = $t.ToString('o'); auto = $true }
}

$nowBtn.Add_Click({
    $script:responded = $true
    Write-Response @{ action = 'Now' }
    $window.Close()
})
$scheduleBtn.Add_Click({
    if ($combo.SelectedIndex -ge 0) {
        $script:responded = $true
        $sel = @($config.options)[$combo.SelectedIndex]
        Write-Response @{ action = 'Schedule'; time = $sel.time }
        $window.Close()
    }
})
$deferBtn.Add_Click({
    $script:responded = $true
    Write-Response @{ action = 'Defer' }
    $window.Close()
})

if ($config.forceMode) {
    # Force mode: prominent countdown to automatic scheduling
    $timerPanel.Visibility = 'Visible'
    $timerInfo.Text = 'If no option is selected before this timer expires, a restart will be scheduled automatically.'
    $deadline = (Get-Date).AddMinutes($config.timeoutMinutes)
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        $left = $deadline - (Get-Date)
        if ($left.TotalSeconds -le 0) {
            $timer.Stop()
            if (-not $script:responded) { $script:responded = $true; Invoke-AutoSchedule }
            $window.Close()
        } else {
            $timerDigits.Text = ('{0:mm\:ss}' -f $left)
        }
    })
    $timer.Start()
} elseif ($config.idleMinutes -gt 0) {
    # Normal mode: idle timer - no selection within the limit schedules a
    # restart for shortly before the end of the working day
    $script:idleTarget   = Get-IdleTarget
    $script:idleDeadline = (Get-Date).AddMinutes($config.idleMinutes)
    $script:idleTargetText = if ($script:idleTarget.Date -eq (Get-Date).Date) {
        ('{0:HH:mm} today' -f $script:idleTarget)
    } else {
        ('{0:HH:mm} on {0:dddd}' -f $script:idleTarget)
    }
    $timerPanel.Visibility = 'Visible'
    $timerInfo.Text = "If no option is selected before this timer expires, a restart will be scheduled automatically for $($script:idleTargetText)."
    $idleTimer = New-Object System.Windows.Threading.DispatcherTimer
    $idleTimer.Interval = [TimeSpan]::FromSeconds(1)
    $idleTimer.Add_Tick({
        $left = $script:idleDeadline - (Get-Date)
        if ($left.TotalSeconds -le 0) {
            $idleTimer.Stop()
            if (-not $script:responded) { $script:responded = $true; Invoke-IdleAutoSchedule }
            $window.Close()
        } else {
            $timerDigits.Text = ('{0:mm\:ss}' -f $left)
        }
    })
    $idleTimer.Start()
} else {
    # Idle timer disabled: the window remains open until the user responds
    $countdown.Text = 'This window will remain open until an option is selected.'
}

$window.Add_Closed({
    if (-not $script:responded) {
        $script:responded = $true
        Invoke-AutoSchedule
    }
    try { Remove-Item $config.pidFile -Force -ErrorAction SilentlyContinue } catch { }
})

[void]$window.ShowDialog()

# ---------------------------------------------------------------------------
# Confirmation notice when a restart was auto-scheduled on close/timeout
# ---------------------------------------------------------------------------
if ($script:noticeTime) {
    $t = $script:noticeTime
    $timeText = if ($t.Date -eq (Get-Date).Date) {
        ('{0:HH:mm} today' -f $t)
    } else {
        ('{0:HH:mm} on {0:dddd d MMMM}' -f $t)
    }

    [xml]$nxaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NinjaOne Reboot Manager - Restart scheduled"
        Width="430" SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        Topmost="True" ResizeMode="NoResize" WindowStyle="ToolWindow"
        FontFamily="Arial" FontSize="13" Background="#FFFFFF">
  <StackPanel Margin="24">
    <Grid Margin="0,0,0,4">
      <TextBlock Text="Restart scheduled" FontSize="18" FontWeight="Bold" Foreground="#1F2937" VerticalAlignment="Center"/>
    </Grid>
    <TextBlock x:Name="NBody" Margin="0,10,0,16" TextWrapping="Wrap" Foreground="#333333"/>
    <Button x:Name="OkBtn" Content="OK" Width="90" Height="34" HorizontalAlignment="Right"
            Background="#1F2937" Foreground="White" FontWeight="SemiBold"
            BorderThickness="0" VerticalContentAlignment="Center" Padding="0"/>
  </StackPanel>
</Window>
"@
    $nreader = New-Object System.Xml.XmlNodeReader $nxaml
    $notice  = [Windows.Markup.XamlReader]::Load($nreader)

    $nbody = $notice.FindName('NBody')
    $nbody.Text = "No restart option was selected, so this device will restart at $timeText. Please save your work in advance - a 5 minute notification will be displayed first.`n`nTo choose a more convenient time in future, select an option when this prompt is displayed."

    $okBtn = $notice.FindName('OkBtn')
    $okBtn.Add_Click({ $notice.Close() })
    [void]$notice.ShowDialog()
}
'@
Set-Content -Path $PopupScript -Value $popupContent -Encoding UTF8

# ---------------------------------------------------------------------------
# Queued reboot wrapper (runs as SYSTEM at the scheduled time; skips if a
# genuine boot has already occurred - Fast Startup does not reset boot time)
# ---------------------------------------------------------------------------
$wrapperContent = @'
# NinjaOne Reboot Manager - queued reboot wrapper (SYSTEM, scheduled time)
$workDir  = 'C:\ProgramData\NinjaOne\RebootManager'
$marker   = Join-Path $workDir 'reboot_scheduled_marker.txt'
$logFile  = Join-Path $workDir 'reboot_manager.log'
$taskName = 'NinjaOne Scheduled Reboot'
$msg      = 'This device is restarting to complete required updates. Please save your work now.'
try {
    $m = (Get-Content (Join-Path $workDir 'reboot_message.txt') -Raw -ErrorAction Stop).Trim()
    if ($m) { $msg = $m }
} catch { }

function Log([string]$m) {
    ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) | Add-Content -Path $logFile
}

$scheduledAt = $null
try { $scheduledAt = [datetime](Get-Content $marker -Raw).Trim() } catch { }

$lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

if ($scheduledAt -and ($lastBoot -gt $scheduledAt)) {
    Log "Skipping queued restart - device genuinely rebooted at $lastBoot, after schedule time $scheduledAt."
} else {
    Log "Executing queued restart (last true boot: $lastBoot)."
    shutdown.exe /r /f /t 300 /c "$msg"
}

Remove-Item $marker -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
'@
Set-Content -Path $RebootWrapper -Value $wrapperContent -Encoding UTF8

# ---------------------------------------------------------------------------
# Response processor configuration
# ---------------------------------------------------------------------------
@{
    deferralLimit          = $DeferralLimit
    forcedFallbackMinutes  = $ForcedFallbackMinutes
    scheduleWindowStartMin = [int]$winStart.TotalMinutes
    scheduleWindowEndMin   = [int]$winEnd.TotalMinutes
    shutdownMsg            = $ShutdownMessage
    repromptMinutes        = $RepromptDelayMinutes
    selfCopy               = $SelfCopy
} | ConvertTo-Json | Set-Content -Path $ProcessorConfig -Encoding UTF8

# ---------------------------------------------------------------------------
# Response processor script (SYSTEM task, every minute, up to 14 days, until a response
# is processed or the main script cleans it up on its next run)
# ---------------------------------------------------------------------------
$processorContent = @'
# NinjaOne Reboot Manager - response processor (SYSTEM, every minute)
$ErrorActionPreference = 'SilentlyContinue'

$workDir       = 'C:\ProgramData\NinjaOne\RebootManager'
$responseFile  = Join-Path $workDir 'user\response.json'
$configFile    = Join-Path $workDir 'processor_config.json'
$promptConfig  = Join-Path $workDir 'config.json'
$pidFile       = Join-Path $workDir 'user\popup.pid'
$marker        = Join-Path $workDir 'reboot_scheduled_marker.txt'
$wrapperPath   = Join-Path $workDir 'Invoke-QueuedReboot.ps1'
$logFile       = Join-Path $workDir 'reboot_manager.log'
$regPath       = 'HKLM:\SOFTWARE\NinjaOne\RebootManager'
$popupTask     = 'NinjaOne Reboot Prompt'
$rebootTask    = 'NinjaOne Scheduled Reboot'
$selfTask      = 'NinjaOne Reboot Response Processor'
$shutdownMsg   = 'This device is restarting to complete required updates. Please save your work now.'

function Log([string]$m) {
    ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) | Add-Content -Path $logFile
}

function Set-NinjaFieldCli([string]$v) {
    $candidates = @(
        (Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'),
        'C:\Program Files\NinjaRMMAgent\ninjarmm-cli.exe',
        'C:\Program Files (x86)\NinjaRMMAgent\ninjarmm-cli.exe'
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { try { & $p set rebootPromptStatus $v | Out-Null } catch { } ; break }
    }
}

if (-not (Test-Path $responseFile)) { exit 0 }

Start-Sleep -Seconds 2   # allow any in-flight write to finish
$response = $null
try { $response = Get-Content $responseFile -Raw | ConvertFrom-Json } catch { exit 0 }
if (-not $response) { exit 0 }

$cfg = Get-Content $configFile -Raw | ConvertFrom-Json
if ($cfg.shutdownMsg) { $shutdownMsg = $cfg.shutdownMsg }
Log "Processing response: $($response.action)"

function Get-NextWindowTime([datetime]$Time) {
    $ws = [TimeSpan]::FromMinutes($cfg.scheduleWindowStartMin)
    $we = [TimeSpan]::FromMinutes($cfg.scheduleWindowEndMin)
    if (($Time.TimeOfDay -ge $ws) -and ($Time.TimeOfDay -le $we)) { return $Time }
    if ($Time.TimeOfDay -lt $ws) { return $Time.Date.Add($ws) }
    return $Time.Date.AddDays(1).Add($ws)
}

function New-QueuedReboot([datetime]$At) {
    (Get-Date).ToString('o') | Set-Content -Path $marker -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $wrapperPath)
    $trigger   = New-ScheduledTaskTrigger -Once -At $At
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -WakeToRun -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $rebootTask -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Log ("Restart scheduled for {0:dd/MM/yyyy HH:mm} (with already-rebooted check)." -f $At)
}

switch ($response.action) {

    'Now' {
        Set-NinjaFieldCli ("User selected restart now {0:dd/MM HH:mm}" -f (Get-Date))
        Log 'User selected restart now.'
        shutdown.exe /r /f /t 60 /c "$shutdownMsg"
    }

    'Schedule' {
        $when = [datetime]$response.time
        # Sanity clamp: the response file is user-writable, so never accept a
        # time in the past or more than 48 hours out
        if ($when -lt (Get-Date) -or $when -gt (Get-Date).AddHours(48)) {
            Log ("Response time {0:o} outside the accepted range - clamped." -f $when)
            $when = Get-NextWindowTime (Get-Date).AddMinutes(60)
        }
        New-QueuedReboot -At $when
        if ($response.auto) {
            Log 'No restart option was selected - restart auto-scheduled.'
            Set-NinjaFieldCli ("No selection - restart auto-scheduled for {0:dd/MM HH:mm}" -f $when)
        } else {
            Set-NinjaFieldCli ("Restart scheduled for {0:dd/MM HH:mm}" -f $when)
        }
    }

    'Defer' {
        $count = 0
        try { $count = [int](Get-ItemProperty -Path $regPath -Name DeferralCount).DeferralCount } catch { }
        $count++
        Set-ItemProperty -Path $regPath -Name DeferralCount -Value $count
        Set-ItemProperty -Path $regPath -Name LastDeferralTime -Value (Get-Date).ToString('o')
        Log "Postponed. Count is now $count of $($cfg.deferralLimit)."
        Set-NinjaFieldCli ("Postponed {0}/{1} at {2:dd/MM HH:mm}" -f $count, $cfg.deferralLimit, (Get-Date))

        # Self-rearm: re-display the prompt after the configured delay,
        # independent of any further trigger from the RMM.
        if ($cfg.repromptMinutes -gt 0 -and $cfg.selfCopy -and (Test-Path $cfg.selfCopy)) {
            $rpArgs      = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $cfg.selfCopy)
            $rpAction    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $rpArgs
            $rpTrigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($cfg.repromptMinutes)
            $rpPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $rpSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
            Register-ScheduledTask -TaskName 'NinjaOne Reboot Re-prompt' -Action $rpAction -Trigger $rpTrigger -Principal $rpPrincipal -Settings $rpSettings -Force | Out-Null
            Log ("Re-prompt scheduled in {0} minute(s)." -f $cfg.repromptMinutes)
        }
    }

    'Timeout' {
        # Only occurs in force mode - schedule automatically, clamped to the window
        $when = Get-NextWindowTime (Get-Date).AddMinutes($cfg.forcedFallbackMinutes)
        New-QueuedReboot -At $when
        Set-NinjaFieldCli ("No response in force mode - restart auto-scheduled for {0:dd/MM HH:mm}" -f $when)
    }
}

# Clean up the prompt cycle and remove this processor task. The re-prompt
# task is deliberately KEPT when the user postponed - it is what brings the
# prompt back after RepromptDelayMinutes. For every other outcome, remove it.
Remove-Item $responseFile, $promptConfig, $configFile, $pidFile -Force
Get-ScheduledTask -TaskName $popupTask -ErrorAction SilentlyContinue |
    Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
if ($response.action -ne 'Defer') {
    Get-ScheduledTask -TaskName 'NinjaOne Reboot Re-prompt' -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
}
Unregister-ScheduledTask -TaskName $selfTask -Confirm:$false -ErrorAction SilentlyContinue
exit 0
'@
Set-Content -Path $ProcessorScript -Value $processorContent -Encoding UTF8

# ---------------------------------------------------------------------------
# VBScript shim - launches the prompt with the console window fully suppressed
# ---------------------------------------------------------------------------
$vbsContent = @"
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File ""$PopupScript""", 0, False
"@
Set-Content -Path $LauncherVbs -Value $vbsContent -Encoding ASCII

# ---------------------------------------------------------------------------
# Register and start the prompt (user session) and the response processor
# ---------------------------------------------------------------------------
$action = New-ScheduledTaskAction -Execute 'wscript.exe' `
    -Argument ('//B //Nologo "{0}"' -f $LauncherVbs)
$popupPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
$popupSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -ExecutionTimeLimit (New-TimeSpan -Hours 72)
Register-ScheduledTask -TaskName $PopupTaskName -Action $action -Principal $popupPrincipal -Settings $popupSettings -Force | Out-Null
Start-ScheduledTask -TaskName $PopupTaskName

$procAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $ProcessorScript)
$procTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 14)
$procPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$procSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $ProcessorTaskName -Action $procAction -Trigger $procTrigger `
    -Principal $procPrincipal -Settings $procSettings -Force | Out-Null

Set-ItemProperty -Path $RegPath -Name LastPromptTime -Value (Get-Date).ToString('o')

Write-Log 'Prompt displayed in user session. Response processor registered.'
Set-NinjaField ("Prompt displayed {0:dd/MM HH:mm} - awaiting response" -f (Get-Date))

# ---------------------------------------------------------------------------
# Bounded reporting wait: capture the user's choice in this script's output
# (visible in the NinjaOne activity log) if they respond within the window.
# The response processor remains responsible for acting on the choice.
# ---------------------------------------------------------------------------
Write-Log ("Waiting up to {0} minute(s) to report the user's choice..." -f $OutputWaitMinutes)
$waitDeadline = (Get-Date).AddMinutes($OutputWaitMinutes)
$reported = $false

while ((Get-Date) -lt $waitDeadline) {

    if (Test-Path $ResponseFile) {
        Start-Sleep -Seconds 1   # allow the write to complete
        $resp = $null
        try { $resp = Get-Content $ResponseFile -Raw | ConvertFrom-Json } catch { }
        if ($resp) {
            switch ($resp.action) {
                'Now' {
                    Write-Log 'RESULT: User selected Restart now - the device is restarting.'
                }
                'Schedule' {
                    $t = [datetime]$resp.time
                    if ($resp.auto) {
                        Write-Log ("RESULT: No option was selected - restart auto-scheduled for {0:dd/MM/yyyy HH:mm}." -f $t)
                    } else {
                        Write-Log ("RESULT: User scheduled a restart for {0:dd/MM/yyyy HH:mm}." -f $t)
                    }
                }
                'Defer' {
                    Write-Log ("RESULT: User postponed the restart ({0} of {1} postponements now used)." -f ($deferralCount + 1), $DeferralLimit)
                }
                default {
                    Write-Log ("RESULT: Response received: {0}." -f $resp.action)
                }
            }
            $reported = $true
            break
        }
    }

    # If the processor beat us to the response file, the scheduled task is the evidence
    $rt = Get-ScheduledTask -TaskName $RebootTaskName -ErrorAction SilentlyContinue
    if ($rt) {
        $sb = $null
        try { $sb = [datetime]$rt.Triggers[0].StartBoundary } catch { }
        if ($sb) { Write-Log ("RESULT: A restart has been scheduled for {0:dd/MM/yyyy HH:mm}." -f $sb) }
        else     { Write-Log 'RESULT: A restart has been scheduled.' }
        $reported = $true
        break
    }

    Start-Sleep -Seconds 3
}

if (-not $reported) {
    Write-Log ("RESULT: No response within {0} minute(s) - the prompt remains open on the user's screen. The outcome will be recorded in the rebootPromptStatus custom field and in {1}." -f $OutputWaitMinutes, $LogFile)
}
exit 0
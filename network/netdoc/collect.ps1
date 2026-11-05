<#
.SYNOPSIS
  Read-only collection of Junos and FortiOS config + show output for netdoc.py.
.DESCRIPTION
  Uses OpenSSH with existing key-based auth and ~/.ssh/config aliases. Runs only show/get
  commands, one ssh call per command, each with a hard timeout, and saves HOST__suffix.txt
  files in OutDir. Checks TCP/22 first so an unreachable host (VPN down) fails in seconds.
.EXAMPLE
  .\collect.ps1 -Junos chi-core,cho-stor -FortiGate chi-fw -OutDir C:\netdoc\captures\chicago\test
#>
param(
  [string[]]$Junos = @(),
  [string[]]$FortiGate = @(),
  [Parameter(Mandatory = $true)][string]$OutDir,
  [int]$CommandTimeoutSec = 90
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'collect.log'

# 'when' = only run if the config contains this text (avoids commands that hang on boxes without the feature)
$junosCmds = @(
  @{ k = 'config';  c = 'show configuration | display inheritance no-comments | display set | no-more' }
  @{ k = 'version'; c = 'show version | no-more' }
  @{ k = 'lldp';    c = 'show lldp neighbors | no-more' }
  @{ k = 'terse';   c = 'show interfaces terse | no-more' }
  @{ k = 'bgp';     c = 'show bgp summary | no-more';      when = 'set protocols bgp ' }
  @{ k = 'vc';      c = 'show virtual-chassis | no-more';  t = 25 }
)
$fgtCmds = @(
  @{ k = 'config'; c = 'show' }
  @{ k = 'status'; c = 'get system status' }
  @{ k = 'ifphys'; c = 'get system interface physical' }
  @{ k = 'bgp';    c = 'get router info bgp summary';      when = 'config router bgp' }
)

function Assert-ReadOnly([string]$cmd) {
  if ($cmd -notmatch '^(show|get)( |$)' -or $cmd -match '[;`\r\n]') { throw "Refusing non read-only command: $cmd" }
}

function Get-SshHostName([string]$alias) {
  $h = (& ssh -G $alias 2>$null | Where-Object { $_ -like 'hostname *' } | Select-Object -First 1)
  if ($h) { return $h.Split(' ', 2)[1] } else { return $alias }
}

function Test-Port([string]$h, [int]$p, [int]$ms = 4000) {
  $c = New-Object Net.Sockets.TcpClient
  try { $ok = $c.ConnectAsync($h, $p).Wait($ms) -and $c.Connected } catch { $ok = $false }
  $c.Close(); return $ok
}

function Invoke-Ssh([string]$alias, [string]$cmd, [string]$file, [int]$timeoutSec) {
  # Runs ssh with stdout/stderr to files so a hung session can be killed after the timeout.
  $err = "$file.err"
  $p = Start-Process -FilePath ssh -NoNewWindow -PassThru `
    -ArgumentList @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', $alias, "`"$cmd`"") `
    -RedirectStandardOutput $file -RedirectStandardError $err
  if (-not $p.WaitForExit($timeoutSec * 1000)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    return 'timeout'
  }
  $p.WaitForExit()
  $rc = $p.ExitCode
  if ((Test-Path $err) -and (Get-Item $err).Length -eq 0) { Remove-Item $err }
  return $rc
}

function Invoke-Collect([string]$alias, $cmds) {
  $target = Get-SshHostName $alias
  if (-not (Test-Port $target 22)) {
    $msg = "{0:s}`t{1}`tSKIPPED: {2}:22 not reachable (VPN connected?)" -f (Get-Date), $alias, $target
    $msg | Tee-Object -FilePath $log -Append | Out-Null
    Write-Warning "$alias ($target) is not reachable on TCP/22 - is the VPN connected? Skipping."
    return
  }
  $configText = ''
  foreach ($e in $cmds) {
    Assert-ReadOnly $e.c
    if ($e.when -and $configText -and ($configText -notmatch [regex]::Escape($e.when))) { continue }
    $file = Join-Path $OutDir ("{0}__{1}.txt" -f $alias, $e.k)
    $start = Get-Date
    $tmo = if ($e.t) { [int]$e.t } else { $CommandTimeoutSec }
    $rc = Invoke-Ssh $alias $e.c $file $tmo
    $lines = if (Test-Path $file) { (Get-Content $file | Measure-Object -Line).Lines } else { 0 }
    "{0:s}`t{1}`t{2}`trc={3}`tlines={4}`t{5:N1}s" -f $start, $alias, $e.k, $rc, $lines, ((Get-Date) - $start).TotalSeconds |
      Tee-Object -FilePath $log -Append
    if ($e.k -eq 'config') {
      if ($rc -ne 0) { Write-Warning "$alias config collection failed (rc=$rc) - skipping this host."; return }
      $configText = Get-Content $file -Raw
    }
    if ($rc -eq 'timeout') {
      Write-Warning "$alias '$($e.c)' timed out after $tmo s - skipped."
      Remove-Item $file, "$file.err" -ErrorAction SilentlyContinue
    }
  }
}

foreach ($h in $Junos) { Invoke-Collect $h $junosCmds }
foreach ($h in $FortiGate) { Invoke-Collect $h $fgtCmds }
Write-Host "Done. Files in $OutDir"

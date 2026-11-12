<#
.SYNOPSIS
  Shows when Globalscape EFT file transfers happen, to help pick a maintenance window.

.DESCRIPTION
  Parses EFT W3C activity logs (ex*.log / u_ex*.log). Counts uploads ("created")
  and downloads ("sent"). Method values look like "[46300]created", so the
  session ID prefix is stripped. W3C log times are UTC; they are converted to -TimeZone.

  Output:
    1. Transfers by hour of day (with a bar chart)
    2. Weekday x hour grid (also exported to CSV)
    3. The quietest maintenance windows of -WindowHours length across the week

.EXAMPLE
  .\Get-EftTransferTimes.ps1 -Days 90 -TimeZone 'Eastern Standard Time' -WindowHours 6
#>
param(
    [string]$LogDir      = 'C:\ProgramData\Globalscape\EFT Server\Logs',
    [int]   $Days        = 60,
    [string]$TimeZone    = 'Pacific Standard Time',   # Get-TimeZone -ListAvailable for IDs
    [int]   $WindowHours = 6,
    [string]$CsvOut      = (Join-Path $env:USERPROFILE 'Desktop\eft_transfers_weekday_hour.csv')
)

$tz       = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZone)
$cutoff   = (Get-Date).AddDays(-$Days)
$dayNames = 'Sun','Mon','Tue','Wed','Thu','Fri','Sat'

$files = Get-ChildItem $LogDir -File |
         Where-Object { $_.Name -match '^(u_)?ex\d{6}\.log$' -and $_.LastWriteTime -ge $cutoff } |
         Sort-Object Name
if (-not $files) { Write-Warning "No ex*.log files newer than $Days days in $LogDir"; return }

$grid = @{}          # "<dayIndex>-<hour>" -> count
$up = 0; $down = 0
$firstDate = $null; $lastDate = $null

foreach ($f in $files) {
    $fields = $null
    foreach ($line in [IO.File]::ReadLines($f.FullName)) {
        if ($line.StartsWith('#Fields:')) {
            $fields = $line.Substring(8).Trim() -split ' '
            $iD = [array]::IndexOf($fields, 'date')
            $iT = [array]::IndexOf($fields, 'time')
            $iM = [array]::IndexOf($fields, 'cs-method')
            continue
        }
        if ($line.StartsWith('#') -or -not $fields) { continue }

        $v = $line -split ' '
        if ($v.Count -le $iM) { continue }
        $m = $v[$iM] -replace '^\[\d+\]', ''
        if ($m -ne 'created' -and $m -ne 'sent') { continue }

        $utc = [datetime]::SpecifyKind(
                   [datetime]::ParseExact("$($v[$iD]) $($v[$iT])", 'yyyy-MM-dd HH:mm:ss', $null), 'Utc')
        $lt  = [TimeZoneInfo]::ConvertTimeFromUtc($utc, $tz)

        $k = "$([int]$lt.DayOfWeek)-$($lt.Hour)"
        $grid[$k] = 1 + [int]$grid[$k]
        if ($m -eq 'created') { $up++ } else { $down++ }
        if (-not $firstDate -or $lt -lt $firstDate) { $firstDate = $lt }
        if (-not $lastDate  -or $lt -gt $lastDate)  { $lastDate  = $lt }
    }
}

$total = $up + $down
if ($total -eq 0) { Write-Warning 'Parsed logs but found no created/sent entries.'; return }
$spanDays = [math]::Max(1, [math]::Round(($lastDate - $firstDate).TotalDays, 1))

"`nEFT transfers, $($files.Count) log files, $($firstDate.ToString('yyyy-MM-dd')) to $($lastDate.ToString('yyyy-MM-dd')) ($TimeZone)"
"Uploads (created): $up   Downloads (sent): $down   Total: $total   (~$([math]::Round($total/$spanDays,0))/day)"

# --- 1. By hour of day ---
"`n=== Transfers by hour of day ==="
$byHour = foreach ($h in 0..23) {
    $c = 0; foreach ($d in 0..6) { $c += [int]$grid["$d-$h"] }
    [pscustomobject]@{ Hour = '{0:00}:00' -f $h; Transfers = $c; AvgPerDay = [math]::Round($c / $spanDays, 1) }
}
$max = ($byHour | Measure-Object Transfers -Maximum).Maximum
$byHour | ForEach-Object {
    $bar = '#' * [int][math]::Ceiling(40 * $_.Transfers / [math]::Max(1, $max))
    '{0}  {1,7}  {2,6}/day  {3}' -f $_.Hour, $_.Transfers, $_.AvgPerDay, $bar
}

# --- 2. Weekday x hour grid ---
"`n=== Weekday x hour (total transfers over the period) ==="
$table = foreach ($h in 0..23) {
    $row = [ordered]@{ Hour = '{0:00}:00' -f $h }
    $sum = 0
    foreach ($d in 0..6) { $c = [int]$grid["$d-$h"]; $row[$dayNames[$d]] = $c; $sum += $c }
    $row['Total'] = $sum
    [pscustomobject]$row
}
$table | Format-Table -AutoSize | Out-String
$table | Export-Csv $CsvOut -NoTypeInformation
"Grid exported to $CsvOut"

# --- 3. Quietest maintenance windows ---
"`n=== Quietest $WindowHours-hour windows (week wraps around) ==="
$slots = foreach ($d in 0..6) { foreach ($h in 0..23) { [int]$grid["$d-$h"] } }
$windows = foreach ($s in 0..167) {
    $sum = 0
    for ($i = 0; $i -lt $WindowHours; $i++) { $sum += $slots[($s + $i) % 168] }
    $e = ($s + $WindowHours) % 168
    [pscustomobject]@{
        Start     = '{0} {1:00}:00' -f $dayNames[[math]::Floor($s / 24)], ($s % 24)
        End       = '{0} {1:00}:00' -f $dayNames[[math]::Floor($e / 24)], ($e % 24)
        Transfers = $sum
        PerWeek   = [math]::Round($sum / [math]::Max(1, $spanDays / 7), 1)
    }
}
$windows | Sort-Object Transfers | Select-Object -First 10 | Format-Table -AutoSize | Out-String

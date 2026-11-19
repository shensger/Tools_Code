<#
.SYNOPSIS
    Writes existing BitLocker recovery passwords to a NinjaOne Secure custom field.
    Does NOT enable, resume, suspend or change encryption.

.DESCRIPTION
    For every BitLocker-capable volume (OS + fixed data drives) that has one or more
    RecoveryPassword protectors, writes "<Drive> <ProtectorId>: <RecoveryPassword>" entries,
    joined with " | ", to the Ninja field. Volumes with no encryption are reported and skipped.

    Run as SYSTEM from NinjaOne. The field must be a Secure (TEXT_ENCRYPTED) field,
    assigned to the device role, with Automations = Read/Write.

.PARAMETER NinjaField
    Custom field name. Default: bitlockerrecoverykey. Ninja script variable: ninjaField.

.PARAMETER AddRecoveryPassword
    If an encrypted volume has no RecoveryPassword protector, add one so there is a key to
    escrow. Adding a protector does not change encryption or protection state.
    Default: off. Ninja script variable: addRecoveryPassword = true.

.PARAMETER BackupToAD
    Also back up each recovery password to AD (domain-joined, DC reachable).
    Default: off. Ninja script variable: backupToAD = true.

.NOTES
    Exit codes: 0 = key(s) written or nothing to escrow; 1 = error; 3 = field write failed.
#>
param(
    [string]$NinjaField = $(if ($env:ninjaField) { $env:ninjaField } else { 'bitlockerrecoverykey' }),
    [switch]$AddRecoveryPassword = ($env:addRecoveryPassword -eq 'true'),
    [switch]$BackupToAD = ($env:backupToAD -eq 'true')
)

$ErrorActionPreference = 'Stop'
function Write-Log($msg) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg) }

if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Write-Log "BitLocker cmdlets not available (Home edition or BitLocker feature not installed). Nothing to escrow."
    exit 0
}

$entries = @()
$vols = Get-BitLockerVolume | Where-Object { $_.VolumeType -in 'OperatingSystem','FixedData' }

foreach ($v in $vols) {
    Write-Log ("{0} {1}: Status={2} Protection={3} Method={4}" -f $v.MountPoint, $v.VolumeType, $v.VolumeStatus, $v.ProtectionStatus, $v.EncryptionMethod)

    if ($v.VolumeStatus -eq 'FullyDecrypted') { Write-Log "  not encrypted - skipped"; continue }

    $rp = @($v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
    if ($rp.Count -eq 0) {
        if ($AddRecoveryPassword) {
            Write-Log "  no recovery password protector - adding one"
            Add-BitLockerKeyProtector -MountPoint $v.MountPoint -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
            $rp = @((Get-BitLockerVolume -MountPoint $v.MountPoint).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
        } else {
            Write-Log "  WARNING: encrypted but has NO recovery password protector (re-run with addRecoveryPassword=true)"
            continue
        }
    }

    foreach ($p in $rp) {
        $entries += "$($v.MountPoint) $($p.KeyProtectorId): $($p.RecoveryPassword)"
        if ($BackupToAD) {
            try {
                Backup-BitLockerKeyProtector -MountPoint $v.MountPoint -KeyProtectorId $p.KeyProtectorId | Out-Null
                Write-Log "  $($p.KeyProtectorId) backed up to AD"
            } catch { Write-Log "  AD backup failed: $($_.Exception.Message)" }
        }
    }
}

if (-not $entries) { Write-Log "No recovery passwords found - field left unchanged."; exit 0 }

if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
    Write-Log "ERROR: Ninja-Property-Set not available (not running under the NinjaOne agent)."; exit 1
}

$value = $entries -join ' | '
$result = Ninja-Property-Set $NinjaField $value 2>&1 | Out-String
if ($result -match 'error|not found|denied|invalid|unable|fail') {
    Write-Log "ERROR: write to '$NinjaField' failed: $($result.Trim()). Check the field is assigned to this device's role with Automations = Write."
    exit 3
}
Write-Log "Wrote $($entries.Count) recovery key(s) to NinjaOne field '$NinjaField'."
exit 0

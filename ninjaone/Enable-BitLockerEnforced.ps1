<#
.SYNOPSIS
    Enables and enforces BitLocker on the OS drive, with recovery key escrow.

.DESCRIPTION
    Built for NinjaOne deployment (runs as SYSTEM). Handles three states:
      - Fully decrypted        -> adds recovery password + TPM protector, starts encryption (XTS-AES 256)
      - Encrypted, protection off (Windows auto device encryption / clear key)
                               -> adds missing protectors, escrows key, resumes protection
      - Encrypted, protected   -> verifies protectors and re-escrows the key (idempotent)

    The recovery key is escrowed BEFORE protection is turned on. If no escrow target
    succeeds, the script stops and does not enable protection (unless -AllowNoEscrow).

    Escrow targets, tried in order:
      1. Active Directory (domain-joined, DC reachable)
      2. Entra ID (Entra-joined or hybrid-joined)
      3. NinjaOne Secure custom field (default: bitlockerRecoveryKey) - works off-network

    Also writes the BitLocker policy keys (HKLM\SOFTWARE\Policies\Microsoft\FVE) so
    future encryption uses XTS-AES 256 and backs up recovery info to AD DS.

.PARAMETER MountPoint
    OS drive. Default: $env:SystemDrive (C:)

.PARAMETER NinjaField
    Name of a NinjaOne device custom field (Secure type, Automations = Write) to store
    the recovery password. Default: bitlockerRecoveryKey. Override with the Ninja script
    variable ninjaField. Set to "none" to disable.

.PARAMETER AllowNoEscrow
    Enable protection even if the key could not be escrowed anywhere. Not recommended.
    Ninja script variable: allowNoEscrow (checkbox)

.PARAMETER SkipPolicyKeys
    Do not write HKLM\SOFTWARE\Policies\Microsoft\FVE values (use when GPO/Intune owns them).

.NOTES
    Exit codes:
      0 = Protected and key escrowed
      1 = Failure (see output)
      2 = TPM missing / not ready - needs hands-on
      3 = Key could not be escrowed - protection NOT enabled
#>

[CmdletBinding()]
param(
    [string]$MountPoint = $env:SystemDrive,
    [string]$NinjaField = $(if ($env:ninjaField) { $env:ninjaField } else { 'bitlockerRecoveryKey' }),
    [switch]$AllowNoEscrow = ($env:allowNoEscrow -eq 'true'),
    [switch]$SkipPolicyKeys = ($env:skipPolicyKeys -eq 'true')
)

$ErrorActionPreference = 'Stop'

function Write-Log($msg) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg) }

# ---------------------------------------------------------------- pre-checks
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Must run as Administrator/SYSTEM."; exit 1
}

if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Write-Log "ERROR: BitLocker cmdlets not available (Home edition or feature missing)."; exit 1
}

try {
    $tpm = Get-Tpm
} catch {
    Write-Log "ERROR: Unable to query TPM: $($_.Exception.Message)"; exit 2
}
if (-not $tpm.TpmPresent) { Write-Log "ERROR: No TPM present. Check BIOS (enable TPM/PTT)."; exit 2 }
if (-not $tpm.TpmReady)   { Write-Log "ERROR: TPM present but not ready (not owned/initialized). Run Initialize-Tpm or clear TPM in BIOS."; exit 2 }
Write-Log "TPM present and ready."

# ---------------------------------------------------------------- policy keys
if (-not $SkipPolicyKeys) {
    $fve = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    if (-not (Test-Path $fve)) { New-Item -Path $fve -Force | Out-Null }
    $policy = @{
        EncryptionMethodWithXtsOs     = 7   # XTS-AES 256 for OS drives
        EncryptionMethodWithXtsFdv    = 7   # XTS-AES 256 for fixed data drives
        EncryptionMethodWithXtsRdv    = 4   # AES-CBC 256 for removable (cross-compatible)
        OSRecovery                    = 1   # Choose how OS drives can be recovered: enabled
        OSManageDRA                   = 1
        OSRecoveryPassword            = 2   # Allow 48-digit recovery password
        OSRecoveryKey                 = 2   # Allow 256-bit recovery key
        OSHideRecoveryPage            = 0
        OSActiveDirectoryBackup       = 1   # Save recovery info to AD DS
        OSActiveDirectoryInfoToStore  = 1   # Recovery passwords and key packages
        OSRequireActiveDirectoryBackup = 0  # Script enforces escrow itself so off-network laptops aren't blocked
    }
    foreach ($k in $policy.Keys) {
        Set-ItemProperty -Path $fve -Name $k -Value $policy[$k] -Type DWord
    }
    Write-Log "BitLocker policy keys written ($fve)."
}

# ---------------------------------------------------------------- current state
$vol = Get-BitLockerVolume -MountPoint $MountPoint
Write-Log ("Initial state: VolumeStatus={0} Protection={1} Method={2} Protectors=[{3}]" -f `
    $vol.VolumeStatus, $vol.ProtectionStatus, $vol.EncryptionMethod, (($vol.KeyProtector.KeyProtectorType) -join ','))

if ($vol.VolumeStatus -in 'EncryptionInProgress','DecryptionInProgress') {
    Write-Log "Volume is mid-$($vol.VolumeStatus). Continuing with protector/escrow steps."
}
if ($vol.VolumeStatus -eq 'DecryptionInProgress') {
    Write-Log "WARNING: Decryption in progress - someone/something is turning BitLocker off. Investigate before re-running."
    exit 1
}

# ---------------------------------------------------------------- recovery password protector
$rp = @($vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
if ($rp.Count -eq 0) {
    Write-Log "Adding recovery password protector..."
    Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
    $vol = Get-BitLockerVolume -MountPoint $MountPoint
    $rp = @($vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
} else {
    Write-Log "Recovery password protector already present ($($rp.Count))."
}

# ---------------------------------------------------------------- escrow (before enabling protection)
$escrowed = @()
$cs = Get-CimInstance Win32_ComputerSystem
$dsreg = (dsregcmd /status) 2>$null
$aadJoined = [bool]($dsreg -match 'AzureAdJoined\s*:\s*YES')

foreach ($p in $rp) {
    # 1. Active Directory
    if ($cs.PartOfDomain) {
        try {
            if (Test-ComputerSecureChannel -ErrorAction Stop) {
                Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $p.KeyProtectorId | Out-Null
                Write-Log "Recovery key $($p.KeyProtectorId) backed up to AD ($($cs.Domain))."
                $escrowed += 'AD'
            } else {
                Write-Log "Domain-joined but no secure channel to a DC - skipping AD backup."
            }
        } catch {
            Write-Log "AD backup failed: $($_.Exception.Message)"
        }
    }
    # 2. Entra ID
    if ($aadJoined) {
        try {
            BackupToAAD-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $p.KeyProtectorId | Out-Null
            Write-Log "Recovery key $($p.KeyProtectorId) backed up to Entra ID."
            $escrowed += 'EntraID'
        } catch {
            Write-Log "Entra ID backup failed: $($_.Exception.Message)"
        }
    }
}

# 3. NinjaOne custom field
if ($NinjaField -and $NinjaField -ne 'none') {
    if (-not (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue)) {
        Write-Log "Ninja-Property-Set not available (not running under the NinjaOne agent) - skipping Ninja field."
    } else {
        try {
            $keys = ($rp | ForEach-Object { "$($_.KeyProtectorId): $($_.RecoveryPassword)" }) -join ' | '
            # Ninja-Property-Set reports problems (missing field, no write permission) as output text, not exceptions
            $result = Ninja-Property-Set $NinjaField $keys 2>&1 | Out-String
            if ($result -match 'error|not found|denied|invalid|unable|fail') {
                Write-Log "NinjaOne field write failed: $($result.Trim()). Check that Secure field '$NinjaField' exists, is assigned to this device's role, and has Automations = Write."
            } else {
                Write-Log "Recovery key written to NinjaOne field '$NinjaField'."
                $escrowed += 'NinjaOne'
            }
        } catch {
            Write-Log "NinjaOne field write failed: $($_.Exception.Message)"
        }
    }
}

$escrowed = $escrowed | Select-Object -Unique
if (-not $escrowed) {
    if ($AllowNoEscrow) {
        Write-Log "WARNING: Key not escrowed anywhere, continuing because -AllowNoEscrow is set."
    } else {
        Write-Log "ERROR: Recovery key could not be escrowed anywhere. NOT enabling protection. Create the Ninja Secure field '$NinjaField' (or connect to VPN/domain), then re-run."
        exit 3
    }
}

# ---------------------------------------------------------------- enable / resume
$vol = Get-BitLockerVolume -MountPoint $MountPoint
$hasTpm = [bool]($vol.KeyProtector | Where-Object { $_.KeyProtectorType -like 'Tpm*' })

try {
    if ($vol.VolumeStatus -eq 'FullyDecrypted') {
        Write-Log "Volume is decrypted. Enabling BitLocker (XTS-AES 256, TPM protector, full disk)..."
        Enable-BitLocker -MountPoint $MountPoint -EncryptionMethod XtsAes256 -TpmProtector -SkipHardwareTest -WarningAction SilentlyContinue | Out-Null
    }
    else {
        if (-not $hasTpm) {
            Write-Log "Adding TPM protector..."
            Add-BitLockerKeyProtector -MountPoint $MountPoint -TpmProtector -WarningAction SilentlyContinue | Out-Null
        }
        if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -ne 'On') {
            Write-Log "Resuming protection (removes clear key)..."
            Resume-BitLocker -MountPoint $MountPoint | Out-Null
        }
    }
} catch {
    Write-Log "ERROR enabling/resuming BitLocker: $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------------------- verify
Start-Sleep -Seconds 5
$vol = Get-BitLockerVolume -MountPoint $MountPoint
Write-Log ("Final state: VolumeStatus={0} Protection={1} Method={2} Encrypted={3}% Protectors=[{4}] Escrow=[{5}]" -f `
    $vol.VolumeStatus, $vol.ProtectionStatus, $vol.EncryptionMethod, $vol.EncryptionPercentage,
    (($vol.KeyProtector.KeyProtectorType) -join ','), ($escrowed -join ','))

if ($vol.ProtectionStatus -eq 'On') {
    Write-Log "SUCCESS: BitLocker protection is ON."
    exit 0
}
if ($vol.VolumeStatus -eq 'EncryptionInProgress') {
    Write-Log "SUCCESS: Encryption in progress - protection turns ON when encryption completes."
    exit 0
}
Write-Log "ERROR: Protection is not on after run."
exit 1

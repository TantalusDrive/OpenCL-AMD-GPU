# This PowerShell script extends the original batch by safely cleaning up invalid or misplaced
# registry entries and coherently registering AMD OpenCL DLLs in the correct 32-bit or 64-bit hive,
# while providing detailed and transparent status output.
#
# Unsigned DLLs are allowed by default to avoid removing valid but unusual ICDs.
# The user can override this behavior with -AllowUnsigned:$false.
#
# Risky registry operations are gated on evidence of registry backups (RegBack).
#
# Tested on older AMD GPUs (R5 M330, R5 M430). Feedback and contributions are welcome.
#
# Licensed under the MIT License
# (See LICENSE file in the repository root for full terms)

param(
    [switch]$AllowUnsigned = $true
)

Write-Host "OpenCL Driver (ICD) Fix for AMD GPUs"
Write-Host "Original batch by Patrick Trumpis (https://github.com/ptrumpis/OpenCL-AMD-GPU)"
Write-Host "PowerShell implementation by TantalusDrive (https://github.com/TantalusDrive)"
Write-Host "=================================================="
Write-Host ""

# -------------------------
# Runtime counters
# -------------------------
$Stats = @{
    RemovedMissing = 0
    RemovedSignature = 0
    Moved = 0
    Registered = 0
    AlreadyRegistered = 0
    SkippedDuplicate = 0
}

# -------------------------
# Configuration
# -------------------------
$Roots = @{
    64 = "HKLM:\SOFTWARE\Khronos\OpenCL\Vendors"
    32 = "HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors"
}

$ScanDirs = @(
    "$env:WINDIR\System32",
    "$env:WINDIR\SysWOW64",
    "$env:WINDIR\System32\DriverStore\FileRepository"
)

$Global:RegisteredSeen = [System.Collections.Generic.HashSet[string]]::new()

# -------------------------
# Helpers
# -------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RegistryBackupEnabled {
    $regBack = Join-Path $env:WINDIR "System32\config\RegBack"
    if (Test-Path $regBack) {
        foreach ($hive in 'SAM','SECURITY','SOFTWARE','SYSTEM','DEFAULT') {
            $f = Join-Path $regBack $hive
            if (-not (Test-Path $f)) { return $false }
            if ((Get-Item $f).Length -le 0) { return $false }
        }
        return $true
    }

    try {
        return [bool](Get-ScheduledTask -TaskName RegIdleBackup -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Try-EnableRegistryBackup {
    Write-Host "[INFO] Attempting to enable automatic registry backup..."
    try {
        $cfg = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager"
        if (-not (Test-Path $cfg)) {
            New-Item -Path (Split-Path $cfg) -Name "Configuration Manager" -Force | Out-Null
        }
        New-ItemProperty -Path $cfg -Name EnablePeriodicBackup -Value 1 -PropertyType DWord -Force | Out-Null
    } catch {
        Write-Host "[WARN] Failed to configure registry backup."
        return $false
    }

    try {
        $task = Get-ScheduledTask -TaskName RegIdleBackup -ErrorAction SilentlyContinue
        if ($task) {
            Enable-ScheduledTask $task | Out-Null
            Start-ScheduledTask  $task | Out-Null
        }
    } catch { }

    Start-Sleep -Seconds 4
    return (Test-RegistryBackupEnabled)
}

function Get-DllBitness {
    param([string]$Path)

    $fs = $null
    $br = $null
    try {
        $fs = [IO.File]::Open($Path,'Open','Read','Read')
        $br = New-Object IO.BinaryReader($fs)
        $fs.Seek(0x3C,'Begin') | Out-Null
        $pe = $br.ReadInt32()
        $fs.Seek($pe + 4,'Begin') | Out-Null
        switch ($br.ReadUInt16()) {
            0x8664 { 64 }
            0x014C { 32 }
            default { $null }
        }
    } catch { $null }
    finally {
        if ($br) { $br.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

function Is-AcceptableSignature {
    param($Sig)
    if (-not $Sig) { return $false }
    if ($Sig.Status -eq 'Valid') { return $true }
    if ($AllowUnsigned -and $Sig.Status -in 'NotSigned','Unknown') { return $true }
    return $false
}

function Ensure-Registry {
    param($Bit,$DllPath)

    $Root = $Roots[$Bit]
    if (-not $Root) { return }

    if (-not (Test-Path $Root)) {
        New-Item -Path $Root -Force | Out-Null
        Write-Host "[INFO] Created registry key: $Root"
    }

    if ($Global:RegisteredSeen.Contains($DllPath)) {
        Write-Host "[SKIP] Duplicate already processed: $DllPath"
        $Stats.SkippedDuplicate++
        return
    }

    $props = (Get-ItemProperty -Path $Root -ErrorAction SilentlyContinue).PSObject.Properties
    $exists = $props | Where-Object { $_.Name -eq $DllPath } | Select-Object -First 1

    if ($exists) {
        Write-Host "[OK] $Bit-bit already registered"
        $Stats.AlreadyRegistered++
    } else {
        try {
            New-ItemProperty -Path $Root -Name $DllPath -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Host "[ADD] $Bit-bit → $DllPath"
            $Stats.Registered++
        } catch {
            Write-Host "[WARN] Failed to register $DllPath under ${Root}: $_"
        }
    }

    $Global:RegisteredSeen.Add($DllPath) | Out-Null
}

# -------------------------
# Admin + backup gate
# -------------------------
if (-not (Test-IsAdmin)) {
    Write-Host "[FATAL] Administrator privileges required."
    exit 1
}

$RegistryBackupEnabled = Test-RegistryBackupEnabled

if ($RegistryBackupEnabled) {
    Write-Host "Registry backup detected — full remediation allowed."
} else {
    Write-Host "[WARN] Registry backup not detected."
    $ans = Read-Host "Enable automatic registry backup now? (Y/N)"
    if ($ans -match '^[Yy]$' -and (Try-EnableRegistryBackup)) {
        $RegistryBackupEnabled = $true
        Write-Host "[OK] Registry backup confirmed."
    } else {
        Write-Host "[SAFE MODE] Risky operations disabled."
    }
}

# -------------------------
# Registry reconciliation
# -------------------------
Write-Host ""
Write-Host "[PHASE] Registry reconciliation"

foreach ($bit in 64,32) {
    $root = $Roots[$bit]
    if (-not (Test-Path $root)) { continue }

    $props = (Get-ItemProperty $root).PSObject.Properties |
             Where-Object { $_.MemberType -eq 'NoteProperty' }

    foreach ($p in $props) {

        $dll = $p.Name
        if ($dll -notlike "*amdocl*.dll") { continue }

        if (-not $RegistryBackupEnabled) {
            Write-Host "[SAFE] Skipped $dll"
            continue
        }

        if (-not (Test-Path $dll)) {
            Write-Host "[REMOVE] Missing → $dll"
            Remove-ItemProperty -Path $root -Name $dll -Force
            $Stats.RemovedMissing++
            continue
        }

        $sig = Get-AuthenticodeSignature $dll
        if (-not (Is-AcceptableSignature $sig)) {
            Write-Host "[REMOVE] Signature rejected → $dll"
            Remove-ItemProperty -Path $root -Name $dll -Force
            $Stats.RemovedSignature++
            continue
        }

        $realBit = Get-DllBitness $dll
        if ($realBit -and $realBit -ne $bit) {
            Write-Host "[MOVE] $dll → $realBit-bit hive"
            Remove-ItemProperty -Path $root -Name $dll -Force
            Ensure-Registry $realBit $dll
            $Stats.Moved++
        }
    }
}

# -------------------------
# Standard scan
# -------------------------
Write-Host ""
Write-Host "[PHASE] Fast scan"

foreach ($dir in $ScanDirs) {
    if (-not (Test-Path $dir)) { continue }

    Write-Host "[SCAN] $dir"

    Get-ChildItem $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {

            $sig = Get-AuthenticodeSignature $_.FullName
            if (-not (Is-AcceptableSignature $sig)) {
                Write-Host "[SKIP] Signature rejected → $($_.FullName)"
                return
            }

            $bit = Get-DllBitness $_.FullName
            if ($bit) { Ensure-Registry $bit $_.FullName }
        }
}

# -------------------------
# PATH scan
# -------------------------
Write-Host ""
$ans = Read-Host "Scan PATH directories as well? (Y/N)"

if ($ans -match '^[Yy]$') {

    Write-Host "[PHASE] PATH scan, please wait ..."

    foreach ($p in ($env:PATH -split ';' | Where-Object { Test-Path $_ })) {

        Write-Host "[SCAN] $p"

        Get-ChildItem $p -Filter "amdocl*.dll" -ErrorAction SilentlyContinue |
            ForEach-Object {

                $sig = Get-AuthenticodeSignature $_.FullName
                if (-not (Is-AcceptableSignature $sig)) {
                    Write-Host "[SKIP] Signature rejected → $($_.FullName)"
                    return
                }

                $bit = Get-DllBitness $_.FullName
                if ($bit) { Ensure-Registry $bit $_.FullName }
            }
    }
}

# -------------------------
# Final summary
# -------------------------
Write-Host ""
Write-Host "========== SUMMARY =========="
Write-Host "Removed missing     : $($Stats.RemovedMissing)"
Write-Host "Removed signature   : $($Stats.RemovedSignature)"
Write-Host "Moved entries       : $($Stats.Moved)"
Write-Host "Registered new      : $($Stats.Registered)"
Write-Host "Already registered  : $($Stats.AlreadyRegistered)"
Write-Host "Duplicates skipped  : $($Stats.SkippedDuplicate)"
Write-Host "============================="

Write-Host ""
Write-Host "Completed." -ForegroundColor Green
Read-Host "Press Enter to exit"

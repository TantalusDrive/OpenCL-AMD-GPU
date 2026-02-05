# PowerShell script to manage and fix AMD OpenCL ICDs
#
# Original batch concept: Patrick Trumpis (https://github.com/ptrumpis/OpenCL-AMD-GPU)
# PowerShell implementation and extensions: TantalusDrive (https://github.com/TantalusDrive)
#
# Licensed under the MIT License
# (See LICENSE file in the repository root for full terms)
#
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


param(
    [switch]$AllowUnsigned = $true
)

Write-Host "AMD OpenCL ICD Fix (PowerShell Edition)"
Write-Host "====================================="
Write-Host ""

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

# -------------------------
# Dedup table (prevents duplicate registrations in same run)
# -------------------------
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
    Write-Host "Attempting to enable automatic registry backup..."
    try {
        $cfg = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager"
        if (-not (Test-Path $cfg)) {
            New-Item -Path (Split-Path $cfg) -Name "Configuration Manager" -Force | Out-Null
        }
        New-ItemProperty -Path $cfg -Name EnablePeriodicBackup -Value 1 -PropertyType DWord -Force | Out-Null
    } catch {
        Write-Host "Failed to configure registry backup." -ForegroundColor Yellow
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
    } catch {
        $null
    } finally {
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
        Write-Host "Created registry key: $Root"
    }

    # dedup in-memory
    if ($Global:RegisteredSeen.Contains($DllPath)) {
        Write-Host "[=] Skipping duplicate (already processed): $DllPath"
        return
    }

    # safe property check
    $props = (Get-ItemProperty -Path $Root -ErrorAction SilentlyContinue).PSObject.Properties
    $exists = $props | Where-Object { $_.Name -eq $DllPath } | Select-Object -First 1

    if ($exists) {
        Write-Host "[= $Bit-bit] Already registered: $DllPath"
    } else {
        try {
            New-ItemProperty -Path $Root -Name $DllPath -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Host "[+ $Bit-bit] Registered: $DllPath" -ForegroundColor Cyan
        } catch {
            Write-Host "Failed to register $DllPath under $Root: $_" -ForegroundColor Yellow
        }
    }

    $Global:RegisteredSeen.Add($DllPath) | Out-Null
}

# -------------------------
# Admin + backup gate
# -------------------------
if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: Administrator privileges required." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$RegistryBackupEnabled = Test-RegistryBackupEnabled
if ($RegistryBackupEnabled) {
    Write-Host "Registry backup detected. Full operations enabled." -ForegroundColor Green
} else {
    Write-Host "WARNING: Registry backup not detected." -ForegroundColor Yellow
    $ans = Read-Host "Enable automatic registry backup now? (Y/N)"
    if ($ans -match '^[Yy]$' -and (Try-EnableRegistryBackup)) {
        $RegistryBackupEnabled = $true
        Write-Host "Registry backup confirmed." -ForegroundColor Green
    } else {
        Write-Host "SAFE mode active: registry will not be modified." -ForegroundColor Yellow
    }
}

# -------------------------
# Registry reconciliation
# -------------------------
Write-Host ""
Write-Host "Scanning existing OpenCL ICD registry entries..."
foreach ($bit in 64,32) {
    $root = $Roots[$bit]
    if (-not (Test-Path $root)) { continue }

    $props = (Get-ItemProperty $root).PSObject.Properties |
             Where-Object { $_.MemberType -eq 'NoteProperty' }

    foreach ($p in $props) {
        $dll = $p.Name
        if ($dll -notlike "*amdocl*.dll") { continue }

        if (-not $RegistryBackupEnabled) {
            Write-Host "SAFE: skipped $dll"
            continue
        }

        if (-not (Test-Path $dll)) {
            Write-Host "Removed (missing): $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force
            continue
        }

        $sig = Get-AuthenticodeSignature $dll
        if (-not (Is-AcceptableSignature $sig)) {
            Write-Host "Removed (signature): $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force
            continue
        }

        $realBit = Get-DllBitness $dll
        if ($realBit -and $realBit -ne $bit) {
            Write-Host "Moved to $realBit-bit hive: $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force
            Ensure-Registry $realBit $dll
        }
    }
}

# -------------------------
# Standard scan
# -------------------------
Write-Host ""
Write-Host "Scanning standard locations for AMD OpenCL DLLs..."
foreach ($dir in $ScanDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName
            if (-not (Is-AcceptableSignature $sig)) { return }
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
    foreach ($p in ($env:PATH -split ';' | Where-Object { Test-Path $_ })) {
        Get-ChildItem $p -Filter "amdocl*.dll" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.FullName
                if (-not (Is-AcceptableSignature $sig)) { return }
                $bit = Get-DllBitness $_.FullName
                if ($bit) { Ensure-Registry $bit $_.FullName }
            }
    }
}

Write-Host ""
Write-Host "Completed." -ForegroundColor Green
Read-Host "Press Enter to exit"

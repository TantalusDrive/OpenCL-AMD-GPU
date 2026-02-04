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

# -------------------------
# Configuration
# -------------------------
$roots = @{
    64 = "HKLM:\SOFTWARE\Khronos\OpenCL\Vendors"
    32 = "HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors"
}

# Normalize registry roots defensively (avoid null/empty paths)
$NormalizedRoots = @{}
foreach ($k in $roots.Keys) {
    $v = $roots[$k]
    if (-not [string]::IsNullOrWhiteSpace($v)) {
        $NormalizedRoots[$k] = $v
    }
}
$roots = $NormalizedRoots

$scanDirs = @(
    "$env:WINDIR\System32",
    "$env:WINDIR\SysWOW64",
    "$env:WINDIR\System32\DriverStore\FileRepository"
)

# -------------------------
# Helpers
# -------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RegistryBackupEnabled {
    $windir = $env:WINDIR
    if (-not $windir) { return $false }

    $regBackPath = Join-Path $windir "System32\config\RegBack"
    if (Test-Path $regBackPath) {
        $expected = @('SAM','SECURITY','SOFTWARE','SYSTEM','DEFAULT')
        try {
            foreach ($name in $expected) {
                $f = Join-Path $regBackPath $name
                if (-not (Test-Path $f)) { return $false }
                if ((Get-Item $f -ErrorAction SilentlyContinue).Length -le 0) { return $false }
            }
            return $true
        } catch { }
    }

    try {
        if (Get-ScheduledTask -TaskName 'RegIdleBackup' -ErrorAction SilentlyContinue) { return $true }
        if (Get-ScheduledTask -TaskPath "\Microsoft\Windows\Registry\" -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -eq 'RegIdleBackup' }) { return $true }
    } catch { }

    return $false
}

function Try-EnableRegistryBackup {
    if (-not (Test-IsAdmin)) {
        Write-Host "Administrator privileges required to enable registry backups automatically." -ForegroundColor Yellow
        return $false
    }

    try {
        $cfgKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager"
        if (-not (Test-Path $cfgKey)) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
                     -Name "Configuration Manager" -Force | Out-Null
        }
        New-ItemProperty -Path $cfgKey -Name "EnablePeriodicBackup" `
                         -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host "Set EnablePeriodicBackup = 1 (attempted)." -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to set EnablePeriodicBackup." -ForegroundColor Yellow
    }

    try {
        $task = Get-ScheduledTask -TaskName 'RegIdleBackup' -ErrorAction SilentlyContinue
        if (-not $task) {
            $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Registry\" -ErrorAction SilentlyContinue |
                    Where-Object { $_.TaskName -eq 'RegIdleBackup' }
        }
        if ($task) {
            Enable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
            Start-ScheduledTask  -InputObject $task -ErrorAction SilentlyContinue
            Write-Host "Triggered RegIdleBackup scheduled task." -ForegroundColor Cyan
        }
    } catch { }

    Start-Sleep -Seconds 4
    return (Test-RegistryBackupEnabled)
}

function Get-DllBitness {
    param([string]$Path)
    try {
        $fs = [IO.File]::Open($Path,'Open','Read','Read')
        $br = New-Object IO.BinaryReader($fs)
        $fs.Seek(0x3C,'Begin') | Out-Null
        $pe = $br.ReadInt32()
        $fs.Seek($pe + 4,'Begin') | Out-Null
        $m = $br.ReadUInt16()
        $br.Close(); $fs.Close()
        switch ($m) {
            0x8664 { 64 }
            0x014C { 32 }
            default { $null }
        }
    } catch { $null }
}

function Is-AcceptableSignature {
    param($sig)
    if (-not $sig) { return $false }
    if ($sig.Status -eq 'Valid') { return $true }
    if ($AllowUnsigned -and $sig.Status -in 'NotSigned','Unknown') { return $true }
    return $false
}

function Ensure-Registry {
    param($bit,$dll)

    $root = $roots[$bit.ToString()]
    if ([string]::IsNullOrWhiteSpace($root)) { return }

    if (-not (Test-Path $root)) {
        try {
            New-Item -Path $root -Force | Out-Null
        } catch {
            Write-Host "Failed to create registry root: $root" -ForegroundColor Yellow
            return
        }
    }

    if (-not (Get-ItemProperty -Path $root -Name $dll -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $root -Name $dll -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host "[+ $bit bit] Registered: $dll" -ForegroundColor Cyan
    }
}

# -------------------------
# Main: registry backup gate
# -------------------------
$RegistryBackupEnabled = Test-RegistryBackupEnabled
if (-not $RegistryBackupEnabled) {
    Write-Host "Registry automatic backup not detected." -ForegroundColor Yellow
    $ans = Read-Host "Attempt to enable automatic registry backup now? (Y/N)"
    if ($ans -match '^[Yy]$') {
        if (Try-EnableRegistryBackup) {
            $RegistryBackupEnabled = $true
        } else {
            Write-Host "Backup not confirmed; destructive operations will be skipped." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Proceeding in SAFE mode (no destructive registry changes)." -ForegroundColor Yellow
    }
} else {
    Write-Host "Registry automatic backup detected — destructive fixes allowed." -ForegroundColor Green
}

# -------------------------
# Registry reconciliation
# -------------------------
Write-Host "`nScanning registry for invalid or misplaced entries..." -ForegroundColor Cyan

foreach ($bit in 64,32) {
    $root = $roots[$bit.ToString()]
    if ([string]::IsNullOrWhiteSpace($root)) { continue }
    if (-not (Test-Path $root)) { continue }

    $props = (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue).PSObject.Properties
    foreach ($p in $props) {
        $dll = $p.Name
        if ($dll -notlike "*amdocl*.dll") { continue }

        if (-not $RegistryBackupEnabled) {
            Write-Host "SAFE mode: skipped $dll" -ForegroundColor Yellow
            continue
        }

        if (-not (Test-Path $dll)) {
            Write-Host "Removed (missing): $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force -ErrorAction SilentlyContinue
            continue
        }

        $sig = Get-AuthenticodeSignature $dll -ErrorAction SilentlyContinue
        if (-not (Is-AcceptableSignature $sig)) {
            Write-Host "Removed (signature): $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force -ErrorAction SilentlyContinue
            continue
        }

        $realBit = Get-DllBitness $dll
        if ($realBit -and $realBit -ne $bit) {
            Write-Host "Moved ($realBit bit): $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force -ErrorAction SilentlyContinue
            Ensure-Registry $realBit $dll
        }
    }
}

# -------------------------
# Standard locations scan
# -------------------------
Write-Host "`nRegistering AMD OpenCL DLLs from standard locations..." -ForegroundColor Cyan

foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem -Path $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
            if (-not (Is-AcceptableSignature $sig)) { return }
            $bit = Get-DllBitness $_.FullName
            if ($bit) { Ensure-Registry $bit $_.FullName }
        }
}

# -------------------------
# Optional PATH scan
# -------------------------
Write-Host "`nDo you want to scan PATH directories as well? (Y/N)" -ForegroundColor Yellow
if ((Read-Host) -match '^[Yy]$') {
    foreach ($p in ($env:PATH -split ';' | Where-Object { Test-Path $_ })) {
        Get-ChildItem -Path $p -Filter "amdocl*.dll" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                if (-not (Is-AcceptableSignature $sig)) { return }
                $bit = Get-DllBitness $_.FullName
                if ($bit) { Ensure-Registry $bit $_.FullName }
            }
    }
}

Write-Host "`nCompleted." -ForegroundColor Green
Read-Host "Press Enter to exit"

# PowerShell script to manage and fix AMD OpenCL ICDs
#
# Original batch concept: Patrick Trumpis (https://github.com/ptrumpis/OpenCL-AMD-GPU)
# PowerShell implementation and extensions: TantalusDrive (https://github.com/TantalusDrive)
#
# Licensed under the MIT License
# (See LICENSE file in the repository root for full terms)
#
# This PowerShell script extends the original batch by safely cleaning up invalid or misplaced registry entries and coherently registering
# AMD OpenCL DLLs in the correct 32-bit or 64-bit hive, and providing detailed status output.
# Unsigned DLLs are allowed to prevent accidental removal, the user can override it with -AllowUnsigned:$false .
# Tested on a couple of dated AMD GPUs (R5 M330, R5 M430), feedback and contributions are welcome.
#
# Risky registry operations are gated on evidence of registry backups (RegBack).


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
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RegistryBackupEnabled {
    <#
    Heuristic: check RegBack files and scheduled task RegIdleBackup.
    Returns $true if RegBack appears available (files present & non-zero) or
    if the RegIdleBackup scheduled task exists; otherwise $false.
    #>
    $windir = $env:WINDIR
    if (-not $windir) { return $false }

    $regBackPath = Join-Path -Path $windir -ChildPath "System32\config\RegBack"
    if (Test-Path $regBackPath) {
        $expected = @('SAM','SECURITY','SOFTWARE','SYSTEM','DEFAULT')
        try {
            $allPresent = $true
            foreach ($name in $expected) {
                $f = Join-Path $regBackPath $name
                if (-not (Test-Path $f)) { $allPresent = $false; break }
                $size = (Get-Item $f -ErrorAction SilentlyContinue).Length
                if (-not $size -or $size -eq 0) { $allPresent = $false; break }
            }
            if ($allPresent) { return $true }
        } catch { }
    }

    # Check scheduled task RegIdleBackup (best-effort)
    try {
        $task = Get-ScheduledTask -TaskName 'RegIdleBackup' -ErrorAction SilentlyContinue
        if ($task) { return $true }

        $task2 = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Registry\" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq 'RegIdleBackup' }
        if ($task2) { return $true }
    } catch { }

    return $false
}

function Try-EnableRegistryBackup {
    <#
    Try to enable RegBack behaviour using two common methods:
      1) create/ensure EnablePeriodicBackup DWORD = 1 under:
         HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager
      2) enable & start scheduled task RegIdleBackup (if present)
    Returns $true if afterwards RegBack files are present (heuristic); otherwise $false.
    #>

    if (-not (Test-IsAdmin)) {
        Write-Host "Admin privileges required to enable registry backup automatically. Re-run as Administrator to allow automatic enabling." -ForegroundColor Yellow
        return $false
    }

    $success = $false

    # 1) Try to set EnablePeriodicBackup DWORD
    try {
        $cfgKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager"
        if (-not (Test-Path $cfgKey)) {
            # create parent key if missing
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "Configuration Manager" -Force -ErrorAction SilentlyContinue | Out-Null
        }
        # set EnablePeriodicBackup = 1
        New-ItemProperty -Path $cfgKey -Name "EnablePeriodicBackup" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Set EnablePeriodicBackup = 1 in $cfgKey (attempted)." -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to set EnablePeriodicBackup: $_" -ForegroundColor Yellow
    }

    Start-Sleep -Seconds 1

    # 2) Try to enable & run scheduled task RegIdleBackup
    try {
        $task = Get-ScheduledTask -TaskName 'RegIdleBackup' -ErrorAction SilentlyContinue
        if (-not $task) {
            $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Registry\" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq 'RegIdleBackup' }
        }
        if ($task) {
            try {
                Enable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
                Start-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
                Write-Host "Triggered scheduled task 'RegIdleBackup' (if allowed)." -ForegroundColor Cyan
            } catch {
                Write-Host "Could not start/enable scheduled task 'RegIdleBackup' automatically: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Scheduled task 'RegIdleBackup' not found on this system." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Scheduled task check failed: $_" -ForegroundColor Yellow
    }

    # wait a few seconds to let the task (if started) write RegBack files
    Start-Sleep -Seconds 4

    # re-check RegBack folder
    $windir = $env:WINDIR
    $regBackPath = Join-Path -Path $windir -ChildPath "System32\config\RegBack"
    if (Test-Path $regBackPath) {
        $expected = @('SAM','SECURITY','SOFTWARE','SYSTEM','DEFAULT')
        try {
            $allPresent = $true
            foreach ($name in $expected) {
                $f = Join-Path $regBackPath $name
                if (-not (Test-Path $f)) { $allPresent = $false; break }
                $size = (Get-Item $f -ErrorAction SilentlyContinue).Length
                if (-not $size -or $size -eq 0) { $allPresent = $false; break }
            }
            if ($allPresent) { Write-Host "Registry backup (RegBack) files detected." -ForegroundColor Green; $success = $true }
        } catch { }
    }

    return $success
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
        switch ($m) { 0x8664 {64} 0x014C {32} default {$null} }
    } catch { $null }
}

function Is-AcceptableSignature {
    param($sig)
    if ($sig -eq $null) { return $false }
    if ($sig.Status -eq 'Valid') { return $true }
    if ($AllowUnsigned -and $sig.Status -in 'NotSigned','Unknown') { return $true }
    return $false
}

function Ensure-Registry {
    param($bit,$dll)
    $root = $roots[$bit.ToString()]
    if (-not (Test-Path $root)) { New-Item -Path $root -Force | Out-Null }
    if (-not (Get-ItemProperty -Path $root -Name $dll -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $root -Name $dll -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host "[+ $bit bit] Registered: $dll" -ForegroundColor Cyan
    }
}

# -------------------------
# Main flow: check registry backup availability
# -------------------------
$RegistryBackupEnabled = Test-RegistryBackupEnabled
if (-not $RegistryBackupEnabled) {
    Write-Host "Registry automatic backup (RegBack) not detected." -ForegroundColor Yellow
    $ans = Read-Host "Attempt to enable automatic registry backup now? This will try to set EnablePeriodicBackup and run RegIdleBackup. (Y/N)"
    if ($ans -match '^[Yy]$') {
        $ok = Try-EnableRegistryBackup
        if ($ok) {
            $RegistryBackupEnabled = $true
        } else {
            Write-Host "Automatic enabling failed or RegBack files not created. Destructive registry operations will be SKIPPED." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Proceeding without enabling registry backups; destructive registry operations will be SKIPPED." -ForegroundColor Yellow
    }
} else {
    Write-Host "Registry automatic backup (RegBack) appears available — destructive registry fixes allowed." -ForegroundColor Green
}

# -------------------------
# Registry reconciliation (non-destructive unless $RegistryBackupEnabled)
# -------------------------
Write-Host "`nScanning registry for invalid or misplaced entries..." -ForegroundColor Cyan

foreach ($bit in 64,32) {
    $root = $roots[$bit.ToString()]
    if (-not (Test-Path $root)) { continue }
    $props = (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue).PSObject.Properties
    foreach ($p in $props) {
        $dll = $p.Name
        if ($dll -notlike "*amdocl*.dll") { continue }

        # If registry backups not detected/confirmed, skip destructive checks
        if (-not $RegistryBackupEnabled) {
            Write-Host "SKIP (no registry backup): $dll" -ForegroundColor Yellow
            continue
        }

        if (-not (Test-Path $dll)) {
            Write-Host "Removed (missing): $dll" -ForegroundColor Yellow
            Remove-ItemProperty -Path $root -Name $dll -Force -ErrorAction SilentlyContinue
            continue
        }

        $sig = Get-AuthenticodeSignature $dll -ErrorAction SilentlyContinue
        if (-not (Is-AcceptableSignature $sig)) {
            Write-Host "Removed (invalid signature): $dll" -ForegroundColor Yellow
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
# Register DLLs from standard locations
# -------------------------
Write-Host "`nRegistering AMD OpenCL DLLs from standard locations..." -ForegroundColor Cyan

foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem -Path $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
            if (-not (Is-AcceptableSignature $sig)) { continue }
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
                if (-not (Is-AcceptableSignature $sig)) { continue }
                $bit = Get-DllBitness $_.FullName
                if ($bit) { Ensure-Registry $bit $_.FullName }
            }
    }
}

Write-Host "`nCompleted." -ForegroundColor Green
Read-Host "Press Enter to exit"

# This PowerShell script extends the original batch by safely cleaning up
# invalid or misplaced registry entries and coherently registering AMD
# OpenCL DLLs in the correct 32-bit or 64-bit hive, and providing detailed status output.
# By default, unsigned DLLs are allowed to prevent accidental removal.
#
# Tested on a couple of dated AMD GPUs (R5 M330, R5 M430), feedback and contributions are welcome.
#
# Licensed under the MIT License.
# See LICENSE file in the repository root for full terms.

Write-Host "OpenCL Driver (ICD) Fix for AMD GPUs"
Write-Host "Original batch by Patrick Trumpis (https://github.com/ptrumpis/OpenCL-AMD-GPU)"
Write-Host "Powershell implementation by TantalusDrive (https://github.com/TantalusDrive)
Write-Host "Inspired by https://stackoverflow.com/a/28407851"
Write-Host ""
Write-Host ""

param(
    [switch]$AllowUnsigned = $true
)

$roots = @(
    "HKLM:\SOFTWARE\Khronos\OpenCL\Vendors",
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors"
)

$scanDirs = @(
    "$env:WINDIR\System32",
    "$env:WINDIR\SysWOW64",
    "$env:WINDIR\System32\DriverStore\FileRepository"
)

$hadErrors = $false

function Get-DllBitness {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOffset = $br.ReadInt32()
        $fs.Seek($peOffset + 4, 'Begin') | Out-Null
        $machine = $br.ReadUInt16()
        $br.Close(); $fs.Close()
        switch ($machine) {
            0x8664 { return 64 }
            0x014C { return 32 }
            default { return $null }
        }
    } catch { return $null }
}

function Safe-Remove {
    param($root,$name)
    try { Remove-ItemProperty -Path $root -Name $name -Force }
    catch { $global:hadErrors = $true }
}

function Safe-Add {
    param($root,$name)
    try { New-ItemProperty -Path $root -Name $name -Value 0 -PropertyType DWord -Force | Out-Null }
    catch { $global:hadErrors = $true }
}

function Is-SignatureAcceptable {
    param($sig, $AllowUnsigned)
    if ($sig.Status -eq 'Valid') { return $true }
    if ($AllowUnsigned -and ($sig.Status -eq 'NotSigned' -or $sig.Status -eq 'Unknown')) {
        return $true
    }
    return $false
}

function Register-OpenCLDLL {
    param([string]$dllPath, [switch]$AllowUnsigned)
    if (-not (Test-Path $dllPath)) { return }
    $sig = Get-AuthenticodeSignature -FilePath $dllPath
    if (-not (Is-SignatureAcceptable $sig $AllowUnsigned)) { return }
    $bit = Get-DllBitness $dllPath
    if ($bit -eq 64)      { $root = $roots[0] }
    elseif ($bit -eq 32) { $root = $roots[1] }
    else                 { return }
    $exists = (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue).PSObject.Properties |
              Where-Object { $_.Name -eq $dllPath }
    if (-not $exists) {
        Safe-Add $root $dllPath
        Write-Host "Registered: $dllPath" -ForegroundColor Green
    } else {
        Write-Host "Already present: $dllPath"
    }
}

# ============================================================
# Registry reconciliation
# ============================================================
foreach ($root in $roots) {
    Write-Host "`nAnalyzing: $root"
    $entries = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue
    if (-not $entries) {
        Write-Host "(none)"
        continue
    }
    foreach ($prop in $entries.PSObject.Properties) {
        $dll = $prop.Name
        if ($dll -notlike "*amdocl*.dll") { continue }

        if (-not (Test-Path $dll)) {
            Write-Host "Removed: $dll (file not found)" -ForegroundColor Magenta
            Safe-Remove $root $dll
            continue
        }

        $sig = Get-AuthenticodeSignature -FilePath $dll
        if (-not (Is-SignatureAcceptable $sig $AllowUnsigned)) {
            Write-Host "Removed: $dll (invalid signature)" -ForegroundColor Magenta
            Safe-Remove $root $dll
            continue
        }

        $bit = Get-DllBitness $dll
        if ($bit -eq $null) {
            Write-Host "Removed: $dll (architecture not detected)" -ForegroundColor Magenta
            Safe-Remove $root $dll
            continue
        }

        $correctRoot = if ($bit -eq 64) { $roots[0] } else { $roots[1] }
        if ($correctRoot -ne $root) {
            Write-Host "Moved ($bit` bit): $dll" -ForegroundColor Yellow
            Safe-Remove $root $dll
            $existsDest = (Get-ItemProperty -Path $correctRoot -ErrorAction SilentlyContinue).PSObject.Properties |
                          Where-Object { $_.Name -eq $dll }
            if (-not $existsDest) {
                Safe-Add $correctRoot $dll
            }
            continue
        }

        Write-Host "OK: $dll" -ForegroundColor Green
    }
}

# ============================================================
# Fast Scan (standard directories)
# ============================================================
Write-Host "`nThis script will now attempt to find and install unregistered OpenCL AMD drivers (Fast Scan)."
$input = Read-Host "Do you want to continue? (Y/N)"
if ($input -eq 'Y' -or $input -eq 'y') {

    Write-Host "Running AMD OpenCL Driver Auto Detection"
    Write-Host "========================================"

    foreach ($dir in $scanDirs) {
        if (-not (Test-Path $dir)) { continue }
        Write-Host "Scanning '$dir' for 'amdocl*.dll' files..."
        Get-ChildItem -Path $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.VersionInfo.FileVersionRaw } |
            ForEach-Object {
                Register-OpenCLDLL -dllPath $_.FullName -AllowUnsigned:$AllowUnsigned
        }
}

Write-Host "`nFast Scan complete." -ForegroundColor Cyan

} else {
    Write-Host "`nFast Scan skipped."
}

# ============================================================
# Full Scan (PATH)
# ============================================================
Write-Host "`nThis script will now attempt a Full Scan (PATH)."
Write-Host "(Recommended only for custom or unofficial DLLs)" -ForegroundColor Yellow
$input = Read-Host "Do you want to continue? (Y/N)"
if ($input -eq 'Y' -or $input -eq 'y') {

    Write-Host "`nNow scanning your PATH for 'amdocl*.dll' files..."
    Write-Host "Note: DLLs found in PATH may be unofficial or obsolete." -ForegroundColor Yellow
    Write-Host "==================================================="

    $pathDirs = ($env:PATH -split ';' | Where-Object { Test-Path $_ })
    foreach ($dir in $pathDirs) {
        Get-ChildItem -Path $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.VersionInfo.FileVersionRaw } |
            ForEach-Object {
                Register-OpenCLDLL -dllPath $_.FullName -AllowUnsigned:$AllowUnsigned
            }
    }

    Write-Host "`nFull Scan complete." -ForegroundColor Cyan
} else {
    Write-Host "`nFull Scan skipped."
}

if ($hadErrors) {
    Write-Host "`nCompleted with warnings." -ForegroundColor Yellow
} else {
    Write-Host "`nDone."
}

Read-Host "Press Enter to exit"

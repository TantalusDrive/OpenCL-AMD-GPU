# PowerShell script to manage and fix AMD OpenCL ICDs
#
# Original batch concept: Patrick Trumpis (https://github.com/ptrumpis/OpenCL-AMD-GPU)
# PowerShell implementation and extensions: TantalusDrive (https://github.com/TantalusDrive)
#
# Licensed under the MIT License.
# See LICENSE file in the repository root for full terms.
#
# This PowerShell script extends the original batch by safely cleaning up
# invalid or misplaced registry entries and coherently registering AMD
# OpenCL DLLs in the correct 32-bit or 64-bit hive, and providing detailed status output.
# By default, unsigned DLLs are allowed to prevent accidental removal.
#
# Tested on a couple of dated AMD GPUs (R5 M330, R5 M430), feedback and contributions are welcome.

param(
    [switch]$AllowUnsigned = $true
)

# AMD OpenCL registry hives
$roots = @(
    "HKLM:\SOFTWARE\Khronos\OpenCL\Vendors",        # 64-bit
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors"  # 32-bit
)

# Standard AMD directories scanned for OpenCL ICDs
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

        # Read PE header offset
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOffset = $br.ReadInt32()

        # Read machine field
        $fs.Seek($peOffset + 4, 'Begin') | Out-Null
        $machine = $br.ReadUInt16()

        $br.Close(); $fs.Close()

        switch ($machine) {
            0x8664 { return 64 } # AMD64
            0x014C { return 32 } # I386
            default { return $null }
        }
    } catch { return $null }
}

function Safe-Remove {
    param($root,$name)
    try {
        Remove-ItemProperty -Path $root -Name $name -Force
    } catch { $global:hadErrors = $true }
}

function Safe-Add {
    param($root,$name)
    try {
        New-ItemProperty -Path $root -Name $name -Value 0 -PropertyType DWord -Force | Out-Null
    } catch { $global:hadErrors = $true }
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
        Write-Host "Added ($bit-bit): $dllPath" -ForegroundColor Cyan
    }
}

# ----------------------------------------------------------
# 1) SAFE CLEANUP
# ----------------------------------------------------------

foreach ($root in $roots) {

    Write-Host "`nAnalyzing: $root" -ForegroundColor Cyan

    $entries = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue
    if (-not $entries) {
        Write-Host "No entries found or key missing."
        continue
    }

    foreach ($prop in $entries.PSObject.Properties) {

        $dll = $prop.Name
        if ($dll -notlike "*amdocl*.dll") { continue }

        if (-not (Test-Path $dll)) {
            Write-Host "Removed: $dll (file missing)" -ForegroundColor Yellow
            Safe-Remove $root $dll
            continue
        }

        $sig = Get-AuthenticodeSignature -FilePath $dll
        if (-not (Is-SignatureAcceptable $sig $AllowUnsigned)) {
            Write-Host "Removed: $dll (invalid signature)" -ForegroundColor Yellow
            Safe-Remove $root $dll
            continue
        }

        $bit = Get-DllBitness $dll
        if ($bit -eq $null) {
            Write-Host "Removed: $dll (bitness not detectable)" -ForegroundColor Yellow
            Safe-Remove $root $dll
            continue
        }

        $correctRoot = if ($bit -eq 64) { $roots[0] } else { $roots[1] }

        if ($correctRoot -ne $root) {
            Write-Host "Fixed hive mismatch ($bit-bit): $dll" -ForegroundColor Yellow
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

# ----------------------------------------------------------
# 2) COHERENT REBUILD (improved)
# ----------------------------------------------------------

Write-Host "`nRebuilding..." -ForegroundColor Cyan

foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }

    Get-ChildItem -Path $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
        Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending -ErrorAction SilentlyContinue |
        ForEach-Object {
            Register-OpenCLDLL -dllPath $_.FullName -AllowUnsigned:$AllowUnsigned
        }
}

if ($hadErrors) {
    Write-Host "`nCompleted with warnings." -ForegroundColor Yellow
} else {
    Write-Host "`nCompleted successfully." -ForegroundColor Green
}

# Run as Administrator
$roots = @(
    "HKLM:\SOFTWARE\Khronos\OpenCL\Vendors",            # 64-bit
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors" # 32-bit
)

# Directories to scan (more complete than just System32)
$scanDirs = @(
    "$env:WINDIR\System32",
    "$env:WINDIR\SysWOW64",
    "$env:WINDIR\System32\DriverStore\FileRepository"
)

# Error flag
$hadErrors = $false

function Get-DllBitness {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOffset = $br.ReadInt32()
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

function Safe-RemoveItemProperty {
    param($Path,$Name)
    try {
        Remove-ItemProperty -Path $Path -Name $Name -Force
    } catch {
        Write-Host "Warning: failed to remove $Name" -ForegroundColor Yellow
        $global:hadErrors = $true
    }
}

function Safe-NewItemProperty {
    param($Path,$Name,$Value)
    try {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    } catch {
        Write-Host "Warning: failed to register $Name" -ForegroundColor Yellow
        $global:hadErrors = $true
    }
}

function Register-OpenCLDLL {
    param (
        [string]$dllPath
    )
    if (-not (Test-Path $dllPath)) { return }

    $sig = Get-AuthenticodeSignature $dllPath
    if ($sig.Status -ne 'Valid') { return }

    $bit = Get-DllBitness -Path $dllPath
    if ($bit -eq 64) {
        $rootKey = $roots[0]
    } elseif ($bit -eq 32) {
        $rootKey = $roots[1]
    } else {
        return
    }

    $exists = (Get-ItemProperty -Path $rootKey -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains $dllPath
    if (-not $exists) {
        Safe-NewItemProperty $rootKey $dllPath 0
        Write-Host "Added ($bit-bit): $dllPath" -ForegroundColor Cyan
    }
}

# 1) Cleanup
foreach ($root in $roots) {
    Write-Host "`nAnalyzing: $root" -ForegroundColor Cyan
    $entries = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue
    if ($entries) {
        foreach ($property in $entries.PSObject.Properties) {
            $dllPath = $property.Name
            if ($dllPath -notlike "*amdocl*.dll") { continue }

            if (-not (Test-Path $dllPath)) {
                Write-Host "Removed: $dllPath (missing file)" -ForegroundColor Red
                Safe-RemoveItemProperty $root $dllPath
                continue
            }

            $sig = Get-AuthenticodeSignature $dllPath
            if ($sig.Status -ne 'Valid') {
                Write-Host "Removed: $dllPath (invalid signature)" -ForegroundColor Red
                Safe-RemoveItemProperty $root $dllPath
                continue
            }

            # Move if registered under the wrong hive
            $bit = Get-DllBitness -Path $dllPath
            $shouldRoot = if ($bit -eq 64) { $roots[0] } elseif ($bit -eq 32) { $roots[1] } else { $null }
            if ($shouldRoot -and ($root -ne $shouldRoot)) {
                if (-not (Test-Path $shouldRoot)) {
                    Write-Host "Warning: destination hive not found, skipping $dllPath" -ForegroundColor Yellow
                    continue
                }
                Write-Host "Moving ($bit-bit) from wrong hive: $dllPath" -ForegroundColor Yellow
                Safe-RemoveItemProperty $root $dllPath
                $existsDest = (Get-ItemProperty -Path $shouldRoot -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains $dllPath
                if (-not $existsDest) {
                    Safe-NewItemProperty $shouldRoot $dllPath 0
                }
            } else {
                Write-Host "OK: $dllPath" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "Key not found or empty." -ForegroundColor Yellow
    }
}

# 2) Rebuild from common locations (avoids duplicates, respects bitness)
Write-Host "`nRebuilding missing entries..." -ForegroundColor Cyan
foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem -Path $dir -Filter "amdocl*.dll" -Recurse -ErrorAction SilentlyContinue |
        Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending -ErrorAction SilentlyContinue |
        ForEach-Object {
            Register-OpenCLDLL -dllPath $_.FullName
        }
}

# Final message
if ($hadErrors) {
    Write-Host "`nScript finished with warnings or errors." -ForegroundColor Yellow
} else {
    Write-Host "`nScript finished successfully." -ForegroundColor Green
}

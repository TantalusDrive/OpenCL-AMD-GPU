# OpenCL-AMD-GPU
A possible fix for OpenCL detection problems on AMD Radeon GPU's.

![amdocl](https://user-images.githubusercontent.com/116500225/228428316-f24ba410-00fd-49ee-a173-f2ad7e27a433.PNG)

It will scan your system for *OpenCL Installable Client Driver (ICD)* files by AMD and register them on Windows.
- amdocl.dll
- amdocl12cl.dll
- amdocl12cl64.dll
- amdocl32.dll
- amdocl64.dll
- versioned variants (e.g. amdocl_*.dll, amdocl64_*.dll)

## Usage
## Batch script
1. Make sure to have the latest [AMD drivers](https://www.amd.com/en/support) installed
2. Download and execute `amdocl.bat`
3. Run the file as **Administrator** (Right click file and select `Run as Administrator`)

## PowerShell script
1. Download `amdocl-fix.ps1` and place it in a folder of your choice.
2. Make sure to run it as **Administrator**:
   - Right‑click the file → **Run with PowerShell** → confirm the UAC prompt.
   - Alternatively, open PowerShell as Administrator and run:
     ```powershell
     cd "C:\path\to\folder"
     .\amdocl-fix.ps1
     ```

## Compatibility
- Windows 10, 11: fully supported
- Windows 7, 8, 8.1: batch script fully supported; PowerShell script (`amdocl-fix.ps1`) requires PowerShell 5.1 or newer
- Windows XP / Vista: script runs safely, but OpenCL drivers may not be present  
The script ensures proper detection and registration of AMD OpenCL drivers on Windows, including handling SysWOW64, scanning the PATH safely, registering versioned DLLs, and avoiding duplicate entries.

## Notes
Inspired by StackOverflow https://stackoverflow.com/a/28407851

---

© 2023 [Patrick Trumpis](https://github.com/ptrumpis)   
© 2025 [TantalusDrive](https://github.com/TantalusDrive) (Additional improvements and PowerShell version)

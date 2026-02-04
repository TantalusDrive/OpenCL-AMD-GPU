@echo off
cls
echo OpenCL Driver (ICD) Fix for AMD GPUs
echo Original work by Patrick Trumpis (https://github.com/ptrumpis/OpenCL-AMD-GPU)
echo Improvements by TantalusDrive (https://github.com/TantalusDrive)
REM SysWOW64 handling, PATH scan, versioned DLLs, duplicate prevention
echo Inspired by https://stackoverflow.com/a/28407851
echo:
echo:

REM ============================================================
REM Privilege check
REM ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 goto :noAdmin

goto :continue

:noAdmin
echo.
echo Execution stopped
echo =================
echo This script requires administrator rights.
echo Please run it again as administrator.
echo You can right click the file and select 'Run as administrator'
echo.
pause
exit /b 1

:continue


REM ============================================================
REM Check Windows version (Vista+ required for registry backup)
REM ============================================================
for /f "tokens=4 delims=. " %%v in ('ver') do set WINVER=%%v
if %WINVER% lss 6 (
    echo WARNING: Automatic registry backup not supported before Windows Vista.
    set "REGBKOK=0"
) else (
    REM ========================================================
    REM Check automatic registry backup (EnablePeriodicBackup DWORD)
    REM ========================================================
    set "REGBKOK=0"

    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Configuration Manager key missing. SAFE mode enforced.
        set "REGBKOK=0"
    ) else (
        reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup >nul 2>&1
        if %errorlevel% equ 0 (
            REM check if value is 0x0 (disabled) otherwise consider enabled
            reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup | findstr /I "0x0" >nul 2>&1
            if %errorlevel%==0 (
                set "REGBKOK=0"
            ) else (
                set "REGBKOK=1"
            )
        )
    )

    if %REGBKOK%==0 (
        echo WARNING: Automatic registry backup is not enabled.
        set "INPUT="
        set /P "INPUT=Do you want to enable it now? (Y/N): "
        if /I "%INPUT%"=="Y" (
            reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup /t REG_DWORD /d 1 /f >nul 2>&1
            if %errorlevel%==0 (
                echo Backup registry mechanism enabled.
                set "REGBKOK=1"
            ) else (
                echo Failed to enable backup, proceeding with SAFE operations only.
            )
        ) else (
            echo Backup not enabled. Only safe operations will run.
        )
    )

    if %REGBKOK%==1 (echo Registry backup active.) else (echo Registry backup inactive, SAFE mode.)
)

REM ============================================================
REM Main script variables
REM ============================================================
SETLOCAL EnableDelayedExpansion
SET ROOTKEY64=HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors
SET ROOTKEY32=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors

REM Display current drivers
echo Currently installed OpenCL Client Drivers - 64bit
echo ==================================================
reg query %ROOTKEY64% >nul 2>&1 && (
    for /f "tokens=1,*" %%A in ('reg query %ROOTKEY64%') do echo %%A - %%B
) || echo (none)
echo:
echo Currently installed OpenCL Client Drivers - 32bit
echo ==================================================
reg query %ROOTKEY32% >nul 2>&1 && (
    for /f "tokens=1,*" %%A in ('reg query %ROOTKEY32%') do echo %%A - %%B
) || echo (none)
echo:

REM This script will now attempt to find and install unregistered OpenCL AMD drivers (Fast Scan).
set "INPUT="
set /P "INPUT=Do you want to continue? (Y/N): "
if /I "!INPUT!"=="Y" (
    echo:
) else (
    goto :exit
)

REM ============================================================
REM Fast Scan - standard directories (recursive registration)
REM ============================================================
echo Running AMD OpenCL Driver Auto Detection
echo ========================================
echo:

for %%D in ("%SYSTEMROOT%\System32" "%SYSTEMROOT%\SysWOW64") do (
    if exist "%%~D" (
        echo Scanning '%%~D' for 'amdocl*.dll' files, please wait...
        pushd "%%~D"
        call :registerMissingClientDriver
        popd
        echo:
    )
)

echo Fast Scan complete.
echo:
set "INPUT="
set /P "INPUT=Do you want to perform a Full PATH scan? (Y/N): "
if /I not "%INPUT%"=="Y" goto :complete

echo:
echo Now scanning PATH for 'amdocl*.dll' files...
echo:

for %%A in ("%PATH:;=";"%") do (
    if "%%~A" neq "" (
        if exist "%%~A\" (
            pushd "%%~A" >nul 2>&1
            if !ERRORLEVEL! == 0 (
                call :registerMissingClientDriver
                popd
            )
        )
    )
)

echo:
echo Full Scan complete.
echo:

:complete
echo Done.
pause
goto :exit

REM ============================================================
REM Register missing client drivers (non-destructive)
REM - recursive search, whitelist + versioned variants, diagnostics
REM - skips destructive operations if registry backup not active
REM ============================================================
:registerMissingClientDriver
for /r %%f in (amdocl*.dll) do (
    set "FILE=%%~dpnxf"
    set "NAME=%%~nxf"
    set "VALID="

    REM Accept fixed names and versioned variants (only real AMD files)
    if /I "!NAME!"=="amdocl.dll" (
        set "VALID=1"
    ) else if /I "!NAME!"=="amdocl64.dll" (
        set "VALID=1"
    ) else if /I "!NAME!"=="amdocl12cl.dll" (
        set "VALID=1"
    ) else if /I "!NAME!"=="amdocl12cl64.dll" (
        set "VALID=1"
    ) else (
        echo !NAME! | findstr /C:"amdocl64_" >nul && set "VALID=1"
        echo !NAME! | findstr /C:"amdocl_" >nul && set "VALID=1"
    )

    if defined VALID (
        echo Found: !FILE!

        REM Bitness detection (prefer explicit 64, otherwise default to 32)
        if /I "!NAME!"=="amdocl64.dll" (
            set "ROOTKEY=!ROOTKEY64!"
        ) else if /I "!NAME!"=="amdocl12cl64.dll" (
            set "ROOTKEY=!ROOTKEY64!"
        ) else (
            echo !NAME! | findstr /C:"amdocl64_" >nul
            if !ERRORLEVEL! == 0 (
                set "ROOTKEY=!ROOTKEY64!"
            ) else (
                set "ROOTKEY=!ROOTKEY32!"
            )
        )

        REM Ensure root key exists (with diagnostic)
        reg query !ROOTKEY! >nul 2>&1
        if !ERRORLEVEL! neq 0 (
            reg add !ROOTKEY! /f >nul 2>&1
            if !ERRORLEVEL! == 0 (
                echo Added Key: !ROOTKEY!
            ) else (
                echo ERROR: Failed to add key !ROOTKEY!
            )
        )

        REM Register DLL if missing (respect SAFE gating)
        if "!REGBKOK!"=="1" (
            reg query !ROOTKEY! /v "!FILE!" >nul 2>&1
            if !ERRORLEVEL! neq 0 (
                reg add !ROOTKEY! /v "!FILE!" /t REG_DWORD /d 0 /f >nul 2>&1
                if !ERRORLEVEL! == 0 (
                    echo Registered: !FILE!
                ) else (
                    echo ERROR: Failed to register !FILE!
                )
            ) else (
                echo Already present: !FILE!
            )
        ) else (
            echo SAFE mode: registry modification skipped for !FILE! (backup not active)
        )
    )
    REM Reset VALID for next iteration
    set "VALID="
)
goto :eof

:exit
exit /b 0

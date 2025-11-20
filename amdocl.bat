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
if %errorlevel% neq 0 (
    echo Execution stopped
    echo =================
    echo This script requires administrator rights.
    echo Please run it again as administrator.
    echo You can right click the file and select 'Run as administrator'
    echo:
    pause
    exit /b 1
)

SETLOCAL EnableDelayedExpansion

SET ROOTKEY64=HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors
SET ROOTKEY32=HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Khronos\OpenCL\Vendors

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

echo This script will now attempt to find and install unregistered OpenCL AMD drivers (Fast Scan).
set "INPUT="
set /P "INPUT=Do you want to continue? (Y/N): "
if /I "!INPUT!"=="Y" (
    echo:
    goto :scanFilesFast
) else (
    goto :exit
)

:scanFilesFast
echo Running AMD OpenCL Driver Auto Detection
echo ========================================
echo:

echo Scanning '%SYSTEMROOT%\System32' for 'amdocl*.dll' files...
cd /d %SYSTEMROOT%\System32
call :registerMissingClientDriver

echo:
echo Scanning '%SYSTEMROOT%\SysWOW64' for 'amdocl*.dll' files...
cd /d %SYSTEMROOT%\SysWOW64
call :registerMissingClientDriver

echo:
echo Fast Scan complete.
echo:

echo This script will now attempt a Full Scan (PATH).
set "INPUT="
set /P "INPUT=Do you want to continue? (Y/N): "
if /I "!INPUT!"=="Y" (
    goto :scanFilesFull
) else (
    goto :complete
)

:scanFilesFull
echo Now scanning your PATH for 'amdocl*.dll' files...
echo:

for %%A in ("%path:;=";"%") do (
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

:exit
exit /b 0

REM ============================================================
REM Register missing client drivers
REM ============================================================
:registerMissingClientDriver
for /r %%f in (amdocl*.dll) do (
    set FILE=%%~dpnxf
    set NAME=%%~nxf

    REM Accept fixed names and versioned variants (only real AMD files)
    set "VALID="
    if /I "!NAME!"=="amdocl.dll" (
        set "VALID=1"
    ) else if /I "!NAME!"=="amdocl64.dll" (
        set "VALID=1"
    ) else if /I "!NAME!"=="amdocl12cl.dll" (
        set "VALID=1"
    ) else if /I "!NAME!"=="amdocl12cl64.dll" (
        set "VALID=1"
    ) else (
        REM Versioned variants used by AMD releases
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
                REM Default to 32-bit if not matched above
                set "ROOTKEY=!ROOTKEY32!"
            )
        )

        REM Ensure root key exists
        reg query !ROOTKEY! >nul 2>&1
        if !ERRORLEVEL! neq 0 (
            reg add !ROOTKEY! /f >nul 2>&1
            if !ERRORLEVEL! == 0 (
                echo Added Key: !ROOTKEY!
            ) else (
                echo ERROR: Failed to add key !ROOTKEY!
            )
        )

        REM Register DLL if missing
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
    )
    REM Reset VALID for next iteration
    set "VALID="
)
goto :eof

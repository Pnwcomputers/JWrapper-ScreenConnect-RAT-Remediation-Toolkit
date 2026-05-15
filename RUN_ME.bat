@echo off
color 0B
echo ===================================================
echo   JWrapper / ScreenConnect Remediation Launcher
echo ===================================================
echo.

:: Check for Administrator privileges
echo [*] Checking for Administrative permissions...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Administrative permissions confirmed.
) else (
    color 0C
    echo.
    echo [ERROR] This script requires Administrative privileges!
    echo Please right-click 'RUN_ME.bat' and select "Run as administrator".
    echo.
    pause
    exit
)

:: Launch the PowerShell script
echo.
echo [*] Launching PowerShell Remediation Script (fix.ps1)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix.ps1"

echo.
echo ===================================================
echo   Remediation sequence complete.
echo   Please review the output above.
echo ===================================================
pause

@echo off
color 0B
echo ================================================================
echo   PNWC Intrusion Response Toolkit
echo   JWrapper / ScreenConnect Campaign
echo   Pacific Northwest Computers ^| 360-624-7379
echo ================================================================
echo.

:: Check for Administrator privileges
echo [*] Checking for Administrative permissions...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Administrative permissions confirmed.
    echo.
) else (
    color 0C
    echo.
    echo [ERROR] This script REQUIRES Administrator privileges!
    echo.
    echo Please close this window, then right-click RUN_ME.bat
    echo and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Present menu
echo ================================================================
echo   Select an option:
echo.
echo   [1]  CHECK ONLY  - Scan system for indicators (no changes made)
echo                       Run this FIRST to document what is present
echo.
echo   [2]  FIX / CLEAN - Remove all detected malware artifacts
echo                       Run CHECK first, then use this to remediate
echo.
echo   [3]  EXIT
echo ================================================================
echo.
set /p CHOICE="Enter choice (1, 2, or 3): "

if "%CHOICE%"=="1" goto CHECK
if "%CHOICE%"=="2" goto FIX
if "%CHOICE%"=="3" goto EXIT
echo.
echo [!] Invalid selection. Please enter 1, 2, or 3.
echo.
pause
goto :eof


:CHECK
echo.
echo ================================================================
echo   Launching Detection Scanner (CHECK-SYSTEM.PS1)
echo   READ ONLY - No changes will be made to this system
echo ================================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Check-System.ps1"
echo.
echo ================================================================
echo   Scan complete. Review the output above.
echo   A report file has been saved to this folder.
echo   Run option [2] to perform remediation if threats were found.
echo ================================================================
pause
exit /b 0


:FIX
echo.
color 0E
echo ================================================================
echo   WARNING: REMEDIATION MODE
echo   This will REMOVE malware artifacts from this system.
echo   Ensure you have run the CHECK (option 1) first and saved
echo   the report for documentation purposes.
echo ================================================================
echo.
set /p CONFIRM="Type YES to continue with remediation, or NO to cancel: "
if /i NOT "%CONFIRM%"=="YES" (
    echo.
    echo [*] Remediation cancelled. No changes were made.
    echo.
    pause
    exit /b 0
)
color 0C
echo.
echo [*] Launching Remediation Script (FIX.PS1)...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix.ps1"
echo.
echo ================================================================
echo   Remediation sequence complete.
echo   Review the output above and the log file saved to this folder.
echo   REBOOT THIS MACHINE when ready, then re-run option [1]
echo   to verify the system is clean.
echo ================================================================
pause
exit /b 0


:EXIT
echo.
echo [*] Exiting. No changes were made.
echo.
exit /b 0

@echo off
:: Set UTF-8 codepage so PowerShell Unicode box-drawing characters render correctly
chcp 65001 >nul 2>&1
color 0B
title PNWC Intrusion Response Toolkit v2.2

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
    echo [OK] Administrator confirmed.
    echo.
) else (
    color 0C
    echo.
    echo [ERROR] This script REQUIRES Administrator privileges.
    echo.
    echo Please close this window, then RIGHT-CLICK RUN_ME.bat
    echo and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Menu
:MENU
echo ================================================================
echo   Select an option:
echo.
echo   [1]  CHECK ONLY   Scan for malware indicators (NO changes made)
echo                     ** Run this FIRST. Saves a report file. **
echo.
echo   [2]  FIX / CLEAN  Remove all detected malware
echo                     Run CHECK first, then use this to remediate.
echo.
echo   [3]  EXIT
echo ================================================================
echo.
set /p CHOICE="Enter 1, 2, or 3: "

if "%CHOICE%"=="1" goto CHECK
if "%CHOICE%"=="2" goto FIX
if "%CHOICE%"=="3" goto EXIT

echo.
echo [!] Invalid choice. Enter 1, 2, or 3.
echo.
goto MENU


:CHECK
echo.
echo ================================================================
echo   Launching: system_check.ps1  (READ-ONLY - no changes made)
echo ================================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & '%~dp0system_check.ps1' }"
echo.
echo ================================================================
echo   Scan complete. A report file has been saved to this folder.
echo   ** EMAIL the report to jon@pnwcomputers.com **
echo   Run option [2] if threats were found and need to be removed.
echo ================================================================
pause
goto MENU


:FIX
echo.
color 0E
echo ================================================================
echo   WARNING: REMEDIATION MODE
echo   This will REMOVE malware artifacts from this system.
echo   Have you run the CHECK scan (option 1) and saved the report?
echo ================================================================
echo.
set /p CONFIRM="Type YES to continue, or NO to cancel: "
if /i NOT "%CONFIRM%"=="YES" (
    echo.
    echo [*] Cancelled. No changes were made.
    echo.
    pause
    goto MENU
)
color 0C
echo.
echo [*] Launching Fix.ps1...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & '%~dp0Fix.ps1' }"
echo.
echo ================================================================
echo   Remediation complete. A report file has been saved.
echo   ** EMAIL the report to jon@pnwcomputers.com **
echo   REBOOT this machine, then run option [1] to verify clean.
echo ================================================================
pause
goto MENU


:EXIT
echo.
echo [*] Exiting. No changes were made.
echo.
exit /b 0

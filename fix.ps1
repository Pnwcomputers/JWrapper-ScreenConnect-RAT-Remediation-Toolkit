<#
.SYNOPSIS
    Comprehensive Remediation for JWrapper/ScreenConnect Dual-Stage Intrusion.
#>

$ErrorActionPreference = "SilentlyContinue"
Write-Host "--- JWrapper/ScreenConnect Remediation Tool ---" -ForegroundColor Cyan

# 1. IDENTIFY & KILL MALICIOUS PROCESSES
$BadProcs = @(
    "Remote_Access_Service", 
    "SimpleService", 
    "ScreenConnect.WindowsClient", 
    "WindowsBackstageShell", 
    "rqe",
    "Remote AccessWinLauncher",
    "ScreenConnect.WindowsFileManager"
)
foreach ($proc in $BadProcs) {
    if (Get-Process $proc) {
        Write-Host "[!] Killing malicious process: $proc" -ForegroundColor Red
        Stop-Process -Name $proc -Force
    }
}

# 2. UNREGISTER SERVICES (WITH WILDCARDS)
$ServicesToKill = @("Remote Access Service")
$SCServices = Get-Service -Name "ScreenConnect Client*" | Select-Object -ExpandProperty Name
if ($SCServices) { $ServicesToKill += $SCServices }

foreach ($svc in $ServicesToKill) {
    if (Get-Service $svc) {
        Write-Host "[*] Removing Service: $svc" -ForegroundColor Yellow
        Stop-Service -Name $svc -Force 
        sc.exe delete $svc
    }
}

# 3. SCRUB PERSISTENCE REGISTRY KEYS
$RegKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Remote Access",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service"
)
foreach ($key in $RegKeys) {
    if (Test-Path $key) {
        Write-Host "[-] Deleting Persistence Key: $key" -ForegroundColor Red
        Remove-Item -Path $key -Recurse -Force
    }
}

# 4. PURGE FILE SYSTEM ARTIFACTS
$Paths = @(
    "$env:ProgramData\JWrapper-Remote Access",
    "C:\Windows\SystemTemp\ScreenConnect",
    "$env:TEMP\ScreenConnect"
)

# Catch ScreenConnect installs in Program Files
$SCProgramFiles = Get-ChildItem -Path "C:\Program Files (x86)\", "C:\Program Files\" -Filter "ScreenConnect Client*" -Directory
foreach ($dir in $SCProgramFiles) {
    $Paths += $dir.FullName
}

foreach ($path in $Paths) {
    if (Test-Path $path) {
        Write-Host "[X] Purging malware directory: $path" -ForegroundColor Red
        Remove-Item -Path $path -Recurse -Force
    }
}

Write-Host "--- Remediation Complete. REBOOT REQUIRED ---" -ForegroundColor Green

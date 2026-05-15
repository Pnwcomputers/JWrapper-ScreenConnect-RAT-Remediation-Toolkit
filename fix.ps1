<#
.SYNOPSIS
    Comprehensive Remediation for JWrapper/ScreenConnect Dual-Stage Intrusion.
    Pacific Northwest Computers - Malware Removal Tool

.DESCRIPTION
    Kills malicious processes, removes services, scrubs registry persistence,
    purges all file system artifacts, removes firewall rules, and logs all
    actions to a timestamped file for forensic record.

    Run Check-System.ps1 FIRST to document the pre-remediation state.

.NOTES
    Author  : Pacific Northwest Computers (enhanced from field incident)
    Contact : jon@pnwcomputers.com | 360-624-7379
    Version : 2.0
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

# ── Logging Setup ─────────────────────────────────────────────────────────────
$Timestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile    = Join-Path $ScriptDir "PNWC_Remediation_Log_$Timestamp.txt"
$ActionLog  = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
    Write-Host $entry -ForegroundColor $Color
    $ActionLog.Add($entry)
}

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "   PNWC Remediation Tool - JWrapper / ScreenConnect Intrusion   " -ForegroundColor Cyan
Write-Host "   Pacific Northwest Computers | jon@pnwcomputers.com           " -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Started  : $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Computer : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Log file : $LogFile" -ForegroundColor Gray
Write-Host ""

$ActionLog.Add("PNWC Remediation Tool - JWrapper/ScreenConnect")
$ActionLog.Add("Started: $(Get-Date)")
$ActionLog.Add("Computer: $env:COMPUTERNAME")
$ActionLog.Add("Operator: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)")
$ActionLog.Add("OS: $((Get-WmiObject Win32_OperatingSystem).Caption)")
$ActionLog.Add("=" * 70)


# ════════════════════════════════════════════════════════════════════
# STEP 1 — KILL MALICIOUS PROCESSES
# ════════════════════════════════════════════════════════════════════
Write-Log "--- STEP 1: Terminating Malicious Processes ---" "Cyan"

$BadProcs = @(
    "Remote_Access_Service",
    "Remote_Access_Configure",
    "Remote_Access_Launcher",
    "Remote_AccessWinLauncher",
    "SimpleService",
    "StopSimpleGatewayService",
    "ScreenConnect.WindowsClient",
    "ScreenConnect.WindowsFileManager",
    "WindowsBackstageShell",
    "rqe"
)

foreach ($proc in $BadProcs) {
    $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($running) {
        Write-Log "  [!] Killing process: $proc (PID: $(($running.Id -join ', ')))" "Red"
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        # Verify it's gone
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
            Write-Log "  [!] WARNING: $proc is still running after kill attempt" "Red"
        } else {
            Write-Log "  [OK] $proc terminated" "Green"
        }
    }
}

# Kill any java.exe running out of the JWrapper directory
Get-Process -Name "java" -ErrorAction SilentlyContinue | 
    Where-Object { $_.Path -like "*JWrapper*" } | ForEach-Object {
        Write-Log "  [!] Killing JWrapper java.exe (PID: $($_.Id)) at $($_.Path)" "Red"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }


# ════════════════════════════════════════════════════════════════════
# STEP 2 — REMOVE MALICIOUS SERVICES
# ════════════════════════════════════════════════════════════════════
Write-Log "" 
Write-Log "--- STEP 2: Removing Malicious Services ---" "Cyan"

$ServicesToKill = [System.Collections.Generic.List[string]]::new()
$ServicesToKill.Add("Remote Access Service")

# Discover any ScreenConnect client services dynamically
$SCServices = Get-Service -Name "ScreenConnect Client*" -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty Name
if ($SCServices) { foreach ($s in $SCServices) { $ServicesToKill.Add($s) } }

foreach ($svc in $ServicesToKill) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        Write-Log "  [*] Stopping service: $svc (Status: $($s.Status))" "Yellow"
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800

        Write-Log "  [*] Deleting service registration: $svc" "Yellow"
        $result = sc.exe delete $svc 2>&1
        if ($result -like "*SUCCESS*" -or $result -like "*marked for deletion*") {
            Write-Log "  [OK] Service '$svc' deleted successfully" "Green"
        } else {
            Write-Log "  [!] sc.exe delete result for '$svc': $result" "Red"
        }
    } else {
        Write-Log "  [--] Service not found (already removed or never installed): $svc" "DarkGray"
    }
}


# ════════════════════════════════════════════════════════════════════
# STEP 3 — REMOVE REGISTRY PERSISTENCE
# ════════════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 3: Removing Registry Persistence Keys ---" "Cyan"

$RegKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Remote Access Service",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Remote Access",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service"
)

foreach ($key in $RegKeys) {
    if (Test-Path $key) {
        try {
            Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
            Write-Log "  [OK] Removed key: $key" "Green"
        } catch {
            Write-Log "  [!] Failed to remove $key : $($_.Exception.Message)" "Red"
            # Try with reg.exe as a fallback
            $regPath = $key -replace "HKLM:\\", "HKLM\" -replace "HKCU:\\", "HKCU\"
            reg.exe delete $regPath /f 2>&1 | ForEach-Object { Write-Log "      reg.exe: $_" "Gray" }
        }
    } else {
        Write-Log "  [--] Key not present (already clean): $key" "DarkGray"
    }
}

# Sweep Run keys for any JWrapper/ScreenConnect autostart entries
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($runkey in $RunKeys) {
    if (Test-Path $runkey) {
        $vals = Get-ItemProperty -Path $runkey -ErrorAction SilentlyContinue
        $vals.PSObject.Properties | Where-Object {
            $_.Value -like "*JWrapper*" -or $_.Value -like "*ScreenConnect*" -or
            $_.Value -like "*Remote Access*" -or $_.Value -like "*SimpleHelp*" -or
            $_.Value -like "*SimpleGateway*"
        } | ForEach-Object {
            Write-Log "  [!] Removing autorun entry: '$($_.Name)' from $runkey" "Red"
            Remove-ItemProperty -Path $runkey -Name $_.Name -Force -ErrorAction SilentlyContinue
        }
    }
}

# Remove any scheduled tasks associated with the intrusion
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskPath -like "*JWrapper*" -or $_.TaskName -like "*Remote Access*" -or
    $_.TaskName -like "*ScreenConnect*" -or $_.TaskName -like "*SimpleHelp*"
} | ForEach-Object {
    Write-Log "  [!] Removing scheduled task: $($_.TaskName)" "Red"
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
}


# ════════════════════════════════════════════════════════════════════
# STEP 4 — PURGE FILE SYSTEM ARTIFACTS
# ════════════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 4: Purging File System Artifacts ---" "Cyan"

$Paths = [System.Collections.Generic.List[string]]::new()
$Paths.Add("$env:ProgramData\JWrapper-Remote Access")
$Paths.Add("C:\Windows\SystemTemp\ScreenConnect")
$Paths.Add("$env:TEMP\ScreenConnect")
$Paths.Add("C:\Windows\Temp\ScreenConnect")

# Dynamically discover ScreenConnect client install directories in Program Files
$SCInstallSearchPaths = @("C:\Program Files (x86)", "C:\Program Files")
foreach ($base in $SCInstallSearchPaths) {
    if (Test-Path $base) {
        Get-ChildItem -Path $base -Filter "ScreenConnect Client*" -Directory -ErrorAction SilentlyContinue | 
            ForEach-Object { $Paths.Add($_.FullName) }
    }
}

foreach ($path in $Paths) {
    if (Test-Path $path) {
        Write-Log "  [X] Purging: $path" "Red"
        try {
            # Take ownership first for stubborn files
            takeown /F $path /R /D Y 2>&1 | Out-Null
            icacls $path /grant administrators:F /T /Q 2>&1 | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Log "  [OK] Removed: $path" "Green"
        } catch {
            Write-Log "  [!] Could not fully remove $path : $($_.Exception.Message)" "Red"
            Write-Log "      Some files may be locked. Retry after reboot." "Gray"
        }
    } else {
        Write-Log "  [--] Path not found (already clean): $path" "DarkGray"
    }
}

# Remove known individual malware files if they exist outside the above directories
$LooseFiles = @(
    "$env:USERPROFILE\Downloads\rq.msi",
    "$env:USERPROFILE\Downloads\rqe.exe",
    "$env:PUBLIC\Downloads\rq.msi",
    "$env:PUBLIC\Downloads\rqe.exe"
)
foreach ($f in $LooseFiles) {
    if (Test-Path $f) {
        Write-Log "  [X] Removing loose artifact: $f" "Red"
        Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
    }
}

# Search for and remove any .scr files planted in SystemTemp
Get-ChildItem "C:\Windows\SystemTemp" -Filter "*.scr" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log "  [X] Removing suspicious .scr file: $($_.FullName)" "Red"
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
}


# ════════════════════════════════════════════════════════════════════
# STEP 5 — REMOVE SUSPICIOUS FIREWALL RULES
# ════════════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 5: Removing Malicious Firewall Rules ---" "Cyan"

Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "*Remote Access*" -or
    $_.DisplayName -like "*ScreenConnect*" -or
    $_.DisplayName -like "*SimpleHelp*" -or
    $_.DisplayName -like "*JWrapper*"
} | ForEach-Object {
    Write-Log "  [X] Removing firewall rule: $($_.DisplayName)" "Red"
    Remove-NetFirewallRule -DisplayName $_.DisplayName -ErrorAction SilentlyContinue
    Write-Log "  [OK] Removed: $($_.DisplayName)" "Green"
}


# ════════════════════════════════════════════════════════════════════
# STEP 6 — FLUSH DNS (CLEAR C2 DOMAIN FROM CACHE)
# ════════════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 6: Flushing DNS Cache ---" "Cyan"
try {
    Clear-DnsClientCache -ErrorAction Stop
    Write-Log "  [OK] DNS client cache flushed (removes cached C2 domain resolutions)" "Green"
} catch {
    Write-Log "  [!] DNS flush failed: $($_.Exception.Message)" "Red"
}


# ════════════════════════════════════════════════════════════════════
# STEP 7 — POST-REMEDIATION VERIFICATION
# ════════════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 7: Post-Remediation Verification ---" "Cyan"
$Issues = 0

# Re-check key indicators
$Checks = @{
    "Service: Remote Access Service"         = { Get-Service "Remote Access Service" -ErrorAction SilentlyContinue }
    "Dir: ProgramData\JWrapper-Remote Access" = { Test-Path "$env:ProgramData\JWrapper-Remote Access" }
    "Dir: SystemTemp\ScreenConnect"           = { Test-Path "C:\Windows\SystemTemp\ScreenConnect" }
    "RegKey: SafeBoot persistence"            = { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service" }
    "RegKey: Services entry"                  = { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service" }
    "Process: Remote_Access_Service"          = { Get-Process "Remote_Access_Service" -ErrorAction SilentlyContinue }
}

foreach ($check in $Checks.Keys) {
    $result = & $Checks[$check]
    if ($result) {
        $Issues++
        Write-Log "  [!] STILL PRESENT: $check" "Red"
    } else {
        Write-Log "  [OK] Cleared: $check" "Green"
    }
}


# ════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "================================================================" "DarkCyan"
Write-Log "   REMEDIATION COMPLETE" "Cyan"
Write-Log "================================================================" "DarkCyan"
Write-Log ""

if ($Issues -eq 0) {
    Write-Log "  STATUS: All verified indicators have been removed." "Green"
    Write-Log "  *** A SYSTEM REBOOT IS STRONGLY RECOMMENDED ***" "Yellow"
    Write-Log ""
    Write-Log "  After rebooting, re-run Check-System.ps1 to confirm" "White"
    Write-Log "  the system is clean. Then change ALL passwords." "White"
} else {
    Write-Log "  STATUS: $Issues item(s) could not be removed." "Red"
    Write-Log "  Review the log output above for details." "Yellow"
    Write-Log "  Reboot the system and re-run this script, or contact PNWC." "Yellow"
}

Write-Log ""
Write-Log "  IMPORTANT NEXT STEPS:" "Yellow"
Write-Log "  1. REBOOT this machine immediately" "White"
Write-Log "  2. After reboot, run Check-System.ps1 to verify clean state" "White"
Write-Log "  3. Change ALL passwords used on this machine since March 30, 2026" "White"
Write-Log "  4. Enable MFA on all accounts" "White"
Write-Log "  5. Block IOC IPs at firewall: 147.45.218.0, 91.215.85.219, 147.45.218.13" "White"
Write-Log "  6. Block domain at firewall: gqpplgq2g.anondns.net" "White"
Write-Log ""
Write-Log "  Contact : Pacific Northwest Computers" "Gray"
Write-Log "  Phone   : 360-624-7379" "Gray"
Write-Log "  Email   : jon@pnwcomputers.com" "Gray"
Write-Log ""
Write-Log "  Log saved to: $LogFile" "Gray"
Write-Log "================================================================" "DarkCyan"

# Save log to disk
try {
    $header = @"
================================================================
   PNWC Remediation Log - JWrapper / ScreenConnect Campaign
   Pacific Northwest Computers | jon@pnwcomputers.com | 360-624-7379
================================================================
Date     : $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')
Computer : $env:COMPUTERNAME
OS       : $((Get-WmiObject Win32_OperatingSystem).Caption)
Operator : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
================================================================

"@
    $header | Out-File -FilePath $LogFile -Encoding UTF8
    $ActionLog | Out-File -FilePath $LogFile -Encoding UTF8 -Append
} catch {
    Write-Host "  [!] Could not save log: $($_.Exception.Message)" -ForegroundColor Red
}

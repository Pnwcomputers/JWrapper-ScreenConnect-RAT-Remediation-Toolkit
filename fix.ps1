<#
.SYNOPSIS
    Comprehensive Remediation for JWrapper/ScreenConnect Dual-Stage Intrusion.
    Pacific Northwest Computers - Malware Removal Tool

.DESCRIPTION
    Kills malicious processes, removes services, scrubs registry persistence,
    purges all file system artifacts, removes firewall rules, flushes DNS,
    and saves a full timestamped action report with email instructions.

    Run system_check.ps1 FIRST to document the pre-remediation state.

.NOTES
    Author  : Pacific Northwest Computers
    Contact : jon@pnwcomputers.com | 360-624-7379
    Version : 2.1
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

# ── Setup ─────────────────────────────────────────────────────────────────────
$Timestamp     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ScriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReportFile    = Join-Path $ScriptDir "PNWC_Remediation_Report_$Timestamp.txt"
$ActionLog     = [System.Collections.Generic.List[string]]::new()
$RemovedItems  = [System.Collections.Generic.List[string]]::new()
$FailedItems   = [System.Collections.Generic.List[string]]::new()
$NotFoundItems = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Msg, [string]$Color = "White")
    $entry = "[$(Get-Date -Format 'HH:mm:ss')]  $Msg"
    Write-Host $entry -ForegroundColor $Color
    $ActionLog.Add($entry)
}
function Log-Removed  { param([string]$I); $RemovedItems.Add("  [REMOVED]      $I") }
function Log-Failed   { param([string]$I); $FailedItems.Add("  [FAILED]       $I") }
function Log-NotFound { param([string]$I); $NotFoundItems.Add("  [NOT FOUND]    $I") }

# ── Banner ────────────────────────────────────────────────────────────────────
# Ensure console can render box-drawing and block characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host.UI.RawUI.WindowTitle = "PNWC Remediation Tool v2.2"

Clear-Host
Write-Host ""
Write-Host "  ██████╗ ███╗   ██╗██╗    ██╗ ██████╗ " -ForegroundColor Cyan
Write-Host "  ██╔══██╗████╗  ██║██║    ██║██╔════╝ " -ForegroundColor Cyan
Write-Host "  ██████╔╝██╔██╗ ██║██║ █╗ ██║██║      " -ForegroundColor Cyan
Write-Host "  ██╔═══╝ ██║╚██╗██║██║███╗██║██║      " -ForegroundColor Cyan
Write-Host "  ██║     ██║ ╚████║╚███╔███╔╝╚██████╗ " -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝  ╚═══╝ ╚══╝╚══╝  ╚═════╝ " -ForegroundColor Cyan
Write-Host ""
Write-Host "  Pacific Northwest Computers" -ForegroundColor White
Write-Host "  Malware Remediation Toolkit" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host "   PNWC Remediation Tool - JWrapper / ScreenConnect Intrusion  " -ForegroundColor Cyan
Write-Host "   Pacific Northwest Computers  |  jon@pnwcomputers.com        " -ForegroundColor Gray
Write-Host "   v2.2 -- SILENTCONNECT / Medusa IAB variant                  " -ForegroundColor DarkGray
Write-Host ("=" * 70) -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Started  : $(Get-Date -Format 'dddd MMMM dd yyyy  HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Computer : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Log file : $ReportFile" -ForegroundColor Gray
Write-Host ""
$ActionLog.Add("PNWC Remediation Tool v2.2 -- JWrapper/ScreenConnect (SILENTCONNECT)")
$ActionLog.Add("Started : $(Get-Date)")
$ActionLog.Add("Computer: $env:COMPUTERNAME")
$ActionLog.Add("OS      : $((Get-WmiObject Win32_OperatingSystem).Caption)")
$ActionLog.Add("Operator: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)")
$ActionLog.Add(("=" * 70))


# ════════════════════════════════════════════════════════════
# STEP 1 — KILL PROCESSES
# ════════════════════════════════════════════════════════════
Write-Log "--- STEP 1: Terminating Malicious Processes ---" "Cyan"
$BadProcs = @(
    "Remote_Access_Service","Remote_Access_Configure","Remote_Access_Launcher",
    "Remote_AccessWinLauncher","SimpleService","StopSimpleGatewayService",
    "ScreenConnect.WindowsClient","ScreenConnect.WindowsFileManager",
    "WindowsBackstageShell","rqe"
)
foreach ($proc in $BadProcs) {
    $r = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($r) {
        Write-Log "  [!] Killing: $proc  (PID: $(($r.Id -join ', ')))" "Red"
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
            Write-Log "  [!] WARNING: $proc still running after kill attempt" "Red"
            Log-Failed "Process: $proc (still running)"
        } else {
            Write-Log "  [OK] $proc terminated" "Green"
            Log-Removed "Process: $proc"
        }
    } else {
        Write-Log "  [--] Not running: $proc" "DarkGray"
        Log-NotFound "Process: $proc"
    }
}
# Kill JWrapper java instances
Get-Process -Name "java" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*JWrapper*" } | ForEach-Object {
        Write-Log "  [!] Killing JWrapper java.exe  PID: $($_.Id)" "Red"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Log-Removed "JWrapper java.exe PID $($_.Id)"
    }


# ════════════════════════════════════════════════════════════
# STEP 2 — REMOVE SERVICES
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 2: Removing Malicious Services ---" "Cyan"
$SvcList = [System.Collections.Generic.List[string]]::new()
$SvcList.Add("Remote Access Service")
Get-Service -Name "ScreenConnect Client*" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name | ForEach-Object { $SvcList.Add($_) }

foreach ($svc in $SvcList) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        Write-Log "  [*] Stopping: $svc  (Status: $($s.Status))" "Yellow"
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
        Write-Log "  [*] Deleting service registration: $svc" "Yellow"
        $res = sc.exe delete $svc 2>&1
        if ($res -like "*SUCCESS*" -or $res -like "*marked for deletion*") {
            Write-Log "  [OK] Service deleted: $svc" "Green"
            Log-Removed "Service: $svc"
        } else {
            Write-Log "  [!] sc.exe result for '$svc': $res" "Red"
            Log-Failed "Service: $svc  ($res)"
        }
    } else {
        Write-Log "  [--] Service not found: $svc" "DarkGray"
        Log-NotFound "Service: $svc"
    }
}


# ════════════════════════════════════════════════════════════
# STEP 3 — REGISTRY PERSISTENCE
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 3: Removing Registry Persistence ---" "Cyan"
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
            Log-Removed "Registry: $key"
        } catch {
            Write-Log "  [!] Failed to remove: $key  ($($_.Exception.Message))" "Red"
            $regPath = $key -replace "HKLM:\\","HKLM\" -replace "HKCU:\\","HKCU\"
            reg.exe delete $regPath /f 2>&1 | Out-Null
            Log-Failed "Registry: $key"
        }
    } else {
        Write-Log "  [--] Key not present: $key" "DarkGray"
        Log-NotFound "Registry: $key"
    }
}
# Run key sweep
foreach ($rk in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
    if (Test-Path $rk) {
        (Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Value -like "*JWrapper*" -or $_.Value -like "*ScreenConnect*" -or $_.Value -like "*Remote Access*" } |
            ForEach-Object {
                Write-Log "  [!] Removing autorun: '$($_.Name)' from $rk" "Red"
                Remove-ItemProperty -Path $rk -Name $_.Name -Force -ErrorAction SilentlyContinue
                Log-Removed "Autorun: $($_.Name) in $rk"
            }
    }
}
# Scheduled tasks
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -like "*Remote Access*" -or $_.TaskName -like "*ScreenConnect*" -or $_.TaskPath -like "*JWrapper*" } |
    ForEach-Object {
        Write-Log "  [!] Removing scheduled task: $($_.TaskName)" "Red"
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Log-Removed "Scheduled Task: $($_.TaskName)"
    }


# ════════════════════════════════════════════════════════════
# STEP 4 — FILE SYSTEM
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 4: Purging File System Artifacts ---" "Cyan"
$Paths = [System.Collections.Generic.List[string]]::new()
$Paths.Add("$env:ProgramData\JWrapper-Remote Access")
$Paths.Add("C:\Windows\SystemTemp\ScreenConnect")
$Paths.Add("$env:TEMP\ScreenConnect")
$Paths.Add("C:\Windows\Temp\ScreenConnect")
foreach ($base in @("C:\Program Files (x86)","C:\Program Files")) {
    Get-ChildItem -Path $base -Filter "ScreenConnect Client*" -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $Paths.Add($_.FullName) }
}
foreach ($path in $Paths) {
    if (Test-Path $path) {
        Write-Log "  [X] Purging: $path" "Red"
        try {
            takeown /F $path /R /D Y 2>&1 | Out-Null
            icacls $path /grant administrators:F /T /Q 2>&1 | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Log "  [OK] Removed: $path" "Green"
            Log-Removed "Directory: $path"
        } catch {
            Write-Log "  [!] Could not fully remove $path : $($_.Exception.Message)" "Red"
            Log-Failed "Directory: $path (may need reboot)"
        }
    } else {
        Write-Log "  [--] Not found: $path" "DarkGray"
        Log-NotFound "Directory: $path"
    }
}
foreach ($f in @("$env:USERPROFILE\Downloads\rq.msi","$env:USERPROFILE\Downloads\rqe.exe","$env:PUBLIC\Downloads\rq.msi","$env:PUBLIC\Downloads\rqe.exe")) {
    if (Test-Path $f) {
        Write-Log "  [X] Removing: $f" "Red"
        Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
        Log-Removed "File: $f"
    }
}
Get-ChildItem "C:\Windows\SystemTemp\" -Filter "*.scr" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log "  [X] Removing .scr dropper: $($_.FullName)" "Red"
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    Log-Removed "SCR File: $($_.FullName)"
}


# ════════════════════════════════════════════════════════════
# STEP 5 — FIREWALL RULES
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 5: Removing Malicious Firewall Rules ---" "Cyan"
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Remote Access*" -or $_.DisplayName -like "*ScreenConnect*" -or $_.DisplayName -like "*JWrapper*" } |
    ForEach-Object {
        Write-Log "  [X] Removing firewall rule: $($_.DisplayName)" "Red"
        Remove-NetFirewallRule -DisplayName $_.DisplayName -ErrorAction SilentlyContinue
        Log-Removed "Firewall Rule: $($_.DisplayName)"
    }


# ════════════════════════════════════════════════════════════
# STEP 6 — DNS FLUSH
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 6: Flushing DNS Cache ---" "Cyan"
try {
    Clear-DnsClientCache -ErrorAction Stop
    Write-Log "  [OK] DNS cache flushed (clears cached C2 domain resolutions)" "Green"
    Log-Removed "DNS Cache (flushed)"
} catch {
    Write-Log "  [!] DNS flush failed: $($_.Exception.Message)" "Red"
    Log-Failed "DNS Cache flush"
}


# ════════════════════════════════════════════════════════════
# STEP 7 — POST-REMEDIATION VERIFICATION
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 7: Post-Remediation Verification ---" "Cyan"
$Issues = 0
$VerifyResults = [System.Collections.Generic.List[string]]::new()

$Checks = @{
    "Service: Remote Access Service"           = { Get-Service "Remote Access Service" -ErrorAction SilentlyContinue }
    "Directory: JWrapper-Remote Access"        = { Test-Path "$env:ProgramData\JWrapper-Remote Access" }
    "Directory: SystemTemp\ScreenConnect"      = { Test-Path "C:\Windows\SystemTemp\ScreenConnect" }
    "Registry: SafeBoot persistence key"       = { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service" }
    "Registry: Services entry"                 = { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service" }
    "Process: Remote_Access_Service running"   = { Get-Process "Remote_Access_Service" -ErrorAction SilentlyContinue }
}
foreach ($check in $Checks.Keys) {
    $result = & $Checks[$check]
    if ($result) {
        $Issues++
        Write-Log "  [!] STILL PRESENT: $check" "Red"
        $VerifyResults.Add("  [STILL PRESENT]  $check")
    } else {
        Write-Log "  [OK] Cleared: $check" "Green"
        $VerifyResults.Add("  [CLEAR]          $check")
    }
}


# ════════════════════════════════════════════════════════════
# CONSOLE SUMMARY
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log ("=" * 70) "DarkCyan"
Write-Log "  REMEDIATION COMPLETE" "Cyan"
Write-Log ("=" * 70) "DarkCyan"
Write-Log ""
if ($Issues -eq 0) {
    Write-Log "  STATUS : All verified indicators removed successfully." "Green"
    Write-Log "  *** REBOOT THIS MACHINE NOW ***" "Yellow"
    Write-Log ""
    Write-Log "  After rebooting, run system_check.ps1 to confirm clean." "White"
    Write-Log "  Then change ALL passwords used on this machine." "White"
} else {
    Write-Log "  STATUS : $Issues item(s) could not be removed." "Red"
    Write-Log "  Review output above. Reboot and re-run, or contact PNWC." "Yellow"
}
Write-Log ""
Write-Log "  Report saved to: $ReportFile" "Cyan"
Write-Log ("=" * 70) "DarkCyan"


# ════════════════════════════════════════════════════════════
# SAVE REPORT FILE
# ════════════════════════════════════════════════════════════
$statusText = if ($Issues -eq 0) { "ALL DETECTED ITEMS REMOVED -- Reboot required to complete cleanup" }
              else               { "INCOMPLETE -- $Issues item(s) could not be removed, see details below" }

$divider = "=" * 70

$reportContent = @"
$divider
  PNWC REMEDIATION REPORT
  JWrapper / ScreenConnect Campaign
$divider
  Prepared by : Pacific Northwest Computers
  Phone       : 360-624-7379
  Email       : jon@pnwcomputers.com
$divider

  ##############################################################
  ##                                                          ##
  ##   PLEASE EMAIL THIS REPORT TO: jon@pnwcomputers.com     ##
  ##                                                          ##
  ##   Copy the entire contents of this file and email to:   ##
  ##     jon@pnwcomputers.com                                 ##
  ##                                                          ##
  ##   Suggested subject line:                                ##
  ##     Remediation Report - $env:COMPUTERNAME               ##
  ##                                                          ##
  ##############################################################

$divider
REMEDIATION DETAILS
$divider
  Date/Time  : $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')
  Computer   : $env:COMPUTERNAME
  OS         : $((Get-WmiObject Win32_OperatingSystem).Caption)
  Ran By     : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
  Report     : $ReportFile
$divider
OVERALL STATUS:  $statusText
$divider
  Items removed  : $($RemovedItems.Count)
  Items failed   : $($FailedItems.Count)
  Not found      : $($NotFoundItems.Count)
$divider

"@

$reportContent += @"
$divider
ITEMS SUCCESSFULLY REMOVED
$divider

"@
if ($RemovedItems.Count -gt 0) {
    $reportContent += ($RemovedItems | Out-String)
} else {
    $reportContent += "  None -- no items matched this run.`n"
}

$reportContent += @"

$divider
ITEMS THAT FAILED TO REMOVE  (may need manual attention)
$divider

"@
if ($FailedItems.Count -gt 0) {
    $reportContent += ($FailedItems | Out-String)
} else {
    $reportContent += "  None -- no removal failures.`n"
}

$reportContent += @"

$divider
ITEMS NOT FOUND  (already clean or removed by a prior run)
$divider

"@
if ($NotFoundItems.Count -gt 0) {
    $reportContent += ($NotFoundItems | Out-String)
} else {
    $reportContent += "  None`n"
}

$reportContent += @"

$divider
POST-REMEDIATION VERIFICATION RESULTS
$divider

$($VerifyResults | Out-String)
$divider
REQUIRED NEXT STEPS
$divider

  1. REBOOT this machine immediately
  2. After reboot, run system_check.ps1 to verify clean state
  3. Change ALL passwords used on this machine since March 30, 2026
       Priority: email, banking, QuickBooks, business portals, cloud services
  4. Enable Multi-Factor Authentication (MFA) on all accounts
  5. Review bank / financial accounts for unauthorized transactions
  6. Block at your router or firewall:
       IP: 147.45.218.0
       IP: 91.215.85.219
       IP: 147.45.218.13
       Domain: gqpplgq2g.anondns.net

$divider
CONTACT PNWC FOR ASSISTANCE
$divider
  Pacific Northwest Computers
  Jon Pienkowski -- CompTIA A+ Certified
  Phone : 360-624-7379
  Email : jon@pnwcomputers.com

$divider
FULL REMEDIATION ACTION LOG
$divider

$($ActionLog | Out-String)

$divider
  ##############################################################
  ##   PLEASE EMAIL THIS REPORT TO: jon@pnwcomputers.com     ##
  ##   Subject: Remediation Report - $env:COMPUTERNAME        ##
  ##############################################################
$divider
"@

try {
    $reportContent | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host "  REPORT SAVED SUCCESSFULLY" -ForegroundColor Green
    Write-Host ""
    Write-Host "  File  : $ReportFile" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  *** PLEASE EMAIL THIS FILE TO jon@pnwcomputers.com ***" -ForegroundColor Yellow
    Write-Host "  Subject: Remediation Report - $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host ""
    Start-Process notepad.exe -ArgumentList $ReportFile
} catch {
    Write-Host "  [!] Could not save report: $($_.Exception.Message)" -ForegroundColor Red
}

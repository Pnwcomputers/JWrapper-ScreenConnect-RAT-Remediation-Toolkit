<#
.SYNOPSIS
    Comprehensive Remediation for JWrapper/ScreenConnect Dual-Stage Intrusion.
    Pacific Northwest Computers - Malware Removal Tool

.DESCRIPTION
    Kills malicious processes, removes services, scrubs registry persistence,
    purges all file system artifacts (including ClickOnce cache, VBScript
    delivery files, and SILENTCONNECT staging paths), removes firewall rules,
    flushes DNS, removes the Windows Defender .exe exclusion added by the
    SILENTCONNECT variant, and saves a full timestamped action report.

    Run system_check.ps1 FIRST to document the pre-remediation state.

.NOTES
    Author  : Pacific Northwest Computers
    Contact : jon@pnwcomputers.com | 360-624-7379
    Version : 2.2
    Updated : May 2026 -- added ClickOnce cache purge, VBScript staging files,
              SILENTCONNECT delivery artifacts, Defender exclusion removal,
              new process aliases, updated firewall block list
#>

#Requires -RunAsAdministrator
# Set UTF-8 output encoding so box-drawing characters render correctly
# Works whether launched via RUN_ME.bat (chcp 65001) or directly from PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
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

# Helper: takeown + icacls + Remove-Item with logging
function Remove-LockedPath {
    param([string]$Path, [string]$Label)
    Write-Log "  [X] Purging: $Path" "Red"
    try {
        takeown /F $Path /R /D Y 2>&1 | Out-Null
        icacls $Path /grant administrators:F /T /Q 2>&1 | Out-Null
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-Log "  [OK] Removed: $Path" "Green"
        Log-Removed $Label
    } catch {
        Write-Log "  [!] Could not fully remove $Path : $($_.Exception.Message)" "Red"
        Log-Failed "$Label (may require reboot -- item may be in use)"
    }
}

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
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
    "Remote_Access_Service",
    "Remote Access Service",        # space-variant alias (confirmed in ETL traces)
    "Remote_Access_Configure",
    "Remote_Access_Launcher",
    "Remote_AccessWinLauncher",     # JWrapper Windows launcher component (v2.2 addition)
    "SimpleService",
    "StopSimpleGatewayService",
    "ScreenConnect.WindowsClient",
    "ScreenConnect.WindowsFileManager",
    "WindowsBackstageShell",
    "rqe"
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
# Kill JWrapper java instances (path-filtered to avoid terminating legitimate Java)
Get-Process -Name "java" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*JWrapper*" } | ForEach-Object {
        Write-Log "  [!] Killing JWrapper java.exe  PID: $($_.Id)  Path: $($_.Path)" "Red"
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
foreach ($rk in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)) {
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

# Primary installation directories
$PrimaryPaths = [System.Collections.Generic.List[string]]::new()
$PrimaryPaths.Add("$env:ProgramData\JWrapper-Remote Access")
$PrimaryPaths.Add("C:\Windows\SystemTemp\ScreenConnect")
$PrimaryPaths.Add("$env:TEMP\ScreenConnect")
$PrimaryPaths.Add("C:\Windows\Temp\ScreenConnect")
foreach ($base in @("C:\Program Files (x86)","C:\Program Files")) {
    Get-ChildItem -Path $base -Filter "ScreenConnect Client*" -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $PrimaryPaths.Add($_.FullName) }
}
foreach ($path in $PrimaryPaths) {
    if (Test-Path $path) {
        Remove-LockedPath -Path $path -Label "Directory: $path"
    } else {
        Write-Log "  [--] Not found: $path" "DarkGray"
        Log-NotFound "Directory: $path"
    }
}

# ClickOnce cache -- remove ScreenConnect entries per-user (v2.2 addition)
Write-Log "  [*] Scanning ClickOnce cache for ScreenConnect artifacts..." "Yellow"
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $coPath = Join-Path $_.FullName "AppData\Local\Apps\2.0"
    if (Test-Path $coPath) {
        # Target directories containing the campaign assembly token or ScreenConnect binaries
        Get-ChildItem -Path $coPath -Recurse -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*27fa83f1ad328157*" -or $_.Name -like "*420d02d3849b7992*" } |
            ForEach-Object {
                Remove-LockedPath -Path $_.FullName -Label "ClickOnce cache dir (campaign token): $($_.FullName)"
            }
        # Also check for ScreenConnect executables directly in the cache
        Get-ChildItem -Path $coPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "ScreenConnect.*" -and $_.Extension -eq ".exe" } |
            ForEach-Object {
                $scDir = $_.Directory.FullName
                if (Test-Path $scDir) {
                    Remove-LockedPath -Path $scDir -Label "ClickOnce ScreenConnect dir: $scDir"
                }
            }
    }
}

# SILENTCONNECT variant staging files (v2.2 addition)
$StagingFiles = @(
    "C:\Windows\Temp\FileR.txt",                          # C# payload staging file
    "C:\Temp\ScreenConnect.ClientSetup.msi",              # MSI staging path
    "$env:USERPROFILE\Downloads\rq.msi",
    "$env:USERPROFILE\Downloads\rqe.exe",
    "$env:PUBLIC\Downloads\rq.msi",
    "$env:PUBLIC\Downloads\rqe.exe"
)
foreach ($f in $StagingFiles) {
    if (Test-Path $f) {
        Write-Log "  [X] Removing staging file: $f" "Red"
        Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $f)) {
            Write-Log "  [OK] Removed: $f" "Green"
            Log-Removed "File: $f"
        } else {
            Log-Failed "File: $f"
        }
    } else {
        Log-NotFound "File: $f"
    }
}

# VBScript delivery files in common locations (v2.2 addition)
$VbsPatterns = @(
    "$env:USERPROFILE\Downloads\E-INVITE.vbs",
    "$env:USERPROFILE\Downloads\Proposal-*.vbs",
    "$env:USERPROFILE\Downloads\*Trans.vbs",
    "$env:PUBLIC\Downloads\E-INVITE.vbs",
    "$env:TEMP\*.vbs",
    "C:\Windows\Temp\*.vbs"
)
foreach ($pat in $VbsPatterns) {
    Get-Item -Path $pat -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "  [X] Removing VBScript delivery file: $($_.FullName)" "Red"
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        Log-Removed "VBScript lure: $($_.FullName)"
    }
}

# e-Signature lure files
foreach ($pat in @(
    "$env:USERPROFILE\Downloads\e-Signature*.exe",
    "$env:PUBLIC\Downloads\e-Signature*.exe",
    "$env:TEMP\e-Signature*.exe",
    "C:\Windows\Temp\e-Signature*.exe"
)) {
    Get-Item -Path $pat -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "  [X] Removing lure file: $($_.FullName)" "Red"
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        Log-Removed "Lure file: $($_.FullName)"
    }
}

# SCR dropper files
Get-ChildItem "C:\Windows\SystemTemp\" -Filter "*.scr" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log "  [X] Removing .scr dropper: $($_.FullName)" "Red"
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    Log-Removed "SCR File: $($_.FullName)"
}

# MMSOFT Design Pulseway staging dir -- only remove if no legitimate Pulseway install present
$pulsewayInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Pulseway*" } | Select-Object -First 1
$pulsewayPath = "$env:APPDATA\MMSOFT Design\Pulseway\working"
if ((Test-Path $pulsewayPath) -and (-not $pulsewayInstalled)) {
    Write-Log "  [X] Removing Pulseway staging directory (no legitimate install found): $pulsewayPath" "Red"
    Remove-LockedPath -Path $pulsewayPath -Label "Pulseway staging dir (attacker-staged, no legitimate install): $pulsewayPath"
} elseif (Test-Path $pulsewayPath) {
    Write-Log "  [--] Pulseway directory found but legitimate Pulseway install detected -- skipping" "DarkGray"
    Log-NotFound "Pulseway staging dir (skipped -- legitimate install present)"
}


# ════════════════════════════════════════════════════════════
# STEP 5 — FIREWALL RULES
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 5: Removing Malicious Firewall Rules & Adding C2 Blocks ---" "Cyan"

# Remove any firewall rules created by the malware
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Remote Access*" -or $_.DisplayName -like "*ScreenConnect*" -or $_.DisplayName -like "*JWrapper*" } |
    ForEach-Object {
        Write-Log "  [X] Removing malware firewall rule: $($_.DisplayName)" "Red"
        Remove-NetFirewallRule -DisplayName $_.DisplayName -ErrorAction SilentlyContinue
        Log-Removed "Firewall Rule: $($_.DisplayName)"
    }

# Add outbound block rules for all known C2 IPs
$C2BlockIPs = @{
    "147.45.218.0"   = "JWrapper C2 primary relay"
    "91.215.85.219"  = "JWrapper C2 redundant relay"
    "147.45.218.13"  = "JWrapper C2 redundant relay"
    "15.204.131.77"  = "ScreenConnect C2 relay (instance-sis2tc) -- April 2026 campaign"
    "147.28.146.148" = "ScreenConnect C2 relay (instance-fc5xev) -- 2024 campaign wave"
    "86.38.225.59"   = "bumptobabeco.top -- SILENTCONNECT delivery server, Lithuania"
}
foreach ($ip in $C2BlockIPs.Keys) {
    $ruleName = "PNWC_Block_C2_$($ip.Replace('.','_'))"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        try {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound -Action Block `
                -RemoteAddress $ip `
                -Protocol Any `
                -Enabled True `
                -Description "PNWC Remediation v2.2 -- Block $($C2BlockIPs[$ip])" `
                -ErrorAction Stop | Out-Null
            Write-Log "  [OK] Added outbound block rule for: $ip ($($C2BlockIPs[$ip]))" "Green"
            Log-Removed "Firewall block added for C2 IP: $ip"
        } catch {
            Write-Log "  [!] Could not add block rule for $ip : $($_.Exception.Message)" "Red"
            Log-Failed "Firewall block for: $ip"
        }
    } else {
        Write-Log "  [--] Block rule already exists for: $ip" "DarkGray"
    }
}


# ════════════════════════════════════════════════════════════
# STEP 6 — DNS FLUSH
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 6: Flushing DNS Cache ---" "Cyan"
try {
    Clear-DnsClientCache -ErrorAction Stop
    Write-Log "  [OK] DNS cache flushed (removes cached resolution of C2 domains)" "Green"
    Log-Removed "DNS Cache (flushed)"
} catch {
    Write-Log "  [!] DNS flush failed: $($_.Exception.Message)" "Red"
    Log-Failed "DNS Cache flush"
}


# ════════════════════════════════════════════════════════════
# STEP 7 — WINDOWS DEFENDER EXCLUSION REMOVAL (NEW v2.2)
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 7: Removing Windows Defender Exclusions Added by Malware ---" "Cyan"
# SILENTCONNECT adds an ExclusionExtension for .exe during delivery
# to prevent Defender from scanning the ScreenConnect installer
try {
    $currentExclusions = (Get-MpPreference -ErrorAction Stop).ExclusionExtension
    if ($currentExclusions -and $currentExclusions -contains ".exe") {
        Remove-MpPreference -ExclusionExtension ".exe" -ErrorAction Stop
        Write-Log "  [OK] Removed Defender .exe extension exclusion (added by SILENTCONNECT during delivery)" "Green"
        Log-Removed "Windows Defender ExclusionExtension: .exe"
    } else {
        Write-Log "  [--] No .exe Defender exclusion found" "DarkGray"
        Log-NotFound "Defender .exe exclusion (not present)"
    }
} catch {
    Write-Log "  [!] Could not check/remove Defender exclusions: $($_.Exception.Message)" "Red"
    Log-Failed "Defender exclusion removal"
}


# ════════════════════════════════════════════════════════════
# STEP 8 — POST-REMEDIATION VERIFICATION
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log "--- STEP 8: Post-Remediation Verification ---" "Cyan"
$Issues = 0
$VerifyResults = [System.Collections.Generic.List[string]]::new()

$Checks = @{
    "Service: Remote Access Service"           = { Get-Service "Remote Access Service" -ErrorAction SilentlyContinue }
    "Directory: JWrapper-Remote Access"        = { Test-Path "$env:ProgramData\JWrapper-Remote Access" }
    "Directory: SystemTemp\ScreenConnect"      = { Test-Path "C:\Windows\SystemTemp\ScreenConnect" }
    "Registry: SafeBoot persistence key"       = { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service" }
    "Registry: Services entry"                 = { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service" }
    "Process: Remote_Access_Service running"   = { Get-Process "Remote_Access_Service" -ErrorAction SilentlyContinue }
    "File: SILENTCONNECT staging FileR.txt"    = { Test-Path "C:\Windows\Temp\FileR.txt" }
    "Defender: .exe exclusion present"         = { (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionExtension -contains ".exe" }
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

# Check if any ClickOnce campaign tokens remain
$clickOnceClean = $true
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $coPath = Join-Path $_.FullName "AppData\Local\Apps\2.0"
    if (Test-Path $coPath) {
        $remaining = Get-ChildItem -Path $coPath -Recurse -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*27fa83f1ad328157*" -or $_.Name -like "*420d02d3849b7992*" }
        if ($remaining) {
            $clickOnceClean = $false
            $Issues++
            $VerifyResults.Add("  [STILL PRESENT]  ClickOnce campaign token dirs in: $coPath")
            Write-Log "  [!] STILL PRESENT: ClickOnce campaign dirs in $coPath" "Red"
        }
    }
}
if ($clickOnceClean) {
    $VerifyResults.Add("  [CLEAR]          ClickOnce cache (no campaign tokens found)")
    Write-Log "  [OK] Cleared: ClickOnce cache" "Green"
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
  JWrapper / ScreenConnect Campaign (SILENTCONNECT / Medusa IAB Variant)
$divider
  Prepared by : Pacific Northwest Computers
  Phone       : 360-624-7379
  Email       : jon@pnwcomputers.com
  Tool ver    : 2.2
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
ITEMS THAT FAILED TO REMOVE  (may need manual attention or reboot)
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

  BLOCK AT YOUR ROUTER OR FIREWALL (in addition to Windows rules added above):
    # JWrapper C2 relays
    IP: 147.45.218.0
    IP: 91.215.85.219
    IP: 147.45.218.13
    # ScreenConnect campaign relays (field-confirmed)
    IP: 15.204.131.77
    IP: 147.28.146.148
    # SILENTCONNECT delivery infrastructure
    IP: 86.38.225.59
    # Dynamic DNS
    Domain: gqpplgq2g.anondns.net
    Domain: instance-sis2tc-relay.screenconnect.com
    Domain: instance-fc5xev-relay.screenconnect.com
    Domain: bumptobabeco.top
    Domain: imansport.ir
    Domain: solpru.com

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

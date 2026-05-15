<#
.SYNOPSIS
    JWrapper / ScreenConnect Intrusion Detection Checker
    Pacific Northwest Computers - Pre-Remediation Assessment Tool

.DESCRIPTION
    Non-destructive detection script. Makes NO changes to the system.
    Run this BEFORE executing Fix.ps1 to document what is present.
    A timestamped report is saved to the same folder as this script.

.NOTES
    Author  : Pacific Northwest Computers
    Contact : jon@pnwcomputers.com | 360-624-7379
    Version : 1.0
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

# ── Output Setup ─────────────────────────────────────────────────────────────
$Timestamp    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile      = Join-Path $ScriptDir "PNWC_Detection_Report_$Timestamp.txt"
$FindingCount = 0
$CriticalHits = 0
$Results      = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    $Results.Add($Message)
}

function Write-Section {
    param([string]$Title)
    $line = "=" * 72
    Write-Log ""
    Write-Log $line "DarkCyan"
    Write-Log "  $Title" "Cyan"
    Write-Log $line "DarkCyan"
}

function Write-Hit {
    param([string]$Label, [string]$Detail, [string]$Severity = "HIGH")
    $script:FindingCount++
    if ($Severity -eq "CRITICAL") { $script:CriticalHits++ }
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Yellow" }
        "MEDIUM"   { "Cyan" }
        default    { "White" }
    }
    Write-Log "  [!] [$Severity] $Label" $color
    Write-Log "      $Detail" "Gray"
}

function Write-Clear {
    param([string]$Label)
    Write-Log "  [OK] $Label" "DarkGreen"
}

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Log "================================================================" "DarkCyan"
Write-Log "   PNWC Intrusion Detection Checker - JWrapper / ScreenConnect  " "Cyan"
Write-Log "   Pacific Northwest Computers | jon@pnwcomputers.com           " "Gray"
Write-Log "   ** READ-ONLY: This script makes NO changes to the system **  " "Green"
Write-Log "================================================================" "DarkCyan"
Write-Log ""
Write-Log "  Scan started : $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')" "Gray"
Write-Log "  Computer     : $env:COMPUTERNAME" "Gray"
Write-Log "  Running as   : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" "Gray"
Write-Log "  Report file  : $LogFile" "Gray"
Write-Log ""


# ════════════════════════════════════════════════════════════════════
# SECTION 1 — MALICIOUS PROCESSES
# ════════════════════════════════════════════════════════════════════
Write-Section "1. RUNNING MALICIOUS PROCESSES"

$MaliciousProcesses = @{
    "Remote_Access_Service"            = "JWrapper/SimpleHelp RAT main service process"
    "SimpleService"                    = "JWrapper SafeBoot persistence manager"
    "StopSimpleGatewayService"         = "JWrapper RAT management utility (active session indicator)"
    "Remote_Access_Configure"          = "JWrapper RAT reconfiguration tool"
    "Remote_Access_Launcher"           = "JWrapper RAT launcher"
    "ScreenConnect.WindowsClient"      = "ScreenConnect Stage-1 remote access client"
    "ScreenConnect.WindowsFileManager" = "ScreenConnect file transfer component"
    "WindowsBackstageShell"            = "ScreenConnect remote shell component"
    "rqe"                              = "ScreenConnect DotNetRunner dropper component"
}

$FoundProcs = $false
foreach ($proc in $MaliciousProcesses.Keys) {
    $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($running) {
        $FoundProcs = $true
        $pids = ($running | Select-Object -ExpandProperty Id) -join ", "
        Write-Hit -Label "Active Process: $proc" `
                  -Detail "$($MaliciousProcesses[$proc]) | PID(s): $pids" `
                  -Severity "CRITICAL"
    }
}

# Also check for any JWrapper java processes
$JavaProcs = Get-Process -Name "java" -ErrorAction SilentlyContinue | 
    Where-Object { $_.Path -like "*JWrapper*" -or $_.MainWindowTitle -like "*Remote Access*" }
if ($JavaProcs) {
    foreach ($jp in $JavaProcs) {
        Write-Hit -Label "Suspicious Java Process" `
                  -Detail "java.exe PID $($jp.Id) - Path: $($jp.Path)" `
                  -Severity "CRITICAL"
        $FoundProcs = $true
    }
}

if (-not $FoundProcs) { Write-Clear "No malicious processes detected in memory" }


# ════════════════════════════════════════════════════════════════════
# SECTION 2 — WINDOWS SERVICES
# ════════════════════════════════════════════════════════════════════
Write-Section "2. MALICIOUS WINDOWS SERVICES"

# Exact known bad service name
$ExactServices = @("Remote Access Service")
$FoundSvcs = $false

foreach ($svc in $ExactServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        $FoundSvcs = $true
        Write-Hit -Label "Malicious Service Registered: '$svc'" `
                  -Detail "Status: $($s.Status) | StartType: $($s.StartType)" `
                  -Severity "CRITICAL"
    }
}

# Wildcard sweep for ScreenConnect services
$SCServices = Get-Service -Name "ScreenConnect Client*" -ErrorAction SilentlyContinue
if ($SCServices) {
    foreach ($s in $SCServices) {
        $FoundSvcs = $true
        Write-Hit -Label "ScreenConnect Service: '$($s.Name)'" `
                  -Detail "Status: $($s.Status) | StartType: $($s.StartType)" `
                  -Severity "CRITICAL"
    }
}

# Check WMI for service binary paths pointing to known malware locations
$WmiServices = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | 
    Where-Object { $_.PathName -like "*JWrapper*" -or $_.PathName -like "*JWrapper-Remote*" }
if ($WmiServices) {
    foreach ($s in $WmiServices) {
        $FoundSvcs = $true
        Write-Hit -Label "WMI Service with JWrapper Binary Path: '$($s.Name)'" `
                  -Detail "Binary: $($s.PathName)" `
                  -Severity "CRITICAL"
    }
}

if (-not $FoundSvcs) { Write-Clear "No malicious services found in SCM or WMI" }


# ════════════════════════════════════════════════════════════════════
# SECTION 3 — REGISTRY PERSISTENCE
# ════════════════════════════════════════════════════════════════════
Write-Section "3. REGISTRY PERSISTENCE KEYS"

$RegChecks = @{
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service" = 
        "CRITICAL - SafeBoot persistence: RAT survives Safe Mode reboots"
    "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service" = 
        "CRITICAL - RAT registered as Windows service"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Remote Access" = 
        "HIGH - RAT registered in Add/Remove Programs"
}

$FoundReg = $false
foreach ($key in $RegChecks.Keys) {
    if (Test-Path $key) {
        $FoundReg = $true
        $severity = if ($RegChecks[$key] -like "CRITICAL*") { "CRITICAL" } else { "HIGH" }
        Write-Hit -Label "Registry Key Present" `
                  -Detail "$key | $($RegChecks[$key])" `
                  -Severity $severity
    }
}

# Check for any ScreenConnect-related run keys
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
            $_.Value -like "*JWrapper*" -or
            $_.Value -like "*ScreenConnect*" -or
            $_.Value -like "*Remote Access*" -or
            $_.Value -like "*SimpleHelp*" -or
            $_.Value -like "*SimpleGateway*"
        } | ForEach-Object {
            $FoundReg = $true
            Write-Hit -Label "Autorun Entry in $runkey" `
                      -Detail "Name: $($_.Name) | Value: $($_.Value)" `
                      -Severity "CRITICAL"
        }
    }
}

# Check Scheduled Tasks
$Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskPath -like "*JWrapper*" -or $_.TaskName -like "*Remote Access*" -or
    $_.TaskName -like "*ScreenConnect*" -or $_.TaskName -like "*SimpleHelp*" -or
    ($_.Actions | Where-Object { $_.Execute -like "*JWrapper*" -or $_.Execute -like "*ScreenConnect*" })
}
if ($Tasks) {
    foreach ($t in $Tasks) {
        $FoundReg = $true
        Write-Hit -Label "Malicious Scheduled Task: '$($t.TaskName)'" `
                  -Detail "Path: $($t.TaskPath) | State: $($t.State)" `
                  -Severity "HIGH"
    }
}

if (-not $FoundReg) { Write-Clear "No malicious registry persistence keys or scheduled tasks found" }


# ════════════════════════════════════════════════════════════════════
# SECTION 4 — FILE SYSTEM ARTIFACTS
# ════════════════════════════════════════════════════════════════════
Write-Section "4. FILE SYSTEM ARTIFACTS"

$FoundFiles = $false

# High-confidence known paths
$KnownPaths = @{
    "$env:ProgramData\JWrapper-Remote Access"                                       = "CRITICAL - JWrapper RAT installation directory"
    "C:\Windows\SystemTemp\ScreenConnect"                                           = "CRITICAL - ScreenConnect staging directory (includes original dropper)"
    "$env:TEMP\ScreenConnect"                                                        = "HIGH - ScreenConnect temp artifacts"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\serviceconfig.xml"  = "CRITICAL - RAT live C2 configuration file"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\alertsdb"           = "HIGH - Encrypted session activity database"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\verified"           = "HIGH - C2 connectivity verification file"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\StopSimpleGatewayService.exe" = "HIGH - RAT management utility"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\Remote_Access_Service.exe"    = "CRITICAL - RAT main service executable"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\SimpleService.exe"            = "CRITICAL - RAT SafeBoot persistence binary"
}

foreach ($p in $KnownPaths.Keys) {
    if (Test-Path $p) {
        $FoundFiles = $true
        $severity = if ($KnownPaths[$p] -like "CRITICAL*") { "CRITICAL" } else { "HIGH" }
        $item = Get-Item $p -ErrorAction SilentlyContinue
        $detail = $KnownPaths[$p]
        if ($item -and -not $item.PSIsContainer) {
            $hash = (Get-FileHash $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $detail += " | Size: $([math]::Round($item.Length/1KB,1)) KB"
            if ($hash) { $detail += " | SHA256: $($hash.Substring(0,16))..." }
        }
        Write-Hit -Label "Path Exists: $p" -Detail $detail -Severity $severity
    }
}

# Scan Program Files for any ScreenConnect client installs
$SCInstallDirs = @("C:\Program Files (x86)", "C:\Program Files")
foreach ($base in $SCInstallDirs) {
    if (Test-Path $base) {
        Get-ChildItem -Path $base -Filter "ScreenConnect Client*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $FoundFiles = $true
            Write-Hit -Label "ScreenConnect Install Directory Found" `
                      -Detail $_.FullName `
                      -Severity "HIGH"
        }
    }
}

# Look for the original e-signature dropper in common locations
$DropperPatterns = @(
    "$env:USERPROFILE\Downloads\e-Signature*.exe",
    "$env:USERPROFILE\Desktop\e-Signature*.exe",
    "$env:TEMP\e-Signature*.exe",
    "C:\Windows\Temp\e-Signature*.exe",
    "C:\Windows\SystemTemp\e-Signature*.exe",
    "$env:PUBLIC\Downloads\e-Signature*.exe"
)
foreach ($pattern in $DropperPatterns) {
    Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        $FoundFiles = $true
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        Write-Hit -Label "Original Dropper Found: $($_.Name)" `
                  -Detail "Path: $($_.FullName) | SHA256: $hash" `
                  -Severity "CRITICAL"
    }
}

# Look for .scr dropper files in SystemTemp
Get-ChildItem "C:\Windows\SystemTemp\" -Filter "*.scr" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $FoundFiles = $true
    Write-Hit -Label "Suspicious .SCR File (possible JWrapper dropper)" `
              -Detail $_.FullName `
              -Severity "HIGH"
}

if (-not $FoundFiles) { Write-Clear "No malicious file system artifacts detected" }


# ════════════════════════════════════════════════════════════════════
# SECTION 5 — ACTIVE NETWORK CONNECTIONS TO C2
# ════════════════════════════════════════════════════════════════════
Write-Section "5. ACTIVE NETWORK CONNECTIONS TO C2 SERVERS"

# Known C2 IPs and port from this campaign
$C2Targets = @{
    "147.45.218.0"   = "JWrapper/SimpleHelp C2 relay - primary"
    "91.215.85.219"  = "JWrapper/SimpleHelp C2 relay - redundant"
    "147.45.218.13"  = "JWrapper/SimpleHelp C2 relay - redundant"
}
$C2Domain = "gqpplgq2g.anondns.net"  # ScreenConnect relay

$FoundNet = $false
$NetConnections = Get-NetTCPConnection -State Established, TimeWait, CloseWait -ErrorAction SilentlyContinue

foreach ($ip in $C2Targets.Keys) {
    $conns = $NetConnections | Where-Object { $_.RemoteAddress -eq $ip }
    if ($conns) {
        foreach ($c in $conns) {
            $FoundNet = $true
            $owning = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name
            Write-Hit -Label "LIVE C2 CONNECTION DETECTED" `
                      -Detail "Remote: $($c.RemoteAddress):$($c.RemotePort) | Local port: $($c.LocalPort) | PID: $($c.OwningProcess) ($owning) | $($C2Targets[$ip])" `
                      -Severity "CRITICAL"
        }
    }
}

# Check port 8041 (ScreenConnect relay)
$sc8041 = $NetConnections | Where-Object { $_.RemotePort -eq 8041 }
if ($sc8041) {
    foreach ($c in $sc8041) {
        $FoundNet = $true
        $owning = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name
        Write-Hit -Label "LIVE SCREENCONNECT C2 CONNECTION (port 8041)" `
                  -Detail "Remote: $($c.RemoteAddress):$($c.RemotePort) | PID: $($c.OwningProcess) ($owning)" `
                  -Severity "CRITICAL"
    }
}

# Check for anondns.net in active DNS cache
$DnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
    Where-Object { $_.Entry -like "*anondns.net*" -or $_.Entry -like "*gqpplgq2g*" }
if ($DnsCache) {
    $FoundNet = $true
    foreach ($d in $DnsCache) {
        Write-Hit -Label "C2 Domain in DNS Cache: $($d.Entry)" `
                  -Detail "Data: $($d.Data) | TTL: $($d.TimeToLive)s | This system recently resolved the ScreenConnect C2 domain" `
                  -Severity "HIGH"
    }
}

# Check all established connections on port 443 by any JWrapper-related process
$JWProcesses = @("Remote_Access_Service","SimpleService","java")
foreach ($pname in $JWProcesses) {
    $proc = Get-Process -Name $pname -ErrorAction SilentlyContinue
    if ($proc) {
        foreach ($p in $proc) {
            $conns443 = $NetConnections | Where-Object { $_.OwningProcess -eq $p.Id -and $_.RemotePort -eq 443 }
            foreach ($c in $conns443) {
                $FoundNet = $true
                Write-Hit -Label "Port 443 C2 beacon from $pname (PID $($p.Id))" `
                          -Detail "Connecting to $($c.RemoteAddress):443 -- likely JWrapper C2 communication" `
                          -Severity "CRITICAL"
            }
        }
    }
}

if (-not $FoundNet) { Write-Clear "No active connections to known C2 addresses or suspicious outbound beacons" }


# ════════════════════════════════════════════════════════════════════
# SECTION 6 — LOG FILE EVIDENCE
# ════════════════════════════════════════════════════════════════════
Write-Section "6. JWRAPPER / SIMPLEHELP LOG EVIDENCE"

$LogDir = "$env:ProgramData\JWrapper-Remote Access\logs"
$FoundLogs = $false

if (Test-Path $LogDir) {
    $LogFiles = Get-ChildItem -Path $LogDir -Filter "*.log" -ErrorAction SilentlyContinue
    if ($LogFiles) {
        $FoundLogs = $true
        $newestLog = $LogFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-Hit -Label "JWrapper Log Directory Present" `
                  -Detail "$LogDir | $($LogFiles.Count) log files found | Most recent: $($newestLog.Name) ($($newestLog.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))" `
                  -Severity "HIGH"

        # Look for active session indicators in the newest logs
        $RecentLogs = $LogFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 3
        foreach ($log in $RecentLogs) {
            $content = Get-Content $log.FullName -Tail 20 -ErrorAction SilentlyContinue
            if ($content -match "PollThread|SimpleGatewayService|Claiming ID|Loaded SecMsg") {
                Write-Hit -Label "Active C2 Session Evidence in Log: $($log.Name)" `
                          -Detail "Log contains recent C2 polling/connection entries (last modified $($log.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" `
                          -Severity "CRITICAL"
            }
        }
    }
}

# Check for GenericUpdater logs
$GULogs = Get-ChildItem -Path "$env:ProgramData\JWrapper-Remote Access\logs" -Filter "GenericUpdater*.log" -ErrorAction SilentlyContinue
if ($GULogs) {
    $newest = $GULogs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Hit -Label "GenericUpdater Logs Present ($($GULogs.Count) files)" `
              -Detail "Most recent auto-update attempt: $($newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) | Confirms RAT was actively phoning home for updates" `
              -Severity "HIGH"
    $FoundLogs = $true
}

if (-not $FoundLogs) { Write-Clear "No JWrapper/SimpleHelp log directory or log files found" }


# ════════════════════════════════════════════════════════════════════
# SECTION 7 — SCREENCONNECT ARTIFACTS
# ════════════════════════════════════════════════════════════════════
Write-Section "7. SCREENCONNECT SPECIFIC ARTIFACTS"

$SCPaths = @{
    "C:\Windows\SystemTemp\ScreenConnect"                                             = "CRITICAL - ScreenConnect staging/working directory"
    "$env:ProgramData\ScreenConnect Client"                                           = "HIGH - ScreenConnect client data"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\system.config"                  = "CRITICAL - Contains C2 relay domain (gqpplgq2g.anondns.net:8041)"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\app.config"                     = "CRITICAL - All 13 stealth settings (no tray, no banner, fully invisible)"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\rq.msi"                         = "CRITICAL - ScreenConnect installer dropped by initial lure"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\rqe.exe"                        = "CRITICAL - Custom DotNetRunner SC component"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\ScreenConnect.WindowsAuthenticationPackage.dll" = "HIGH - Windows credential provider DLL"
}

$FoundSC = $false
foreach ($p in $SCPaths.Keys) {
    if (Test-Path $p) {
        $FoundSC = $true
        $severity = if ($SCPaths[$p] -like "CRITICAL*") { "CRITICAL" } else { "HIGH" }
        Write-Hit -Label "ScreenConnect Artifact: $(Split-Path $p -Leaf)" `
                  -Detail "$p | $($SCPaths[$p])" `
                  -Severity $severity
    }
}

# Check system.config for the specific C2 domain
$SysConfig = "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\system.config"
if (Test-Path $SysConfig) {
    $content = Get-Content $SysConfig -ErrorAction SilentlyContinue
    if ($content -match "anondns\.net") {
        Write-Hit -Label "C2 Domain Confirmed in system.config" `
                  -Detail "gqpplgq2g.anondns.net found in ScreenConnect relay configuration" `
                  -Severity "CRITICAL"
    }
}

if (-not $FoundSC) { Write-Clear "No ScreenConnect-specific artifacts found" }


# ════════════════════════════════════════════════════════════════════
# SECTION 8 — WINDOWS EVENT LOG INDICATORS
# ════════════════════════════════════════════════════════════════════
Write-Section "8. WINDOWS EVENT LOG INDICATORS"

$FoundEvents = $false

# Service install events (7045 = new service installed)
$SvcInstallEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    Id        = 7045
    StartTime = (Get-Date).AddDays(-60)
} -ErrorAction SilentlyContinue | Where-Object { 
    $_.Message -like "*Remote Access*" -or 
    $_.Message -like "*ScreenConnect*" -or 
    $_.Message -like "*SimpleHelp*" -or
    $_.Message -like "*JWrapper*"
}
if ($SvcInstallEvents) {
    $FoundEvents = $true
    foreach ($ev in $SvcInstallEvents) {
        Write-Hit -Label "Event 7045: Service Installed" `
                  -Detail "$($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | $($ev.Message.Split("`n")[0])" `
                  -Severity "HIGH"
    }
}

# PowerShell script block logging — look for suspicious executions
$PSEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = (Get-Date).AddDays(-60)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*JWrapper*" -or 
    $_.Message -like "*SimpleGateway*" -or
    $_.Message -like "*ScreenConnect*" -or
    $_.Message -like "*SafeBoot*"
} | Select-Object -First 5
if ($PSEvents) {
    $FoundEvents = $true
    foreach ($ev in $PSEvents) {
        Write-Hit -Label "PowerShell Script Block (4104) - Suspicious Content" `
                  -Detail "$($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Matches JWrapper/ScreenConnect/SafeBoot patterns" `
                  -Severity "HIGH"
    }
}

# Security log: logon events from SYSTEM running unusual processes
$LogonEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = (Get-Date).AddDays(-60)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*Remote_Access_Service*" -or
    $_.Message -like "*SimpleService.exe*" -or
    $_.Message -like "*officeSH26*" -or
    $_.Message -like "*.scr*"
} | Select-Object -First 5
if ($LogonEvents) {
    $FoundEvents = $true
    foreach ($ev in $LogonEvents) {
        Write-Hit -Label "Process Creation Event (4688) - Malicious Binary" `
                  -Detail "$($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | Malicious process name in Security audit log" `
                  -Severity "HIGH"
    }
}

if (-not $FoundEvents) { 
    Write-Clear "No matching indicators in System, Security, or PowerShell event logs (last 60 days)"
    Write-Log "    Note: Event log retention may have cleared older entries" "DarkGray"
}


# ════════════════════════════════════════════════════════════════════
# SECTION 9 — INSTALLED PROGRAMS
# ════════════════════════════════════════════════════════════════════
Write-Section "9. SUSPICIOUS INSTALLED PROGRAMS"

$FoundApps = $false
$UninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$SuspiciousAppNames = @("Remote Access", "ScreenConnect", "SimpleHelp", "JWrapper")

foreach ($path in $UninstallPaths) {
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
    Where-Object { 
        $name = $_.DisplayName
        $SuspiciousAppNames | Where-Object { $name -like "*$_*" }
    } | ForEach-Object {
        $FoundApps = $true
        Write-Hit -Label "Suspicious Program in Add/Remove Programs: $($_.DisplayName)" `
                  -Detail "Version: $($_.DisplayVersion) | Install Date: $($_.InstallDate) | Publisher: $($_.Publisher)" `
                  -Severity "HIGH"
    }
}

if (-not $FoundApps) { Write-Clear "No suspicious programs found in installed programs registry" }


# ════════════════════════════════════════════════════════════════════
# SECTION 10 — FIREWALL RULES ADDED BY RAT
# ════════════════════════════════════════════════════════════════════
Write-Section "10. SUSPICIOUS FIREWALL RULES"

$FoundFW = $false
$FWRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -like "*Remote Access*" -or
    $_.DisplayName -like "*ScreenConnect*" -or
    $_.DisplayName -like "*SimpleHelp*" -or
    $_.DisplayName -like "*JWrapper*" -or
    $_.Description -like "*JWrapper*"
}
if ($FWRules) {
    foreach ($rule in $FWRules) {
        $FoundFW = $true
        Write-Hit -Label "Suspicious Firewall Rule: $($rule.DisplayName)" `
                  -Detail "Direction: $($rule.Direction) | Action: $($rule.Action) | Enabled: $($rule.Enabled)" `
                  -Severity "HIGH"
    }
}
if (-not $FoundFW) { Write-Clear "No suspicious firewall rules detected" }


# ════════════════════════════════════════════════════════════════════
# SECTION 11 — HASH VERIFICATION OF KEY EXECUTABLES
# ════════════════════════════════════════════════════════════════════
Write-Section "11. KNOWN MALWARE HASH MATCHES"

# Known SHA256 hashes from this specific campaign (PNWC confirmed)
$KnownBadHashes = @{
    "b555ceff3236a8175b48b892c1ebc4977fc82c623f3c15ed1efab0c4ac61a9b6" = "e-Signature-Key_Access_ID-MY7362HY73E.exe (initial lure/dropper)"
    "924600a3a55c196b362e82151fbc3f9dcf03dc29e6c45e0bd113d7b0d95c6850" = "rq.msi (ScreenConnect Stage-1 installer)"
    "959524efe7d4aa6a132a88daf7d1e1871fa14eae8a6025ba73ab1fb65f7e4f22" = "rqe.exe (ScreenConnect DotNetRunner)"
    "bdbdbffb37bc421edac4ac5b20c72db1c72d7f6e819e115c96cde5413146bb36" = "Remote_Access_Service.exe (JWrapper RAT service)"
    "d26b8e1ba6383b1f7749a133cfbf90e85a22a4bece9f171ed57a3d1ab7833f48" = "StopSimpleGatewayService.exe (RAT management utility)"
    "d14a1f14d6ca46bd2168b9d2acf281d8eea62d30e2869d47dd4bf0ad556fb9a2" = "SimpleService.exe (SafeBoot persistence binary)"
    "a5b8f0070201e4f26260af6a25941ea38bd7042aefd48cd68b9acf951fa99ee5" = "ScreenConnect.WindowsAuthenticationPackage.dll"
}

# Scan the known locations for any file matching these hashes
$ScanLocations = @(
    "$env:ProgramData\JWrapper-Remote Access",
    "C:\Windows\SystemTemp\ScreenConnect",
    "$env:TEMP",
    "C:\Windows\Temp",
    "$env:USERPROFILE\Downloads",
    "$env:PUBLIC\Downloads"
)

$FoundHashes = $false
foreach ($loc in $ScanLocations) {
    if (Test-Path $loc) {
        Get-ChildItem -Path $loc -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $KnownBadHashes.ContainsKey($hash.ToLower())) {
                $FoundHashes = $true
                Write-Hit -Label "KNOWN MALWARE HASH MATCH: $($_.Name)" `
                          -Detail "Path: $($_.FullName) | SHA256: $hash | Matches: $($KnownBadHashes[$hash.ToLower()])" `
                          -Severity "CRITICAL"
            }
        }
    }
}

if (-not $FoundHashes) { Write-Clear "No files matching known campaign SHA256 hashes found in scanned locations" }


# ════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════════
$line = "=" * 72
Write-Log ""
Write-Log $line "DarkCyan"
Write-Log "  SCAN SUMMARY" "Cyan"
Write-Log $line "DarkCyan"
Write-Log ""

if ($CriticalHits -gt 0) {
    Write-Log "  STATUS: *** SYSTEM IS ACTIVELY COMPROMISED ***" "Red"
    Write-Log ""
    Write-Log "  CRITICAL findings : $CriticalHits" "Red"
    Write-Log "  Total findings    : $FindingCount" "Yellow"
    Write-Log ""
    Write-Log "  IMMEDIATE ACTIONS REQUIRED:" "Red"
    Write-Log "  1. Do NOT use this machine for any sensitive activity" "Yellow"
    Write-Log "  2. Disconnect from the network if a live C2 session was found" "Yellow"
    Write-Log "  3. Run Fix.ps1 as Administrator to begin remediation" "Yellow"
    Write-Log "  4. Contact PNWC for full remediation: 360-624-7379" "Yellow"
} elseif ($FindingCount -gt 0) {
    Write-Log "  STATUS: SUSPICIOUS ARTIFACTS PRESENT - Review required" "Yellow"
    Write-Log ""
    Write-Log "  Critical findings : 0" "Green"
    Write-Log "  Total findings    : $FindingCount" "Yellow"
    Write-Log ""
    Write-Log "  Residual artifacts may remain after a prior cleanup attempt." "Yellow"
    Write-Log "  Run Fix.ps1 to clear remaining items, then re-run this script." "Yellow"
} else {
    Write-Log "  STATUS: NO INDICATORS DETECTED - System appears clean" "Green"
    Write-Log ""
    Write-Log "  Total findings    : 0" "Green"
    Write-Log ""
    Write-Log "  No traces of this specific campaign were found." "Green"
    Write-Log "  If you recently ran Fix.ps1, remediation appears complete." "Green"
}

Write-Log ""
Write-Log "  Scan completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Gray"
Write-Log "  Report saved   : $LogFile" "Gray"
Write-Log $line "DarkCyan"
Write-Log ""


# ── Save Report to Disk ────────────────────────────────────────────────────────
try {
    $header = @"
================================================================
   PNWC Intrusion Detection Report
   JWrapper / ScreenConnect Campaign - DESKTOP-30258PR Profile
   Pacific Northwest Computers | jon@pnwcomputers.com | 360-624-7379
================================================================
Scan Date  : $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')
Computer   : $env:COMPUTERNAME
OS Version : $((Get-WmiObject Win32_OperatingSystem).Caption)
Scan By    : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
================================================================

"@
    $header | Out-File -FilePath $LogFile -Encoding UTF8
    $Results | Out-File -FilePath $LogFile -Encoding UTF8 -Append
    Write-Host "  [+] Report saved to: $LogFile" -ForegroundColor Green
} catch {
    Write-Host "  [!] Could not save report to disk: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

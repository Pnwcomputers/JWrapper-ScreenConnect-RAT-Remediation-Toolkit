<#
.SYNOPSIS
    JWrapper / ScreenConnect Intrusion Detection Checker
    Pacific Northwest Computers - Pre-Remediation Assessment Tool

.DESCRIPTION
    Non-destructive detection script. Makes NO changes to the system.
    Run this BEFORE Fix.ps1 to document what is present.
    Saves a timestamped report with all findings and instructs
    the user to email it to jon@pnwcomputers.com.

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
$ReportFile    = Join-Path $ScriptDir "PNWC_Detection_Report_$Timestamp.txt"
$FindingCount  = 0
$CriticalHits  = 0
$ScreenLog     = [System.Collections.Generic.List[string]]::new()
$MaliciousHits = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Msg, [string]$Color = "White")
    Write-Host $Msg -ForegroundColor $Color
    $ScreenLog.Add($Msg)
}
function Write-Section {
    param([string]$Title)
    Write-Log ""
    Write-Log ("=" * 70) "DarkCyan"
    Write-Log "  $Title" "Cyan"
    Write-Log ("=" * 70) "DarkCyan"
}
function Write-Hit {
    param([string]$Label, [string]$Detail, [string]$Sev = "HIGH")
    $script:FindingCount++
    if ($Sev -eq "CRITICAL") { $script:CriticalHits++ }
    $col = switch ($Sev) { "CRITICAL"{"Red"} "HIGH"{"Yellow"} "MEDIUM"{"Cyan"} default{"White"} }
    Write-Log "  [!] [$Sev]  $Label" $col
    Write-Log "      $Detail" "Gray"
    $script:MaliciousHits.Add("  [$Sev]  $Label")
    $script:MaliciousHits.Add("          $Detail")
    $script:MaliciousHits.Add("")
}
function Write-Clean { param([string]$L); Write-Log "  [OK] $L" "DarkGreen" }

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Log ("=" * 70) "DarkCyan"
Write-Log "   PNWC Detection Checker - JWrapper / ScreenConnect Campaign  " "Cyan"
Write-Log "   Pacific Northwest Computers  |  jon@pnwcomputers.com        " "Gray"
Write-Log "   READ-ONLY -- This script makes NO changes to the system     " "Green"
Write-Log ("=" * 70) "DarkCyan"
Write-Log ""
Write-Log "  Scan started : $(Get-Date -Format 'dddd MMMM dd yyyy  HH:mm:ss')" "Gray"
Write-Log "  Computer     : $env:COMPUTERNAME" "Gray"
Write-Log "  Running as   : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" "Gray"
Write-Log "  Report file  : $ReportFile" "Gray"
Write-Log ""


# ════════════════════════════════════════════════════════════
# 1. PROCESSES
# ════════════════════════════════════════════════════════════
Write-Section "1. RUNNING MALICIOUS PROCESSES"
$BadProcs = @{
    "Remote_Access_Service"            = "JWrapper/SimpleHelp RAT main service"
    "SimpleService"                    = "JWrapper SafeBoot persistence manager"
    "StopSimpleGatewayService"         = "JWrapper RAT management utility"
    "Remote_Access_Configure"          = "JWrapper RAT reconfiguration tool"
    "Remote_Access_Launcher"           = "JWrapper RAT launcher"
    "ScreenConnect.WindowsClient"      = "ScreenConnect Stage-1 remote access client"
    "ScreenConnect.WindowsFileManager" = "ScreenConnect file transfer component"
    "WindowsBackstageShell"            = "ScreenConnect remote shell"
    "rqe"                              = "ScreenConnect DotNetRunner component"
}
$hit = $false
foreach ($p in $BadProcs.Keys) {
    $r = Get-Process -Name $p -ErrorAction SilentlyContinue
    if ($r) {
        $hit = $true
        Write-Hit -Label "Active Malicious Process: $p" `
                  -Detail "$($BadProcs[$p])  |  PID(s): $(($r.Id -join ', '))" -Sev "CRITICAL"
    }
}
Get-Process -Name "java" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*JWrapper*" } | ForEach-Object {
        $hit = $true
        Write-Hit -Label "JWrapper Java Process Running" `
                  -Detail "java.exe  PID: $($_.Id)  Path: $($_.Path)" -Sev "CRITICAL"
    }
if (-not $hit) { Write-Clean "No malicious processes found in memory" }


# ════════════════════════════════════════════════════════════
# 2. SERVICES
# ════════════════════════════════════════════════════════════
Write-Section "2. MALICIOUS WINDOWS SERVICES"
$hit = $false
$s = Get-Service -Name "Remote Access Service" -ErrorAction SilentlyContinue
if ($s) {
    $hit = $true
    Write-Hit -Label "Malicious Service: 'Remote Access Service'" `
              -Detail "Status: $($s.Status)  |  StartType: $($s.StartType)" -Sev "CRITICAL"
}
Get-Service -Name "ScreenConnect Client*" -ErrorAction SilentlyContinue | ForEach-Object {
    $hit = $true
    Write-Hit -Label "ScreenConnect Service: '$($_.Name)'" `
              -Detail "Status: $($_.Status)  |  StartType: $($_.StartType)" -Sev "CRITICAL"
}
Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.PathName -like "*JWrapper*" } | ForEach-Object {
        $hit = $true
        Write-Hit -Label "Service with JWrapper Binary: '$($_.Name)'" `
                  -Detail "Binary: $($_.PathName)" -Sev "CRITICAL"
    }
if (-not $hit) { Write-Clean "No malicious services found" }


# ════════════════════════════════════════════════════════════
# 3. REGISTRY PERSISTENCE
# ════════════════════════════════════════════════════════════
Write-Section "3. REGISTRY PERSISTENCE"
$hit = $false
$RegChecks = @{
    "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service" = "SafeBoot key -- RAT survives Safe Mode reboots"
    "HKLM:\SYSTEM\CurrentControlSet\Services\Remote Access Service"                 = "Service registration key"
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Remote Access"       = "Add/Remove Programs entry"
}
foreach ($k in $RegChecks.Keys) {
    if (Test-Path $k) {
        $hit = $true
        $sev = if ($k -like "*SafeBoot*" -or $k -like "*Services*") { "CRITICAL" } else { "HIGH" }
        Write-Hit -Label "Persistence Key Present" -Detail "$k  |  $($RegChecks[$k])" -Sev $sev
    }
}
foreach ($rk in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
    if (Test-Path $rk) {
        (Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Value -like "*JWrapper*" -or $_.Value -like "*ScreenConnect*" -or $_.Value -like "*Remote Access*" } |
            ForEach-Object {
                $hit = $true
                Write-Hit -Label "Autorun Entry in Run Key" `
                          -Detail "Key: $rk  |  Name: $($_.Name)  |  Value: $($_.Value)" -Sev "CRITICAL"
            }
    }
}
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -like "*Remote Access*" -or $_.TaskName -like "*ScreenConnect*" -or $_.TaskPath -like "*JWrapper*" } |
    ForEach-Object {
        $hit = $true
        Write-Hit -Label "Malicious Scheduled Task: '$($_.TaskName)'" `
                  -Detail "State: $($_.State)  |  Path: $($_.TaskPath)" -Sev "HIGH"
    }
if (-not $hit) { Write-Clean "No malicious registry keys, Run entries, or scheduled tasks found" }


# ════════════════════════════════════════════════════════════
# 4. FILE SYSTEM
# ════════════════════════════════════════════════════════════
Write-Section "4. FILE SYSTEM ARTIFACTS"
$hit = $false
$FilePaths = @{
    "$env:ProgramData\JWrapper-Remote Access"                                                                      = "JWrapper RAT installation directory"
    "C:\Windows\SystemTemp\ScreenConnect"                                                                           = "ScreenConnect staging directory"
    "$env:TEMP\ScreenConnect"                                                                                       = "ScreenConnect temp artifacts"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\serviceconfig.xml"                                 = "Live C2 configuration file"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\alertsdb"                                          = "Encrypted C2 session database"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\verified"                                          = "C2 connectivity confirmation"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\Remote_Access_Service.exe"    = "RAT main service executable"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\SimpleService.exe"            = "SafeBoot persistence binary"
    "$env:ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\StopSimpleGatewayService.exe" = "RAT management utility"
}
foreach ($p in $FilePaths.Keys) {
    if (Test-Path $p) {
        $hit = $true
        $item = Get-Item $p -ErrorAction SilentlyContinue
        $detail = $FilePaths[$p]
        if ($item -and -not $item.PSIsContainer) {
            $hash = (Get-FileHash $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $detail += "  |  Size: $([math]::Round($item.Length/1KB,1)) KB"
            if ($hash) { $detail += "  |  SHA256: $($hash.Substring(0,16))..." }
        }
        $sev = if ($p -like "*Service.exe" -or $p -like "*SimpleService*" -or $p -like "*serviceconfig*") { "CRITICAL" } else { "HIGH" }
        Write-Hit -Label "Artifact Found: $(Split-Path $p -Leaf)" -Detail "Path: $p  |  $detail" -Sev $sev
    }
}
foreach ($base in @("C:\Program Files (x86)","C:\Program Files")) {
    Get-ChildItem -Path $base -Filter "ScreenConnect Client*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $hit = $true
        Write-Hit -Label "ScreenConnect Install Directory Found" -Detail $_.FullName -Sev "HIGH"
    }
}
foreach ($pat in @("$env:USERPROFILE\Downloads\e-Signature*.exe","$env:PUBLIC\Downloads\e-Signature*.exe","$env:TEMP\e-Signature*.exe","C:\Windows\Temp\e-Signature*.exe")) {
    Get-Item -Path $pat -ErrorAction SilentlyContinue | ForEach-Object {
        $hit = $true
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        Write-Hit -Label "Original Dropper Found: $($_.Name)" `
                  -Detail "Path: $($_.FullName)  |  SHA256: $hash" -Sev "CRITICAL"
    }
}
Get-ChildItem "C:\Windows\SystemTemp\" -Filter "*.scr" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $hit = $true
    Write-Hit -Label "Suspicious .SCR File (JWrapper dropper pattern)" -Detail $_.FullName -Sev "HIGH"
}
if (-not $hit) { Write-Clean "No malicious file system artifacts detected" }


# ════════════════════════════════════════════════════════════
# 5. NETWORK C2 CONNECTIONS
# ════════════════════════════════════════════════════════════
Write-Section "5. ACTIVE NETWORK CONNECTIONS TO C2"
$hit = $false
$C2IPs = @{ "147.45.218.0"="JWrapper C2 primary"; "91.215.85.219"="JWrapper C2 redundant"; "147.45.218.13"="JWrapper C2 redundant" }
$NetConns = Get-NetTCPConnection -State Established,TimeWait,CloseWait -ErrorAction SilentlyContinue
foreach ($ip in $C2IPs.Keys) {
    $NetConns | Where-Object { $_.RemoteAddress -eq $ip } | ForEach-Object {
        $hit = $true
        $own = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
        Write-Hit -Label "LIVE C2 CONNECTION" `
                  -Detail "Remote: $($_.RemoteAddress):$($_.RemotePort)  |  Local port: $($_.LocalPort)  |  PID: $($_.OwningProcess) ($own)  |  $($C2IPs[$ip])" -Sev "CRITICAL"
    }
}
$NetConns | Where-Object { $_.RemotePort -eq 8041 } | ForEach-Object {
    $hit = $true
    $own = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
    Write-Hit -Label "LIVE SCREENCONNECT C2 (port 8041)" `
              -Detail "Remote: $($_.RemoteAddress):8041  |  PID: $($_.OwningProcess) ($own)  |  gqpplgq2g.anondns.net" -Sev "CRITICAL"
}
Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Entry -like "*anondns.net*" -or $_.Entry -like "*gqpplgq2g*" } | ForEach-Object {
        $hit = $true
        Write-Hit -Label "C2 Domain in DNS Cache: $($_.Entry)" `
                  -Detail "Resolved IP: $($_.Data)  |  Machine recently contacted ScreenConnect C2 relay" -Sev "HIGH"
    }
foreach ($pn in @("Remote_Access_Service","SimpleService","java")) {
    Get-Process -Name $pn -ErrorAction SilentlyContinue | ForEach-Object {
        $pid = $_.Id
        $NetConns | Where-Object { $_.OwningProcess -eq $pid -and $_.RemotePort -eq 443 } | ForEach-Object {
            $hit = $true
            Write-Hit -Label "Port 443 C2 Beacon from $pn (PID $pid)" `
                      -Detail "Outbound to $($_.RemoteAddress):443  |  JWrapper C2 on HTTPS port" -Sev "CRITICAL"
        }
    }
}
if (-not $hit) { Write-Clean "No active connections to known C2 addresses" }


# ════════════════════════════════════════════════════════════
# 6. LOG FILE EVIDENCE
# ════════════════════════════════════════════════════════════
Write-Section "6. JWRAPPER LOG FILE EVIDENCE"
$LogDir = "$env:ProgramData\JWrapper-Remote Access\logs"
$hit = $false
if (Test-Path $LogDir) {
    $logs = Get-ChildItem -Path $LogDir -Filter "*.log" -ErrorAction SilentlyContinue
    if ($logs) {
        $hit = $true
        $newest = $logs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-Hit -Label "JWrapper Log Directory Present ($($logs.Count) files)" `
                  -Detail "Dir: $LogDir  |  Newest: $($newest.Name)  ($($newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" -Sev "HIGH"
        $logs | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object {
            if ((Get-Content $_.FullName -Tail 20 -ErrorAction SilentlyContinue) -match "PollThread|Claiming ID|Loaded SecMsg") {
                Write-Hit -Label "Active C2 Session Evidence in: $($_.Name)" `
                          -Detail "Contains C2 polling entries  |  Modified: $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" -Sev "CRITICAL"
            }
        }
    }
    $gul = Get-ChildItem -Path $LogDir -Filter "GenericUpdater*.log" -ErrorAction SilentlyContinue
    if ($gul) {
        $hit = $true
        $newest = $gul | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-Hit -Label "GenericUpdater Logs Present ($($gul.Count) files)" `
                  -Detail "Most recent RAT auto-update: $($newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Sev "HIGH"
    }
}
if (-not $hit) { Write-Clean "No JWrapper log files found" }


# ════════════════════════════════════════════════════════════
# 7. SCREENCONNECT ARTIFACTS
# ════════════════════════════════════════════════════════════
Write-Section "7. SCREENCONNECT ARTIFACTS"
$hit = $false
$SCFiles = @{
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\system.config" = "C2 relay config (gqpplgq2g.anondns.net:8041)"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\app.config"    = "All 13 stealth/visibility settings disabled"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\rq.msi"        = "ScreenConnect installer (dropped by lure)"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\rqe.exe"       = "Custom DotNetRunner component"
    "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\ScreenConnect.WindowsAuthenticationPackage.dll" = "Windows credential provider DLL"
}
foreach ($p in $SCFiles.Keys) {
    if (Test-Path $p) {
        $hit = $true
        $sev = if ($p -like "*.msi" -or $p -like "*system.config*") { "CRITICAL" } else { "HIGH" }
        Write-Hit -Label "SC Artifact: $(Split-Path $p -Leaf)" -Detail "Path: $p  |  $($SCFiles[$p])" -Sev $sev
    }
}
if ((Test-Path "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\system.config") -and
    ((Get-Content "C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\system.config" -ErrorAction SilentlyContinue) -match "anondns\.net")) {
    $hit = $true
    Write-Hit -Label "C2 Domain Confirmed in system.config" `
              -Detail "gqpplgq2g.anondns.net confirmed in ScreenConnect relay configuration" -Sev "CRITICAL"
}
if (-not $hit) { Write-Clean "No ScreenConnect artifacts found" }


# ════════════════════════════════════════════════════════════
# 8. EVENT LOG INDICATORS
# ════════════════════════════════════════════════════════════
Write-Section "8. WINDOWS EVENT LOG INDICATORS"
$hit = $false
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-60)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*Remote Access*" -or $_.Message -like "*ScreenConnect*" } | ForEach-Object {
        $hit = $true
        Write-Hit -Label "Event 7045: Malicious Service Installed" `
                  -Detail "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  |  $($_.Message.Split("`n")[0])" -Sev "HIGH"
    }
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date).AddDays(-60)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*Remote_Access_Service*" -or $_.Message -like "*officeSH26*" } |
    Select-Object -First 5 | ForEach-Object {
        $hit = $true
        Write-Hit -Label "Event 4688: Malicious Process Creation" `
                  -Detail "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  |  Malicious binary in Security audit log" -Sev "HIGH"
    }
if (-not $hit) { Write-Clean "No matching indicators in event logs (last 60 days)" }


# ════════════════════════════════════════════════════════════
# 9. INSTALLED PROGRAMS
# ════════════════════════════════════════════════════════════
Write-Section "9. SUSPICIOUS INSTALLED PROGRAMS"
$hit = $false
foreach ($reg in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")) {
    Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Remote Access*" -or $_.DisplayName -like "*ScreenConnect*" -or $_.DisplayName -like "*SimpleHelp*" } |
        ForEach-Object {
            $hit = $true
            Write-Hit -Label "Suspicious Program: $($_.DisplayName)" `
                      -Detail "Version: $($_.DisplayVersion)  |  Installed: $($_.InstallDate)  |  Publisher: $($_.Publisher)" -Sev "HIGH"
        }
}
if (-not $hit) { Write-Clean "No suspicious programs in Add/Remove Programs" }


# ════════════════════════════════════════════════════════════
# 10. FIREWALL RULES
# ════════════════════════════════════════════════════════════
Write-Section "10. SUSPICIOUS FIREWALL RULES"
$hit = $false
Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Remote Access*" -or $_.DisplayName -like "*ScreenConnect*" -or $_.DisplayName -like "*JWrapper*" } |
    ForEach-Object {
        $hit = $true
        Write-Hit -Label "Suspicious Firewall Rule: $($_.DisplayName)" `
                  -Detail "Direction: $($_.Direction)  |  Action: $($_.Action)  |  Enabled: $($_.Enabled)" -Sev "HIGH"
    }
if (-not $hit) { Write-Clean "No suspicious firewall rules detected" }


# ════════════════════════════════════════════════════════════
# 11. KNOWN HASH MATCHING
# ════════════════════════════════════════════════════════════
Write-Section "11. KNOWN MALWARE HASH MATCHES"
$KnownHashes = @{
    "b555ceff3236a8175b48b892c1ebc4977fc82c623f3c15ed1efab0c4ac61a9b6" = "e-Signature-Key_Access_ID-MY7362HY73E.exe (initial lure)"
    "924600a3a55c196b362e82151fbc3f9dcf03dc29e6c45e0bd113d7b0d95c6850" = "rq.msi (ScreenConnect installer)"
    "959524efe7d4aa6a132a88daf7d1e1871fa14eae8a6025ba73ab1fb65f7e4f22" = "rqe.exe (DotNetRunner)"
    "bdbdbffb37bc421edac4ac5b20c72db1c72d7f6e819e115c96cde5413146bb36" = "Remote_Access_Service.exe (RAT service)"
    "d26b8e1ba6383b1f7749a133cfbf90e85a22a4bece9f171ed57a3d1ab7833f48" = "StopSimpleGatewayService.exe (RAT utility)"
    "d14a1f14d6ca46bd2168b9d2acf281d8eea62d30e2869d47dd4bf0ad556fb9a2" = "SimpleService.exe (SafeBoot persistence)"
    "a5b8f0070201e4f26260af6a25941ea38bd7042aefd48cd68b9acf951fa99ee5" = "ScreenConnect.WindowsAuthenticationPackage.dll"
}
$hit = $false
foreach ($loc in @("$env:ProgramData\JWrapper-Remote Access","C:\Windows\SystemTemp\ScreenConnect","$env:TEMP","C:\Windows\Temp","$env:USERPROFILE\Downloads","$env:PUBLIC\Downloads")) {
    if (Test-Path $loc) {
        Get-ChildItem -Path $loc -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $h = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($h -and $KnownHashes.ContainsKey($h.ToLower())) {
                $hit = $true
                Write-Hit -Label "CONFIRMED MALWARE HASH: $($_.Name)" `
                          -Detail "Path: $($_.FullName)  |  SHA256: $h  |  $($KnownHashes[$h.ToLower()])" -Sev "CRITICAL"
            }
        }
    }
}
if (-not $hit) { Write-Clean "No files matching known campaign hashes found" }


# ════════════════════════════════════════════════════════════
# CONSOLE SUMMARY
# ════════════════════════════════════════════════════════════
Write-Log ""
Write-Log ("=" * 70) "DarkCyan"
Write-Log "  SCAN SUMMARY" "Cyan"
Write-Log ("=" * 70) "DarkCyan"
Write-Log ""
if ($CriticalHits -gt 0) {
    Write-Log "  STATUS  : *** SYSTEM IS ACTIVELY COMPROMISED ***" "Red"
    Write-Log "  CRITICAL: $CriticalHits  |  Total findings: $FindingCount" "Red"
    Write-Log ""
    Write-Log "  1. Do NOT use this machine for sensitive activity" "Yellow"
    Write-Log "  2. Run Fix.ps1 as Administrator to remove malware" "Yellow"
    Write-Log "  3. Email the report file to jon@pnwcomputers.com" "Yellow"
} elseif ($FindingCount -gt 0) {
    Write-Log "  STATUS  : SUSPICIOUS ARTIFACTS PRESENT ($FindingCount findings)" "Yellow"
    Write-Log "  Run Fix.ps1 to clear remaining items, then email the report." "Yellow"
} else {
    Write-Log "  STATUS  : NO INDICATORS DETECTED - System appears clean" "Green"
}
Write-Log ""
Write-Log "  Report saved to: $ReportFile" "Cyan"
Write-Log ("=" * 70) "DarkCyan"


# ════════════════════════════════════════════════════════════
# BUILD AND SAVE REPORT FILE
# ════════════════════════════════════════════════════════════
$statusText = if ($CriticalHits -gt 0) { "ACTIVELY COMPROMISED -- $CriticalHits CRITICAL finding(s), $FindingCount total" }
              elseif ($FindingCount -gt 0) { "SUSPICIOUS ARTIFACTS PRESENT -- $FindingCount finding(s), 0 critical" }
              else { "NO INDICATORS DETECTED -- System appears clean" }

$divider  = "=" * 70
$divider2 = "-" * 70

$reportContent = @"
$divider
  PNWC INTRUSION DETECTION REPORT
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
  ##     Malware Scan Report - $env:COMPUTERNAME              ##
  ##                                                          ##
  ##############################################################

$divider
SCAN INFORMATION
$divider
  Date/Time    : $(Get-Date -Format 'dddd, MMMM dd yyyy  HH:mm:ss')
  Computer     : $env:COMPUTERNAME
  OS           : $((Get-WmiObject Win32_OperatingSystem).Caption)
  Scanned By   : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
  Report File  : $ReportFile
$divider
OVERALL STATUS:  $statusText
$divider
  CRITICAL findings : $CriticalHits
  Total findings    : $FindingCount
$divider

"@

if ($MaliciousHits.Count -gt 0) {
    $reportContent += @"
$divider
MALICIOUS FINDINGS  (items that need attention / removal)
$divider

$($MaliciousHits | Out-String)
$divider
END OF MALICIOUS FINDINGS
$divider

"@
} else {
    $reportContent += @"
$divider
MALICIOUS FINDINGS
$divider
  None detected. System appears clean.
  If malware was recently removed by Fix.ps1, this is expected.
$divider

"@
}

$reportContent += @"
$divider
RECOMMENDED NEXT STEPS
$divider

  REGARDLESS OF SCAN RESULT:
  1. Change ALL passwords used on this computer since March 30, 2026
       Priority: email, banking, QuickBooks, business portals, cloud services
  2. Enable Multi-Factor Authentication (MFA/2FA) on every account
  3. Review bank/financial accounts for unauthorized transactions

  IF THREATS WERE FOUND:
  4. Run Fix.ps1 as Administrator to remove all detected malware
  5. Reboot the machine after Fix.ps1 completes
  6. Re-run Check-System.ps1 after reboot to confirm clean state

  BLOCK AT YOUR ROUTER / FIREWALL:
    IP:     147.45.218.0
    IP:     91.215.85.219
    IP:     147.45.218.13
    Domain: gqpplgq2g.anondns.net

$divider
CONTACT PNWC FOR ASSISTANCE
$divider
  Pacific Northwest Computers
  Jon Pienkowski -- CompTIA A+ Certified
  Phone : 360-624-7379
  Email : jon@pnwcomputers.com

$divider
FULL SCAN LOG (all sections including clean checks)
$divider

$($ScreenLog | Out-String)

$divider
  ##############################################################
  ##   PLEASE EMAIL THIS REPORT TO: jon@pnwcomputers.com     ##
  ##   Subject: Malware Scan Report - $env:COMPUTERNAME       ##
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
    Write-Host "  Subject: Malware Scan Report - $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Green
    Write-Host ""
    # Auto-open in Notepad so the user sees the report immediately
    Start-Process notepad.exe -ArgumentList $ReportFile
} catch {
    Write-Host "  [!] Could not save report file: $($_.Exception.Message)" -ForegroundColor Red
}

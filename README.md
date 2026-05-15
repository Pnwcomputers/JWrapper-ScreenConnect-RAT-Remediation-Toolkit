# JWrapper & Weaponized ScreenConnect Remediation Tool (Medusa IAB Variant)

This repository contains a specialized PowerShell remediation script designed to hunt, disable, and completely remove a highly persistent, dual-channel Remote Access Trojan (RAT) infection. 

This specific attack chain is frequently utilized by Initial Access Brokers (IABs) and has been heavily associated with the precursors to **Medusa Ransomware** deployments.

## 🛡️ Indicators of Compromise (IOCs)
If you are hunting for this on your network, look for the following:
* **Paths:** * `C:\ProgramData\JWrapper-Remote Access\`
  * `C:\Windows\SystemTemp\ScreenConnect\`
* **Services:** `Remote Access Service`
* **Network:** Connections over port 443 to unfamiliar IPs, or ScreenConnect relays utilizing dynamic DNS (e.g., `anondns.net`).

## 🚨 Threat Profile & Attack Chain
This tool specifically targets an infection chain that utilizes legitimate, abused software to bypass traditional antivirus (AV) and Endpoint Detection and Response (EDR) solutions. 

The attack typically follows this pattern:
1. **Initial Access:** A user executes a fake e-signature lure (often an NSIS installer with a valid DigiCert certificate).
2. **Stage 1 (ScreenConnect):** The installer drops a completely invisible, weaponized instance of ConnectWise ScreenConnect (`rq.msi`). All user-facing notifications are explicitly disabled.
3. **Stage 2 (JWrapper/SimpleHelp):** The attacker uses ScreenConnect to deploy a second persistent backdoor, packaged via JWrapper and utilizing the SimpleHelp remote access engine.
4. **Defense Evasion:** The malware executes hidden PowerShell scripts to hunt and uninstall legitimate RMM agents (like Datto RMM) and actively polls for security products like Malwarebytes and Windows Defender.

### 🔑 The "Killer Feature": SafeBoot Persistence
Most standard malware removal tools fail to clean this infection because the RAT registers itself as a Windows Service and injects a persistence key into:
`HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\`

This ensures that even if an IT administrator reboots the infected machine into **Safe Mode with Networking** to clean it, the attacker maintains full remote access. **This script specifically targets and scrubs this SafeBoot registry key.**

## 🛠️ What This Script Does
The `fix.ps1` script performs a highly aggressive, single-pass cleanup:
* **Terminates Malicious Processes:** Force-kills `SimpleService`, `Remote_Access_Service`, `rqe`, and hidden ScreenConnect processes.
* **Unregisters Services:** Stops and deletes the associated Windows services (using wildcard targeting to catch dynamically generated ScreenConnect service IDs).
* **Scrubs Persistence:** Deletes the SafeBoot registry keys and standard service registry keys.
* **Purges Artifacts:** Completely deletes the `C:\ProgramData\JWrapper-Remote Access\` tree and the hidden ScreenConnect client in `C:\Windows\SystemTemp\`.

## 🚀 Usage Instructions

For ease of use, it is recommended to run the PowerShell script via a Batch wrapper to ensure it executes with the correct execution policies and Administrator privileges.

1. Download both `fix.ps1` and `RUN_ME.bat` to the same folder on the infected machine.
2. Right-click `RUN_ME.bat` and select **Run as Administrator**.
3. Wait for the console to indicate the cleanup is complete.
4. **Reboot the machine immediately.**

> **WARNING:** This tool removes the attacker's *access*, but it does not undo the *data exposure*. Because this RAT includes screen-monitoring and process-injection capabilities, **all passwords typed or saved on the infected machine should be considered compromised and must be rotated immediately after reboot.**

## 🛡️ Indicators of Compromise (IOCs)
If you are hunting for this on your network, look for the following:
* **Paths:** * `C:\ProgramData\JWrapper-Remote Access\`
  * `C:\Windows\SystemTemp\ScreenConnect\`
* **Services:** `Remote Access Service`
* **Network:** Connections over port 443 to unfamiliar IPs, or ScreenConnect relays utilizing dynamic DNS (e.g., `anondns.net`).

## ⚖️ Disclaimer
This script is provided as-is, without warranty of any kind. It is highly recommended to test this script in a safe environment before deploying it to production machines. Always preserve forensic logs prior to running remediation tools if you intend to involve law enforcement or cyber insurance.

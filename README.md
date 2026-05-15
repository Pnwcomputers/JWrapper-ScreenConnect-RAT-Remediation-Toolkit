# JWrapper & Weaponized ScreenConnect Remediation Toolkit
## *(Medusa IAB Variant)*

This repository contains a specialized PowerShell toolkit designed to **detect, document, and completely remove** a highly persistent, dual-channel Remote Access Trojan (RAT) infection built on abused legitimate remote access software.

This specific attack chain is actively utilized by Initial Access Brokers (IABs) and has been heavily associated with the precursors to **Medusa Ransomware** deployments. All IOCs, hashes, and behavioral signatures in this repository are sourced from real field incident response data.

---

## 📁 Repository Contents

| File | Description |
| :--- | :--- |
| `RUN_ME.bat` | Launcher with admin check and interactive menu. Start here. |
| `Check-System.ps1` | **Read-only** pre-remediation detection scanner. Run this first. |
| `Fix.ps1` | Active remediation script. Removes all known artifacts. |
| `indicators.md` | Full IOC data sheet (hashes, paths, registry keys, network, TTPs). |
| `CONTRIBUTE.md` | Guidelines for submitting new IOCs from the field. |

---

## 🚨 Threat Profile & Attack Chain

This toolkit targets an infection chain that weaponizes **legitimate, digitally signed software** to bypass traditional AV and EDR solutions. No payload component triggers a standard antivirus alert.

The attack follows this progression:

1. **Initial Access:** User executes a fake e-signature lure — typically an NSIS installer named `e-Signature-Key_Access_ID-[ID].exe` — bearing a valid DigiCert Authenticode certificate. Windows displays a trusted (blue) UAC prompt. No AV alert fires.

2. **Stage 1 — ScreenConnect (Immediate Access):** The installer silently drops and installs a weaponized ConnectWise ScreenConnect client (`rq.msi` + `rqe.exe`). All 13 user-facing notification settings are explicitly pre-disabled — no tray icon, no connection banner, no user alert of any kind. The client beacons to the attacker's relay via anonymous dynamic DNS (`gqpplgq2g.anondns.net:8041`).

3. **Stage 2 — JWrapper/SimpleHelp RAT (Persistent Backdoor):** Using the live ScreenConnect session, the attacker deploys a second-stage persistent backdoor packaged via JWrapper (`officeSH26_working_verf.scr`) that installs SimpleHelp v5.5.14 as a SYSTEM-level Windows service. This provides screen monitoring, remote scripting, file transfer, and process injection capabilities with zero user notification.

4. **Defense Evasion:** Malware executes hidden PowerShell immediately post-install. The attacker polls for security products (Malwarebytes `MBAMService`, Windows Defender `WinDefend`) and has been observed using toolbox scripts to uninstall legitimate RMM agents such as Datto RMM.

5. **Operator Handoff (Observed):** In confirmed field cases, the campaign profile identifier rotates mid-intrusion (e.g., from `Transport office101/103/AUTODETECT` to `Star 2026/AUTODETECT`), consistent with an initial access broker selling or transferring the session to a secondary ransomware operator.

---

## 🔑 The SafeBoot Persistence Problem

Most standard removal tools fail against this infection because the RAT registers itself in the Windows SafeBoot registry hive:

```
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service
```

This means that even if you boot the machine into **Safe Mode with Networking** to clean it, the attacker retains full remote access. **Both `Check-System.ps1` and `Fix.ps1` specifically target this key.**

---

## 🛠️ Toolkit Overview

### `Check-System.ps1` — Detection Scanner (Read-Only)
Run this **before** any remediation. It makes zero changes to the system and produces a full timestamped detection report.

Checks 11 categories:
- Running malicious processes (including JWrapper java instances)
- Malicious Windows services (exact names + wildcard + WMI binary path)
- Registry persistence keys (SafeBoot, Services, Run keys, Scheduled Tasks)
- File system artifacts (known paths, dropper files, `.scr` files)
- Active network connections to known C2 IPs and port 8041
- DNS cache for C2 domain resolution history
- JWrapper log directory and active session evidence
- ScreenConnect-specific artifacts including `system.config` and `app.config`
- Windows Event Log indicators (Event IDs 7045, 4688, 4104)
- Installed programs in Add/Remove Programs registry
- SHA256 hash matching against all 7 known campaign files

At completion, the script saves a formatted report to the script directory and **auto-opens it in Notepad**, with clear instructions to email findings to the investigating technician.

---

### `Fix.ps1` — Remediation Script
Performs aggressive single-pass cleanup across 7 steps:

1. **Terminate Processes** — Force-kills all malicious processes; targets JWrapper java instances by path
2. **Remove Services** — Stops and deletes `Remote Access Service` and any `ScreenConnect Client*` services; captures `sc.exe` output for verification
3. **Scrub Registry** — Removes SafeBoot key, service key, Uninstall hive entry, Run key entries, and any related Scheduled Tasks
4. **Purge File System** — Uses `takeown` + `icacls` before deletion to defeat file permission locks; removes `JWrapper-Remote Access`, `ScreenConnect` staging directories, loose dropper files, and `.scr` files
5. **Remove Firewall Rules** — Cleans any rules added by the RAT
6. **Flush DNS Cache** — Removes cached resolution of C2 domains
7. **Post-Remediation Verification** — Re-checks all key indicators and reports pass/fail per item

Saves a full timestamped remediation report (items removed, failed, not found, and verification results) and **auto-opens it in Notepad** with email instructions.

---

### `RUN_ME.bat` — Interactive Launcher
Run this as Administrator. Presents a simple menu:

```
[1]  CHECK ONLY   Scan for indicators (no changes made)
[2]  FIX / CLEAN  Remove all detected malware
[3]  EXIT
```

Option `[2]` requires typing `YES` to confirm before any destructive action runs.

---

## 🚀 Usage Instructions

**Recommended workflow:**

1. Download `RUN_ME.bat`, `Check-System.ps1`, and `Fix.ps1` to the same folder on the target machine.
2. Right-click `RUN_ME.bat` → **Run as administrator**.
3. Select **[1] CHECK ONLY** and wait for the scan to complete.
4. Review the report that opens in Notepad. Email it to your technician if requested.
5. If threats are found, run `RUN_ME.bat` again and select **[2] FIX / CLEAN**.
6. Type `YES` to confirm, wait for remediation to complete, and review the second report.
7. **Reboot the machine immediately.**
8. After reboot, run `RUN_ME.bat` → **[1] CHECK ONLY** again to confirm clean state.

> **You can also run either script directly:**
> ```powershell
> # Right-click PowerShell -> Run as Administrator
> .\Check-System.ps1
> .\Fix.ps1
> ```

---

## 📊 Report Files

Both scripts generate timestamped `.txt` report files saved to the same folder as the scripts:

| Script | Report Filename |
| :--- | :--- |
| `Check-System.ps1` | `PNWC_Detection_Report_YYYY-MM-DD_HH-mm-ss.txt` |
| `Fix.ps1` | `PNWC_Remediation_Report_YYYY-MM-DD_HH-mm-ss.txt` |

Each report opens automatically in Notepad at completion and contains:
- Full system and scan metadata
- A consolidated **Malicious Findings** section listing only the threats detected
- Recommended next steps
- Contact information and instructions to email the report to the investigating technician

---

## ⚠️ Important Warnings

> **This tool removes attacker access but does not undo data exposure.**
>
> Because this RAT includes confirmed screen-monitoring (`AllowMonitoring=true`), remote scripting (`AllowScripting=true`), file transfer, and process injection (`CreateRemoteThread`) capabilities, **all passwords typed or saved on the infected machine during the intrusion window must be treated as compromised and rotated immediately after remediation.**

> **Preserve forensic logs before running Fix.ps1** if you intend to involve law enforcement, cyber insurance, or legal counsel. Run `Check-System.ps1` first and retain the detection report as your pre-remediation baseline.

> **Consider a full OS wipe and reload** for high-value or high-risk machines. While this toolkit removes all known artifacts, a SYSTEM-level attacker with 30+ days of dwell time may have installed additional backdoors outside the available log evidence.

---

## 🌐 Block These at Your Firewall / Router

```
147.45.218.0       (JWrapper C2 - primary)
91.215.85.219      (JWrapper C2 - redundant)
147.45.218.13      (JWrapper C2 - redundant)
gqpplgq2g.anondns.net   (ScreenConnect C2 relay)
```

---

## 🛡️ Indicators of Compromise

See [indicators.md](./indicators.md) for the complete, field-sourced IOC data sheet including file hashes, registry keys, network infrastructure, campaign identifiers, and behavioral TTPs.

---

## ⚖️ Disclaimer

This toolkit is provided as-is under the MIT License, without warranty of any kind. Test in a safe environment before deploying to production. Always preserve forensic evidence before running remediation tools if law enforcement, cyber insurance, or legal proceedings may be involved.

---

*Pacific Northwest Computers — Vancouver, WA*
*jon@pnwcomputers.com | 360-624-7379*

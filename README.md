# JWrapper & ScreenConnect Remediation Toolkit
## *(Medusa IAB Variant — SILENTCONNECT Campaign)*

This repository contains a specialized PowerShell toolkit designed to **detect, document, and completely remove** a highly persistent, dual-channel Remote Access Trojan (RAT) infection built on abused legitimate remote access software.

This specific attack chain is actively utilized by Initial Access Brokers (IABs) and has been heavily associated with the precursors to **Medusa Ransomware** deployments. All IOCs, hashes, and behavioral signatures in this repository are sourced from real field incident response data collected across multiple confirmed victims in SW Washington and the Portland, OR metro area between **March 31 and early May 2026**.

> **⚠️ Active Campaign Alert:** As of May 2026, this infection chain is confirmed active across residential and SMB targets in the Pacific Northwest. Multiple victims share identical C2 infrastructure, confirming a coordinated mass-phishing campaign. This campaign has been independently designated **SILENTCONNECT** by Elastic Security Labs (March 2026) and is tracked by Microsoft as a precursor to ransomware deployment. Field IOCs published on OTX: [pulse/6a18e9c64ab0a08568d345cd](https://otx.alienvault.com/pulse/6a18e9c64ab0a08568d345cd)

---

## 📁 Repository Contents

| File | Description |
| :--- | :--- |
| `RUN_ME.bat` | Launcher with admin check and interactive menu. Start here. |
| `system_check.ps1` | **Read-only** pre-remediation detection scanner. Run this first. |
| `Fix.ps1` | Active remediation script. Removes all known artifacts. |
| `indicators.md` | Full IOC data sheet (hashes, paths, registry keys, network, TTPs). |
| `CONTRIBUTE.md` | Guidelines for submitting new IOCs from the field. |

---

## 🚨 Threat Profile & Attack Chain

This toolkit targets an infection chain that weaponizes **legitimate, digitally signed software** to bypass traditional AV and EDR solutions. No payload component triggers a standard antivirus alert.

The attack follows this progression:

1. **Initial Access — Phishing Lure:** User receives a phishing email and is directed to a Cloudflare Turnstile CAPTCHA page. After passing the CAPTCHA, a malicious file is downloaded. Observed lure types include:
   * NSIS installer: `e-Signature-Key_Access_ID-[ID].exe` — bearing a valid DigiCert Authenticode certificate, producing a trusted (blue) UAC prompt
   * VBScript files: `E-INVITE.vbs`, `Proposal-03-2026.vbs`, and similar names
   * Both variants ultimately deliver the same ScreenConnect payload via PowerShell or direct execution

2. **Stage 1 — ScreenConnect (Immediate Silent Access):** The installer silently drops and installs a weaponized ConnectWise ScreenConnect client (`rq.msi` + `rqe.exe`). All 13 user-facing notification settings are explicitly pre-disabled — no tray icon, no connection banner, no user alert of any kind. The client beacons to the attacker's relay.

3. **Stage 2 — JWrapper/SimpleHelp RAT (Persistent Backdoor):** Using the live ScreenConnect session, the attacker deploys a second-stage persistent backdoor packaged via JWrapper (`officeSH26_working_verf.scr`) that installs SimpleHelp v5.5.14 as a SYSTEM-level Windows service. This provides screen monitoring, remote scripting, file transfer, and process injection capabilities with zero user notification.

4. **Defense Evasion:** Malware executes hidden PowerShell immediately post-install. The attacker polls for security products (Malwarebytes `MBAMService`, Windows Defender `WinDefend`) and has been observed using toolbox scripts to uninstall legitimate RMM agents such as Datto RMM.

5. **Operator Handoff (Observed):** In confirmed field cases, the campaign profile identifier rotates mid-intrusion (e.g., from `Transport office101/103/AUTODETECT` to `Star 2026/AUTODETECT`), consistent with an initial access broker selling or transferring the session to a secondary ransomware operator.

---

## 🔑 The SafeBoot Persistence Problem

Most standard removal tools fail against this infection because the RAT registers itself in the Windows SafeBoot registry hive:

```text
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service
```

This means that even if you boot the machine into **Safe Mode with Networking** to clean it, the attacker retains full remote access. **Both `system_check.ps1` and `Fix.ps1` specifically target this key.**

---

## 🔗 Multi-Victim Campaign Attribution

Field data collected across 6+ confirmed victims in SW Washington / Portland metro area, plus a confirmed multi-machine business compromise active since January 2023, reveals shared C2 infrastructure confirming a long-running coordinated campaign:

| Relay Instance | IPs Observed | Campaign Wave | Notes |
| :--- | :--- | :--- | :--- |
| `instance-sis2tc-relay.screenconnect.com` | `15.204.131.77`, `147.75.50.76` | 2025–2026 | Cross-victim confirmed — multiple victims 2 hrs apart; IP rotating |
| `instance-fc5xev-relay.screenconnect.com` | `147.28.146.148` | 2024 | Earlier campaign wave |
| `instance-zayrhg-relay.screenconnect.com` | `15.204.48.x`, `15.204.43.x`, `139.178.x.x` | 2023–2026 | Long-running — 14+ IP rotations over 3 years |
| `instance-c7gab0-relay.screenconnect.com` | `147.75.70.x`, `15.204.43.236` | 2023–2025 | Secondary relay on same business network |
| `instance-xbirmk-relay.screenconnect.com` | `139.178.89.x` | 2023–2024 | Earliest observed access, Jan 2023 |
| `instance-wrnmil-relay.screenconnect.com` | `147.28.129.152` | 2023 | Fifth relay — concurrent with instance-zayrhg on same victim |
| `gqpplgq2g.anondns.net` | Dynamic | March–April 2026 | Anonymous dynamic DNS — original documented case |

> **Long-term persistence confirmed:** Multiple business networks show continuous compromise spanning years with zero antivirus detection. Three separate businesses confirmed affected in SW Washington / Portland metro area as of June 2026. The attacker maintained up to five simultaneous relay connections, rotated IPs under stable relay hostnames, periodically upgraded payload versions, and deployed VPN firewall rules (L2TP/PPTP/GRE) on victim workstations across multiple businesses — a consistent TTP indicating active lateral movement attempts.

---

## 🛠️ Toolkit Overview

### `system_check.ps1` — Detection Scanner (Read-Only)
Run this **before** any remediation. It makes zero changes to the system and produces a full timestamped detection report.

Checks the following categories:
* Running malicious processes (including JWrapper java instances and malicious ScreenConnect relay arguments)
* Malicious Windows services (exact names + wildcard + WMI binary path)
* Registry persistence keys (SafeBoot, Services, Run keys, Scheduled Tasks, ScreenConnect Tracing/EventLog artifacts)
* File system artifacts (known paths, dropper files, `.scr` files)
* Active network connections to known C2 IPs and port 8041
* DNS cache for C2 domain resolution history
* JWrapper log directory and active session evidence
* ScreenConnect-specific artifacts including `system.config` and `app.config`
* Windows Event Log indicators (Event IDs 7045, 4688, 4104)
* Installed programs in Add/Remove Programs registry
* SHA256 hash matching against all known campaign files
* **Whitelisting:** Safely ignores legitimate Line-of-Business ScreenConnect instances to prevent false positives.

At completion, the script saves a formatted report to the script directory and **auto-opens it in Notepad**, with clear instructions to email findings to the investigating technician.

---

### `Fix.ps1` — Remediation Script
Performs aggressive single-pass cleanup across 7 steps:

1. **Terminate Processes:** Force-kills all malicious processes; targets JWrapper java instances by path.
2. **Remove Services:** Stops and deletes `Remote Access Service` and any `ScreenConnect Client*` services; captures `sc.exe` output for verification.
3. **Scrub Registry:** Removes SafeBoot key, service key, Uninstall hive entry, Run key entries, related Scheduled Tasks, and ScreenConnect Tracing/EventLog footprints.
4. **Purge Caches & File System:** Clears SideBySide/ClickOnce deployment caches across all `HKEY_USERS` registry hives. Uses `takeown` + `icacls` to defeat file permission locks; removes `JWrapper-Remote Access`, `ScreenConnect` staging directories, loose `.vbs`/`.msi`/`.exe` dropper files, and `.scr` files.
5. **Remove/Add Firewall & Network Rules:** Cleans any rules added by the RAT, and adds automated Windows Hosts file sinkholing and Outbound Windows Firewall rules for known malicious relays (`instance-fc5xev`, `instance-sis2tc`, etc.).
6. **Flush DNS Cache:** Removes cached resolution of C2 domains.
7. **Post-Remediation Verification:** Re-checks all key indicators and reports pass/fail per item, and removes Windows Defender exclusions added by the SILENTCONNECT payload.

Saves a full timestamped remediation report (items removed, failed, not found, and verification results) and **auto-opens it in Notepad** with email instructions.

---

### `RUN_ME.bat` — Interactive Launcher
Run this as Administrator. Presents a simple menu:

```text
[1]  CHECK ONLY   Scan for indicators (no changes made)
[2]  FIX / CLEAN  Remove all detected malware
[3]  EXIT
```

Option `[2]` requires typing `YES` to confirm before any destructive action runs.

---

## 📦 Changelog

### v2.5.0
* **Added:** Deep registry cleaning for SideBySide/ClickOnce deployment caches across all `HKEY_USERS` hives.
* **Added:** Cleanup for ScreenConnect Tracing (`WOW6432Node\Microsoft\Tracing`) and EventLog registry keys.
* **Added:** Automated Windows Hosts file sinkholing for known malicious relays (`instance-fc5xev`, `instance-sis2tc`).
* **Updated:** Memory and process detection logic to actively hunt for specific malicious relay command-line arguments.
* **Fixed:** Whitelisted valid local applications (e.g., Furniture Wizard) to prevent accidental disruption of legitimate business tools.

---

## 🚀 Usage Instructions

**Recommended workflow:**

1. Download `RUN_ME.bat`, `system_check.ps1`, and `Fix.ps1` to the same folder on the target machine.
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
> .\system_check.ps1
> .\Fix.ps1
> ```

---

## 📊 Report Files

Both scripts generate timestamped `.txt` report files saved to the same folder as the scripts:

| Script | Report Filename |
| :--- | :--- |
| `system_check.ps1` | `PNWC_Detection_Report_YYYY-MM-DD_HH-mm-ss.txt` |
| `Fix.ps1` | `PNWC_Remediation_Report_YYYY-MM-DD_HH-mm-ss.txt` |

Each report opens automatically in Notepad at completion and contains:
* Full system and scan metadata
* A consolidated **Malicious Findings** section listing only the threats detected
* Recommended next steps
* Contact information and instructions to email the report to the investigating technician

---

## ⚠️ Important Warnings

> **This tool removes attacker access but does not undo data exposure.**
>
> Because this RAT includes confirmed screen-monitoring (`AllowMonitoring=true`), remote scripting (`AllowScripting=true`), file transfer, and process injection (`CreateRemoteThread`) capabilities, **all passwords typed or saved on the infected machine during the intrusion window must be treated as compromised and rotated immediately after remediation.**

> **Preserve forensic logs before running Fix.ps1** if you intend to involve law enforcement, cyber insurance, or legal counsel. Run `system_check.ps1` first and retain the detection report as your pre-remediation baseline.

> **Consider a full OS wipe and reload** for high-value or high-risk machines. While this toolkit removes all known artifacts, a SYSTEM-level attacker with 30+ days of dwell time may have installed additional backdoors outside the available log evidence.

> **QuickBooks and Outlook users — treat all credentials as compromised.** Field evidence confirms this RAT has been present on machines running QuickBooks (QBW.EXE) and Microsoft Outlook simultaneously. Assume financial data, saved credentials, and email history were accessible to the attacker during the dwell window. Notify your bank and rotate all business account credentials immediately.

---

## 🌐 Block These at Your Firewall / Router

```text
# JWrapper C2 — Stage 2 RAT relays
147.45.218.0          (JWrapper C2 - primary)
91.215.85.219         (JWrapper C2 - redundant)
147.45.218.13         (JWrapper C2 - redundant)

# ScreenConnect C2 — instance-sis2tc relay (IP rotating)
15.204.131.77         (instance-sis2tc -- April 2026, cross-victim confirmed)
147.75.50.76          (instance-sis2tc -- Feb 2025, IP rotation)
147.28.146.148        (instance-fc5xev -- 2024 campaign wave)

# ScreenConnect C2 — instance-zayrhg relay (2023–2026, rotating IPs)
15.204.48.24          (instance-zayrhg -- Mar–Aug 2026)
15.204.48.31          (instance-zayrhg -- Dec 2025)
15.204.48.34          (instance-zayrhg -- Jan 2026)
15.204.43.162         (instance-zayrhg -- Apr–May 2026)
139.178.68.80         (instance-zayrhg -- May 2023)
139.178.89.196        (instance-zayrhg -- Nov 2024)
139.178.91.96         (instance-zayrhg -- May 2025)
147.75.70.32          (instance-zayrhg -- Dec 2024)

# ScreenConnect C2 — instance-c7gab0 relay (2023–2025, rotating IPs)
147.75.70.188         (instance-c7gab0 -- Mar 2023)
147.75.70.116         (instance-c7gab0 -- Jul 2024)
147.75.70.28          (instance-c7gab0 -- Feb 2025)
15.204.43.236         (instance-c7gab0 -- Oct 2025)
139.178.69.0          (instance-c7gab0 -- Aug 2023)

# ScreenConnect C2 — instance-xbirmk relay (2023–2024)
139.178.89.208        (instance-xbirmk -- Jan 2023, earliest observed)
139.178.89.96         (instance-xbirmk -- Oct 2023)
139.178.89.228        (instance-xbirmk -- Sep 2024)

# ScreenConnect C2 — instance-wrnmil relay (2023)
147.28.129.152        (instance-wrnmil -- Mar-Oct 2023)

# SILENTCONNECT delivery infrastructure (Elastic Security Labs + OTX corroborated)
86.38.225.59          (bumptobabeco.top -- Lithuania, AS398465 rackdog llc)

# Dynamic DNS C2
gqpplgq2g.anondns.net    (ScreenConnect C2 relay — original documented case)
instance-sis2tc-relay.screenconnect.com
instance-fc5xev-relay.screenconnect.com
instance-zayrhg-relay.screenconnect.com
instance-c7gab0-relay.screenconnect.com
instance-xbirmk-relay.screenconnect.com
instance-wrnmil-relay.screenconnect.com

# Known SILENTCONNECT campaign domains (Elastic Security Labs, March 2026)
bumptobabeco[.]top
imansport[.]ir
solpru[.]com
```

---

## 🛡️ Indicators of Compromise

See [indicators.md](./indicators.md) for the complete, field-sourced IOC data sheet including file hashes, registry keys, network infrastructure, campaign identifiers, and behavioral TTPs.

---

## 📚 External Research & Attribution

This campaign has been independently documented by multiple threat intelligence organizations:

| Source | Publication | Campaign Name |
| :--- | :--- | :--- |
| Elastic Security Labs | March 19, 2026 | SILENTCONNECT |
| Microsoft Security Blog | March 3, 2026 | Signed malware / TrustConnect RMM variant |
| Microsoft Security Blog | May 26, 2026 | ScreenConnect / cryptojacking ScreenConnect abuse |
| BleepingComputer / G DATA | June 25, 2025 | Authenticode stuffing / EvilConwi |
| OTX AlienVault (pnwcomputers) | May 2026 | [JWrapper/ScreenConnect Dual-Stage RAT — SILENTCONNECT / Medusa IAB Variant](https://otx.alienvault.com/pulse/6a18e9c64ab0a08568d345cd) |

The SILENTCONNECT designation from Elastic Security Labs most closely matches the VBScript-delivered variant of this campaign. The NSIS-based e-signature lure variant documented here shares payload infrastructure (`instance-sis2tc-relay.screenconnect.com`, `15.204.131.77`) and behavioral TTPs with the broader SILENTCONNECT campaign family.

---

## ⚖️ Disclaimer

This toolkit is provided as-is under the MIT License, without warranty of any kind. Test in a safe environment before deploying to production. Always preserve forensic evidence before running remediation tools if law enforcement, cyber insurance, or legal proceedings may be involved.

---

*Pacific Northwest Computers — Vancouver, WA*
*jon@pnwcomputers.com | 360-624-7379*
*Last updated: June 2026 — reflects multi-victim field data and v2.5.1 enhancements*

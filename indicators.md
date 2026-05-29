# Medusa IAB Variant (JWrapper/ScreenConnect) — IOC Data Sheet
## *(SILENTCONNECT Campaign Family)*

This is a field-sourced document of known Indicators of Compromise (IOCs) associated with the dual-channel JWrapper/SimpleHelp and weaponized ScreenConnect intrusion chain, frequently utilized by Initial Access Brokers (IABs) linked to Medusa Ransomware. All entries are confirmed from real incident response and forensic analysis of live infections across multiple victims in SW Washington and the Portland, OR metro area, March 31 – May 2026.

> **Campaign status:** ACTIVE as of May 2026. Multiple confirmed victims sharing identical C2 infrastructure. Designated **SILENTCONNECT** by Elastic Security Labs (March 19, 2026).

*Contributions: Submit a pull request or open an issue to add new IOCs observed in the wild.*

---

## 📂 File Names & Payloads

### Stage 0: Delivery / Phishing Lures

| Filename | Description |
| :--- | :--- |
| `e-Signature-Key_Access_ID-MY7362HY73E.exe` | NSIS v2.51 installer lure. Valid DigiCert Authenticode cert. Blue UAC prompt. |
| `e-Signature-Key_Access_ID-MY7362HY73E (1).exe` | Duplicate variant (observed on some systems) |
| `E-INVITE.vbs` | VBScript delivery variant — SILENTCONNECT loader. Downloads C# payload from Google Drive via Cloudflare R2 CAPTCHA page. |
| `Proposal-03-2026.vbs` | VBScript delivery variant — same loader family |
| `Alaska Airlines 2026 Fleet & Route Expansion Summary.vbs` | VBScript delivery variant — same loader family |
| `CODE7_ZOOMCALANDER_INSTALLER_4740.vbs` | VBScript delivery variant — same loader family |
| `2025Trans.vbs` | VBScript delivery variant — same loader family |
| `updatv35.vbs` | VBScript delivery variant — same loader family |
| `C:\Windows\Temp\FileR.txt` | C# source code staged to disk by VBScript loader before in-memory compilation |

> **Note:** VBScript variants use a Cloudflare Turnstile CAPTCHA page as the delivery landing, defeating email gateway sandboxing. The CAPTCHA page downloads the `.vbs` file which then retrieves a C# payload from Google Drive and compiles it in memory before downloading ScreenConnect.

### Stage 1: ScreenConnect Installer & Components

| Filename | Description |
| :--- | :--- |
| `rq.msi` | Weaponized ConnectWise ScreenConnect v25.2.4.9229 installer |
| `rqe.exe` | Custom DotNetRunner — manages the ScreenConnect session |
| `ScreenConnect.WindowsClient.exe` | ScreenConnect remote access client |
| `ScreenConnect.WindowsFileManager.exe` | ScreenConnect file transfer component |
| `ScreenConnect.WindowsBackstageShell.exe` | ScreenConnect remote command shell |
| `ScreenConnect.WindowsAuthenticationPackage.dll` | Windows credential provider integration DLL |
| `system.config` | ScreenConnect C2 relay config (contains relay hostname, resolved IP, and RSA-2048 auth key) |
| `app.config` | ScreenConnect stealth config — `AutoConsentToBackstage=true`, all 13 visibility settings suppressed |

### Stage 2: JWrapper / SimpleHelp RAT

| Filename | Description |
| :--- | :--- |
| `officeSH26_working_verf.scr` | JWrapper deployment payload disguised as a Windows Screensaver file |
| `Remote_Access_Service.exe` | Main JWrapper/SimpleHelp service executable (runs as SYSTEM) |
| `Remote_AccessWinLauncher.exe` | JWrapper Windows launcher component |
| `Remote_Access_Configure.exe` | RAT reconfiguration utility |
| `Remote_Access_Launcher.exe` | RAT launcher component |
| `SimpleService.exe` | SafeBoot persistence binary — writes/removes `SafeBoot\Network` registry key |
| `StopSimpleGatewayService.exe` | Attacker-facing RAT management utility (stop/restart service) |
| `jwutils_win32.dll` | JWrapper native utility library — contains `CreateRemoteThread` (process injection) |
| `jwutils_win64.dll` | JWrapper native utility library 64-bit — contains `CreateRemoteThread` |
| `libzstd-jni.dll` | Zstandard v1.5.2 compression library — used to compress data before C2 exfiltration |
| `ArmUI.ini` | JWrapper multilingual UI resource file (UTF-16 LE, 248KB) — presence confirms JWrapper Stage 2 deployment |
| `serviceconfig.xml` | Live C2 config — contains relay IPs, registration key, and capability flags |
| `alertsdb` | Encrypted session activity database (16KB+) — records all C2 session events |
| `verified` | Plaintext file written after successful C2 connectivity — contains all three relay IPs |
| `sgport` | Contains the local IPC port used by the RAT service (confirmed: `41431`) |
| `jwLastRun` | Binary timestamp of last C2 session (milliseconds since epoch) |
| `secmsg-http*.secmsg` | Per-server encrypted session authentication tokens (one per C2 relay) |
| `secmsg-http*.bcutil` | Supporting session crypto utility files |

---

## 📁 Known File & Directory Paths

### Malware Installation Directories

```
C:\ProgramData\JWrapper-Remote Access\                          (entire tree)
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\
C:\ProgramData\JWrapper-Remote Access\logs\
C:\Windows\SystemTemp\ScreenConnect\
C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\
%TEMP%\ScreenConnect\
C:\Windows\Temp\ScreenConnect\
C:\Windows\Temp\FileR.txt                                       (VBScript variant C# staging file)
C:\Temp\ScreenConnect.ClientSetup.msi                          (VBScript variant MSI staging path)
C:\Program Files\ScreenConnect Client*\
C:\Program Files (x86)\ScreenConnect Client*\
%LOCALAPPDATA%\Apps\2.0\                                        (ClickOnce cache — ScreenConnect client install)
%APPDATA%\MMSOFT Design\Pulseway\working\                       (Pulseway staging dir — observed pre-infection)
```

### Notable Individual Files

```
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\serviceconfig.xml
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\alertsdb
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\verified
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\sgport
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\jwLastRun
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\Remote_Access_Service.exe
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\SimpleService.exe
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\SimpleGatewayService\StopSimpleGatewayService.exe
C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\system.config
C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\app.config
C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\rq.msi
C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\rqe.exe
C:\Windows\SystemTemp\ScreenConnect\25.2.4.9229\ScreenConnect.WindowsAuthenticationPackage.dll
```

### Attacker Toolbox Execution Paths (Secondary Payloads)

```
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\working\toolbox-*\
C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\working\toolbox-7486505558619514016\remove20msp20rmm*.ps1
```

These paths are used by the attacker to stage and execute additional PowerShell scripts — including scripts that uninstall legitimate RMM agents.

### Developer Build Paths (Embedded in Binaries — Threat Actor OPSEC Artifacts)

```
C:\Users\jmorgan\Source\cwcontrol\Custom\DotNetRunner\Release\DotNetRunner.pdb
C:\Compile\screenconnect\Product\WindowsAuthenticationPackage\bin\Release\ScreenConnect.WindowsAuthenticationPackage.pdb
C:\builds\cc\cwcontrol\Product\ClientService\obj\Release\ScreenConnect.ClientService.pdb
C:\builds\cc\cwcontrol\Product\Core\obj\Release\net20\ScreenConnect.Core.pdb
C:\builds\cc\cwcontrol\Product\WindowsClient\obj\Release\ScreenConnect.WindowsClient.pdb
```

> The `jmorgan` username in the DotNetRunner PDB path is a confirmed threat actor OPSEC artifact from the custom ScreenConnect build environment.

---

## 🔑 Registry Keys

### Persistence (CRITICAL)

```
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Remote Access Service
```
> Ensures the RAT service starts even when the machine is booted into Safe Mode with Networking. This is the primary reason standard removal tools fail on this infection.

### Service Registration

```
HKLM\SYSTEM\CurrentControlSet\Services\Remote Access Service
HKLM\SYSTEM\CurrentControlSet\Services\ScreenConnect Client*
```

### Masquerading / Uninstall Hive

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Remote Access
```

---

## 🌐 Network Infrastructure (C2)

### Stage 1 — ScreenConnect Relay Servers

| Address / Hostname | Resolved IP | Port | Campaign Wave | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `instance-sis2tc-relay.screenconnect.com` | `15.204.131.77` | `8041` | April 2026 | **Primary active C2 — confirmed cross-victim** |
| `instance-fc5xev-relay.screenconnect.com` | `147.28.146.148` | `8041` | April 2024 | Earlier campaign wave — same actor or affiliate |
| `gqpplgq2g.anondns.net` | Dynamic | `8041` | March–April 2026 | Anonymous dynamic DNS — original documented case |

> **Cross-victim attribution:** `15.204.131.77` (instance-sis2tc) is confirmed in the `user.config` HostToAddressMap of at least two independent victims, with connection timestamps 2 hours apart on April 29, 2026. This is direct evidence of a coordinated campaign, not coincidence.

> **Re-infection indicator:** One victim's `user.config` contains **both** `instance-fc5xev` (2024) and `instance-sis2tc` (2026), indicating either re-infection two years later or persistent access upgraded to the new payload version.

### Stage 1 — ScreenConnect app.config Stealth Flags (Identical Across All Victims)

```xml
AutoConsentToBackstage    = true    <!-- Attacker gets shell without any user prompt -->
DisabledCommandNames      = ManageCredentials,VideoPause,VideoStop
AllowGuestInitiatedFileTransfer = false
AlwaysDeleteSessionOnExit = true    <!-- Session artifacts purged on disconnect -->
```

### Stage 2 — JWrapper / SimpleHelp Gateways

| Address | Port | Protocol | Role |
| :--- | :--- | :--- | :--- |
| `147.45.218.0` | `443` | HTTP (over HTTPS port) | Primary C2 relay |
| `91.215.85.219` | `443` | HTTP (over HTTPS port) | Redundant C2 relay |
| `147.45.218.13` | `443` | HTTP (over HTTPS port) | Redundant C2 relay |

> All three JWrapper relays use port 443 to blend with HTTPS traffic and bypass firewall rules. They share a single registration key (see Campaign Identifiers), confirming single-operator control.

### SILENTCONNECT VBScript Variant — Delivery Infrastructure

| Address / URL | Type | Notes |
| :--- | :--- | :--- |
| `bumptobabeco[.]top` | domain | ScreenConnect MSI download and C2 — registered Jan 25, 2026 via NameSilo |
| `86.38.225.59` | IPv4 | bumptobabeco.top resolved IP — Lithuania, AS398465 rackdog llc |
| `imansport[.]ir` | domain | VBScript lure delivery endpoint |
| `solpru[.]com` | domain | DocuSign phishing lure page — confirms e-signature social engineering theme |
| `checkfirst[.]net` | domain | Phishing email sender domain (Elastic Security Labs) |
| `checkfirst[.]net.au` | domain | Phishing sender domain — AU variant; lower confidence |
| `http://imansport.ir/download_invitee.php` | URL | VBScript download endpoint |
| `http://solpru.com/process/docusign.html` | URL | DocuSign impersonation lure page |
| `https://bumptobabeco.top/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest` | URL | Direct ScreenConnect MSI delivery URL — first seen serving March 19, 2026 |
| Cloudflare R2 (`r2.dev`) | hosting | VBScript payload hosting |
| Google Drive | hosting | C# second-stage payload staging |

### bumptobabeco.top C2 Server Profile

| Field | Value |
| :--- | :--- |
| Registered | January 25, 2026 (NameSilo, privacy-guarded) |
| Hosting IP | `86.38.225.59` — Lithuania, AS398465 rackdog llc |
| Port 443 | Fully operational weaponized ScreenConnect server |
| TLS Certificate | Let's Encrypt, issued to `bumptobabeco.top` |
| Port 443 title | `ScreenConnect Remote Support Software` |
| Port 80 | Default IIS cover page (Windows Server) |
| First MSI served | March 19, 2026 |
| Server fingerprint hash | `c3d4361939d3f6cf2fe798fef68d4713141c48dce7dd29d3838a5d0c66aa29c7` |

> Port 443 on `86.38.225.59` was confirmed serving a live weaponized ScreenConnect management console as of March 2026 — not just a relay, but the full C2 panel. The server fingerprint hash can be used with Shodan/Censys to hunt for additional infrastructure with the same ScreenConnect configuration.

### Threat Actor Contact / Email IOCs

| Address | Confidence | Notes |
| :--- | :--- | :--- |
| `dan@checkfirst.net.au` | High | Confirmed phishing campaign sender (Elastic Security Labs) |
| `advenwolf@proton.me` | Low | Co-listed with `dan@checkfirst.net.au` in OTX pulse 69cd44f1 — possible operator ProtonMail address or campaign registration email |

### Local IPC Port

```
41431   (TCP, localhost — used by StopSimpleGatewayService.exe to communicate with the running RAT service)
```

---

## #️⃣ File Hashes (SHA-256)

| Filename | SHA-256 |
| :--- | :--- |
| `e-Signature-Key_Access_ID-MY7362HY73E.exe` | `b555ceff3236a8175b48b892c1ebc4977fc82c623f3c15ed1efab0c4ac61a9b6` |
| `rq.msi` | `924600a3a55c196b362e82151fbc3f9dcf03dc29e6c45e0bd113d7b0d95c6850` |
| `rqe.exe` | `959524efe7d4aa6a132a88daf7d1e1871fa14eae8a6025ba73ab1fb65f7e4f22` |
| `Remote_Access_Service.exe` | `bdbdbffb37bc421edac4ac5b20c72db1c72d7f6e819e115c96cde5413146bb36` |
| `StopSimpleGatewayService.exe` | `d26b8e1ba6383b1f7749a133cfbf90e85a22a4bece9f171ed57a3d1ab7833f48` |
| `SimpleService.exe` | `d14a1f14d6ca46bd2168b9d2acf281d8eea62d30e2869d47dd4bf0ad556fb9a2` |
| `ScreenConnect.WindowsAuthenticationPackage.dll` | `a5b8f0070201e4f26260af6a25941ea38bd7042aefd48cd68b9acf951fa99ee5` |
| `SILENTCONNECT reference sample` | `8bab731ac2f7d015b81c2002f518fff06ea751a34a711907e80e98cf70b557db` |

---

## 🏷️ Campaign Identifiers

### Campaign Profile Names (decoded from hex in JWrapper logs)

```
Transport office101/103/AUTODETECT    (initial profile — observed March 30 – April 4)
Star 2026/AUTODETECT                  (rotated profile — observed April 5 onward)
```

> Profile rotation mid-intrusion is consistent with an initial access broker (IAB) handing off or selling the session to a secondary ransomware operator.

### Application Profile IDs

```
30994437457905930274238194135013257   (initial profile)
32662606070342690172655316692737204611 (post-rotation profile)
```

### RAT Session ID

```
SG_3243431771723114121
```

### C2 Registration Key (`reckey`) — Links All Three Relay Servers to Same Operator

```
9F6D305069D23FF1265FA557A597E0CF5EBAE0BEA0EE1BA49A0546E15B809263EB5C0C6AFF2D08B8C9208BDB03B2EDD0A58915D052F76CD9C6B399C414471997
```

### ScreenConnect Assembly Token (directory name fragment — identifies this specific payload build)

```
27fa83f1ad328157    (present in ClickOnce cache directory names across all April 2026 victims)
420d02d3849b7992    (Core/Windows DLL token — same across all April 2026 victims)
```

### JWrapper Package Versions

```
JWrapper core:          00118607049
Remote Access bundle:   00118607124  (SimpleHelp v5.5.14)
Windows JRE:            00118596800  (JRE 21.0.8)
ScreenConnect version:  25.2.4.9229
```

### Package Hash Sentinel Files (zero-byte, named by SHA-256)

```
ba136626de3df076f7210ffde178060755007ae8c2a82e3392424f4b015fd80e3b02797753769c143cc2a46e59d9a5ce8139208405443a433522b48d959bf6e2
c0ff50beeefa3822b38afe48b5296a8e15d92096b16583a06ece69027f9455482ef6b1d473f0f7f272593222dfc85dc64a5fe9419ec0756401d10b58bb7a5989
e616c631f41874299b8c8306861e080be6528df51d27b72b4329257020491c123b49b93ff6fa2ff7d73dd2c4c023662f9248ee74ce19232ade2e2a377611fe95
```

---

## 🖥️ Process Indicators

The following processes were confirmed running simultaneously on infected machines via Windows ETL trace analysis. Presence of **all three RAT processes together** is a high-confidence indicator of active dual-channel infection.

### Malicious Processes (Always Investigate)

| Process | Description |
| :--- | :--- |
| `SimpleService.exe` | JWrapper SafeBoot persistence daemon |
| `Remote Access Service.exe` | JWrapper/SimpleHelp main RAT service |
| `Remote Access.exe` | JWrapper/SimpleHelp launcher alias |
| `ScreenConnect.ClientService.exe` | Stage 1 RAT service |
| `ScreenConnect.WindowsClient.exe` | Stage 1 client |

### False Positive Clarification

The following processes were observed on infected machines but are **legitimate software** used by the affected clients — their presence alone is NOT an indicator of compromise:

| Process | Legitimate Use |
| :--- | :--- |
| `TeamViewer_Service.exe` | TeamViewer — legitimate remote support tool used by these clients |
| `ZohoURSService.exe` | Zoho Assist — legitimate RMM used by these clients |
| `MBAMService.exe` | Malwarebytes Anti-Malware — present and running but did not detect this infection |
| `QBW.EXE` + QB services | QuickBooks — present on business victim machines |
| `OUTLOOK.EXE` | Microsoft Outlook — present on business victim machines |

> **Critical note for business victims running QuickBooks and Outlook:** These applications were confirmed present and running during the dwell window on at least one infected business machine. Treat all credentials, financial data, and email history as compromised regardless of whether financial fraud has been discovered yet.

---

## 🚨 Behavioral Signatures & TTPs (MITRE ATT&CK)

| Tactic | Technique | Detail |
| :--- | :--- | :--- |
| Initial Access | T1566.001 | Spearphishing attachment — fake e-signature file or VBScript lure |
| Initial Access | T1656 | Impersonation — e-signature brand (DocuSign/Adobe style lure) or fake invitation |
| Execution | T1204.002 | User Execution: Malicious File |
| Execution | T1059.001 | PowerShell — VBScript variant compiles C# in-memory; post-install hidden PS execution |
| Execution | T1059.005 | VBScript — SILENTCONNECT VBScript loader variant |
| Execution | T1218.007 | System Binary Proxy Execution: Msiexec — `msiexec.exe /i ScreenConnect.ClientSetup.msi` |
| Persistence | T1543.003 | Create/Modify System Process: Windows Service |
| Persistence | T1547 | Boot/Logon Autostart — SafeBoot registry key |
| Privilege Escalation | T1548.002 | Bypass UAC — DigiCert-signed NSIS installer (blue UAC prompt); VBScript variant uses CMSTPLUA COM interface |
| Defense Evasion | T1036.005 | Masquerading — `.scr` extension, fake e-signature filename |
| Defense Evasion | T1553.002 | Code Signing — valid DigiCert Authenticode certificate on dropper |
| Defense Evasion | T1218 | System Binary Proxy Execution — JVM/JWrapper launches payload |
| Defense Evasion | T1562 | Impair Defenses — polls for and removes legitimate RMM agents |
| Defense Evasion | T1055.001 | PEB Masquerading — VBScript variant overwrites `BaseDLLName` to `winhlp32.exe` |
| Defense Evasion | T1140 | Deobfuscate/Decode Files — VBScript variant compiles C# from plaintext at runtime |
| C2 | T1219 | Remote Access Tools — ScreenConnect + SimpleHelp both weaponized |
| C2 | T1071.001 | Application Layer Protocol: HTTP traffic disguised on port 443 |
| C2 | T1568 | Dynamic Resolution — anonymous DNS (`anondns.net`) for Stage 1 C2 |
| C2 | T1573 | Encrypted Channel — RSA-2048 session keys for JWrapper C2 auth |
| C2 | T1102 | Web Service — VBScript variant uses Google Drive and Cloudflare R2 as staging |
| Collection | T1113 | Screen Capture — `AllowMonitoring=true`, `mdupload` class active |
| Collection | T1056.001 | Keylogging — capability present via active remote desktop control |
| Exfiltration | T1041 | Exfiltration over C2 Channel — Zstandard-compressed uploads |
| Lateral Movement | T1021 | Remote Services — SYSTEM-level access enables local network pivot |
| Injection | T1055 | Process Injection — `CreateRemoteThread` in `jwutils_win32/64.dll` |
| Discovery | T1518.001 | Security Software Discovery — WMI polls for `MBAMService` and `WinDefend` |

### Additional Behavioral Notes

- **Operator timezone:** Monitoring sessions observed at `03:44` local time suggest threat actor operates in **UTC+3 to UTC+5** (Eastern Europe / Russia)
- **Complete UI suppression:** ScreenConnect configured with all 13 visibility settings `false` — no tray icon, no banners, no notifications of any kind during active sessions
- **Kill-signal resistance:** JVM launched with `-Xrs` flag, making the process resistant to standard `SIGTERM`/OS kill signals
- **Auto-recovery:** `AllowRecovery=true` causes the service to auto-reconnect if the connection drops
- **Session cleanup:** `AlwaysDeleteSessionOnExit=true` causes ScreenConnect to purge session artifacts on disconnect, reducing forensic trace
- **SafeBoot persistence:** `SimpleService.exe` exports `SetSafeBootKey` and `DeleteSafeBootKey` functions — explicitly designed to survive incident response Safe Mode reboots
- **Redundant C2:** Three JWrapper relay servers are registered simultaneously; if one is unreachable the RAT fails over automatically, with no single point of failure for the attacker
- **Self-updating:** `GenericUpdater` component checks for and applies RAT updates from C2 servers on an ongoing basis
- **Pulseway pre-staging observed:** In at least one victim, the `%APPDATA%\MMSOFT Design\Pulseway\working\` directory was created approximately **one month before** the ScreenConnect infection, suggesting Pulseway may have been used as a reconnaissance or initial access tool in a prior stage

---

## 📅 Confirmed Victim Timeline (Field Data — SW Washington / Portland Metro)

| Date | Event |
| :--- | :--- |
| April 8, 2024 | Victim "Enver" — first infection, `instance-fc5xev` / `147.28.146.148` |
| February 6, 2025 | Victim "Enver" — ScreenConnect payload updated in place (v18.0.004) |
| March 27, 2026 | Pulseway staging directory created on at least one victim machine |
| March 31, 2026 | Earliest observed infection date in current wave (field data) |
| April 29, 2026 20:15 UTC | Victim "Enver" — re-infected / upgraded to current payload (`instance-sis2tc` / `15.204.131.77`) |
| April 29, 2026 22:18 UTC | Victim "Emina" — infected with identical payload, same C2 relay, ~2 hours later |
| May 2026 | 4+ additional victims identified in same geographic area; campaign confirmed active |

---

## 🔍 YARA Rule (Elastic Security Labs — SILENTCONNECT)

```yara
rule Windows_Trojan_SilentConnect_cdc03e84 {
    meta:
        author = "Elastic Security"
        creation_date = "2026-03-04"
        last_modified = "2026-03-04"
        os = "Windows"
        arch = "x86"
        threat_name = "Windows.Trojan.SilentConnect"
        reference_sample = "8bab731ac2f7d015b81c2002f518fff06ea751a34a711907e80e98cf70b557db"
        license = "Elastic License v2"
    strings:
        $peb_evade = "winhlp32.exe" wide fullword
        $rev_elevation = "wen!rotartsinimdA:noitavelE" wide fullword
        $masquerade_peb_str = "MasqueradePEB" ascii fullword
        $guid = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" wide fullword
        $unique_str = "PebFucker" ascii fullword
        $peb_shellcode = { 53 48 31 DB 48 31 C0 65 48 8B 1C 25 60 00 00 00 }
        $rev_screenconnect = "tcennoCneercS" ascii wide
    condition:
        5 of them
}
```

---

## 🔁 Hash Cross-Reference Table
*(MD5 and SHA1 equivalents for community-corroborated SHA256s — source: OTX pulse 69c227a6)*

| SHA256 | MD5 | SHA1 |
| :--- | :--- | :--- |
| `8bab731ac2f7d015b81c2002f518fff06ea751a34a711907e80e98cf70b557db` | `53b705a1ff29b71c0872ee7e969bfaf4` | `d3d5cad0562d3ffd0778e924e45c9a5fd368267b` |
| `349e78de0fe66d1616890e835ede0d18580abe8830c549973d7df8a2a7ffdcec` | `55c81017eee2ba0db983521b9b769f00` | `d24be8e27e1bd58508c662a74c1358e928d37509` |
| `c3d4361939d3f6cf2fe798fef68d4713141c48dce7dd29d3838a5d0c66aa29c7` | `658186a75f2a6caba5b7e4af2d4651ca` | `0c950ea3559e7df8118bc8249afb75dd4013ef56` |
| `81956d08c8efd2f0e29fd3962bcf9559c73b1591081f14a6297e226958c30d03` | `8cc8e4835de092468989d8a2ffcb730a` | `7a5fbbdb2aa7e2c4ddc82c3620d733810d587c27` |
| `281226ca0203537fa422b17102047dac314bc0c466ec71b2e6350d75f968f2a3` | `cf846e3ce4db94168669eb8dcfe4d956` | `3d99898c8e746bfb46d2333954867acb3d91714c` |
| `adc1cf894cd35a7d7176ac5dab005bea55516bc9998d0c96223b6c0004723c37` | `fa251523d7da027f49aad93d6049d40e` | `f4f9cfda5bea62a13734c844609d6a8112b6c886` |

Additional SHA1 from OTX pulse 69bd45 (SILENTCONNECT loader variant):
```
1b576ebba5b7bbd023eea1b15dac1ed3fb76a211
```

> **Note:** MD5/SHA1 values above are community-sourced (OTX cross-reference pulses) and have not been independently verified against field-collected samples. Use SHA256 as the authoritative identifier.

---

## 🔗 OTX Threat Intelligence References

This IOC set is published and cross-referenced on AlienVault OTX. Related pulses confirming these indicators:

| Pulse ID | Author | Description |
| :--- | :--- | :--- |
| [6a18e9c64ab0a08568d345cd](https://otx.alienvault.com/pulse/6a18e9c64ab0a08568d345cd) | pnwcomputers | Field-sourced IOCs — this repository (20 indicators, TLP:Amber) |
| [69bd45393fac7e92bd363cad](https://otx.alienvault.com/pulse/69bd45393fac7e92bd363cad) | celestre | IOC — SILENTCONNECT (Elastic Security Labs direct) |
| [69c227a65f707b407e32de6c](https://otx.alienvault.com/pulse/69c227a65f707b407e32de6c) | CyberHunter_NL | SILENTCONNECT hash cross-reference |
| [69af7bd5ef2e0695343cd117](https://otx.alienvault.com/pulse/69af7bd5ef2e0695343cd117) | — | RouterHosting/Cloudzy infrastructure (partial overlap) |

> The 7 related pulses auto-linked by OTX confirm these IOCs are corroborated by the broader threat intel community. The `bumptobabeco.top` domain has 4 independent related pulses across OTX.
---

*All IOCs verified from live field incident data unless otherwise noted.*
*Pacific Northwest Computers — jon@pnwcomputers.com | 360-624-7379*
*Last updated: May 2026*
*Contributions welcome — see CONTRIBUTE.md*

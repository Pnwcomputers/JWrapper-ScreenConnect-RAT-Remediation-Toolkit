# Medusa IAB Variant (JWrapper/ScreenConnect) — IOC Data Sheet

This is a field-sourced document of known Indicators of Compromise (IOCs) associated with the dual-channel JWrapper/SimpleHelp and weaponized ScreenConnect intrusion chain, frequently utilized by Initial Access Brokers (IABs) linked to Medusa Ransomware. All entries below are confirmed from real incident response and forensic analysis of live infections.

*Contributions: Submit a pull request or open an issue to add new IOCs observed in the wild.*

---

## 📂 File Names & Payloads

### Stage 1: Initial Lure & ScreenConnect

| Filename | Description |
| :--- | :--- |
| `e-Signature-Key_Access_ID-MY7362HY73E.exe` | Initial lure / NSIS v2.51 installer. Carries a valid DigiCert Authenticode cert. |
| `e-Signature-Key_Access_ID-MY7362HY73E (1).exe` | Duplicate variant (observed on some systems) |
| `rq.msi` | Weaponized ConnectWise ScreenConnect v25.2.4.9229 installer |
| `rqe.exe` | Custom DotNetRunner — manages the ScreenConnect session |
| `ScreenConnect.WindowsClient.exe` | ScreenConnect remote access client |
| `ScreenConnect.WindowsFileManager.exe` | ScreenConnect file transfer component |
| `ScreenConnect.WindowsBackstageShell.exe` | ScreenConnect remote command shell |
| `ScreenConnect.WindowsAuthenticationPackage.dll` | Windows credential provider integration DLL |
| `system.config` | ScreenConnect C2 relay configuration (contains `gqpplgq2g.anondns.net:8041` and RSA-2048 auth key) |
| `app.config` | ScreenConnect stealth configuration (all 13 user-visibility settings explicitly set to `false`) |

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
| `serviceconfig.xml` | Live C2 configuration file — contains relay IPs, registration key, and capability flags |
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
C:\Program Files\ScreenConnect Client*\
C:\Program Files (x86)\ScreenConnect Client*\
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
```

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

### Stage 1 — ScreenConnect Relay

| Address | Port | Protocol | Notes |
| :--- | :--- | :--- | :--- |
| `gqpplgq2g.anondns.net` | `8041` | TCP | Anonymous dynamic DNS — conceals true server location |

### Stage 2 — JWrapper / SimpleHelp Gateways

| Address | Port | Protocol | Role |
| :--- | :--- | :--- | :--- |
| `147.45.218.0` | `443` | HTTP (over HTTPS port) | Primary C2 relay |
| `91.215.85.219` | `443` | HTTP (over HTTPS port) | Redundant C2 relay |
| `147.45.218.13` | `443` | HTTP (over HTTPS port) | Redundant C2 relay |

> All three JWrapper relays use port 443 to blend with HTTPS traffic and bypass firewall rules. They share a single registration key (see Campaign Identifiers), confirming single-operator control.

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

## 🚨 Behavioral Signatures & TTPs (MITRE ATT&CK)

| Tactic | Technique | Detail |
| :--- | :--- | :--- |
| Initial Access | T1566.001 | Spearphishing attachment — fake e-signature file |
| Initial Access | T1656 | Impersonation — e-signature brand (DocuSign/Adobe style lure) |
| Execution | T1204.002 | User Execution: Malicious File |
| Execution | T1059.001 | PowerShell — confirmed executed immediately post-install |
| Persistence | T1543.003 | Create/Modify System Process: Windows Service |
| Persistence | T1547 | Boot/Logon Autostart — SafeBoot registry key |
| Privilege Escalation | T1548.002 | Bypass UAC via DigiCert-signed NSIS installer |
| Defense Evasion | T1036.005 | Masquerading — `.scr` extension, fake e-signature filename |
| Defense Evasion | T1553.002 | Code Signing — valid DigiCert Authenticode certificate on dropper |
| Defense Evasion | T1218 | System Binary Proxy Execution — JVM/JWrapper launches payload |
| Defense Evasion | T1562 | Impair Defenses — polls for and removes legitimate RMM agents |
| C2 | T1219 | Remote Access Tools — ScreenConnect + SimpleHelp both weaponized |
| C2 | T1071.001 | Application Layer Protocol: HTTP traffic disguised on port 443 |
| C2 | T1568 | Dynamic Resolution — anonymous DNS (`anondns.net`) for Stage 1 C2 |
| C2 | T1573 | Encrypted Channel — RSA-2048 session keys for JWrapper C2 auth |
| Collection | T1113 | Screen Capture — `AllowMonitoring=true`, `mdupload` class active |
| Collection | T1056.001 | Keylogging — capability present via active remote desktop control |
| Exfiltration | T1041 | Exfiltration over C2 Channel — Zstandard-compressed uploads |
| Lateral Movement | T1021 | Remote Services — SYSTEM-level access enables local network pivot |
| Injection | T1055 | Process Injection — `CreateRemoteThread` in `jwutils_win32/64.dll` |
| Discovery | T1518.001 | Security Software Discovery — WMI polls for `MBAMService` (Malwarebytes) and `WinDefend` |

### Additional Behavioral Notes

- **Operator timezone:** Monitoring sessions observed at `03:44` local time suggest threat actor operates in **UTC+3 to UTC+5** (Eastern Europe / Russia)
- **Complete UI suppression:** ScreenConnect configured with all 13 visibility settings `false` — no tray icon, no banners, no notifications of any kind during active sessions
- **Kill-signal resistance:** JVM launched with `-Xrs` flag, making the process resistant to standard `SIGTERM`/OS kill signals
- **Auto-recovery:** `AllowRecovery=true` causes the service to auto-reconnect if the connection drops
- **SafeBoot persistence:** `SimpleService.exe` exports `SetSafeBootKey` and `DeleteSafeBootKey` functions — explicitly designed to survive incident response Safe Mode reboots
- **Redundant C2:** Three relay servers are registered simultaneously; if one is unreachable the RAT fails over automatically, with no single point of failure for the attacker
- **Self-updating:** `GenericUpdater` component checks for and applies RAT updates from C2 servers on an ongoing basis

---

*All IOCs verified from live field incident data.*
*Pacific Northwest Computers — jon@pnwcomputers.com | 360-624-7379*
*Contributions welcome — see CONTRIBUTE.md*

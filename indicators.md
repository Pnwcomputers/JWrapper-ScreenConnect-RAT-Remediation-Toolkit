# Medusa IAB Variant (JWrapper/ScreenConnect) - Indicators of Compromise (IOC) Data Sheet

This is a community-driven document of known Indicators of Compromise (IOCs) associated with the dual-channel JWrapper/SimpleHelp and weaponized ScreenConnect intrusion chain, frequently utilized by Initial Access Brokers (IABs) linked to Medusa Ransomware. This information is actual data on the files, folders, registry entries, etc found when responding to, or cleaning up an affected network and/or system(s) in the field.

*Contributions: Please submit a pull request or issue to add new IOCs observed in the wild.*

## 📂 File Names & Payloads

### Stage 1: Dropper & ScreenConnect (Weaponized)
* `e-Signature-Key_Access_ID-MY7362HY73E.exe` (Initial Lure / NSIS Installer)
* `e-Signature-Key_Access_ID-MY7362HY73E (1).exe`
* `rq.msi` (ScreenConnect Installer, silent deployment)
* `rqe.exe` (Custom DotNetRunner)
* `ScreenConnect.WindowsClient.exe`
* `ScreenConnect.WindowsFileManager.exe`
* `ScreenConnect.WindowsBackstageShell.exe`
* `ScreenConnect.WindowsAuthenticationPackage.dll`

### Stage 2: JWrapper / SimpleHelp RAT
* `officeSH26_working_verf.scr` (JWrapper Deployment Payload)
* `Remote_Access_Service.exe` (Main Service Executable)
* `Remote AccessWinLauncher.exe`
* `SimpleService.exe` (SafeBoot persistence setter)
* `StopSimpleGatewayService.exe` (Malware maintenance utility)
* `jwutils_win32.dll` (Contains `CreateRemoteThread` process injection)
* `jwutils_win64.dll` (Contains `CreateRemoteThread` process injection)
* `libzstd-jni.dll` (Zstandard compression for C2 exfiltration)

## 📁 Known File Paths

### Malware Installation Directories
* `C:\ProgramData\JWrapper-Remote Access\` (Entire directory tree)
* `C:\Windows\SystemTemp\ScreenConnect\`
* `%TEMP%\ScreenConnect\`
* `C:\Program Files\ScreenConnect Client*\`
* `C:\Program Files (x86)\ScreenConnect Client*\`

### Malicious Tool/Script Execution Paths
* `C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\working\toolbox-*\` (Used for executing secondary payload scripts)
* *Example:* `C:\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\working\toolbox-7486505558619514016\remove20msp20rmm*.ps1`

### Developer Build Paths (Embedded in Binaries)
* `C:\Users\jmorgan\Source\cwcontrol\Custom\DotNetRunner\Release\DotNetRunner.pdb`
* `C:\Compile\screenconnect\Product\WindowsAuthenticationPackage\bin\Release\`

## 🔑 Registry Keys (Persistence)

* **SafeBoot Persistence (CRITICAL):** * `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Remote Access Service`
* **Service Registration:**
  * `HKLM\SYSTEM\CurrentControlSet\Services\Remote Access Service`
  * `HKLM\SYSTEM\CurrentControlSet\Services\ScreenConnect Client*`
* **Uninstall Hive (Masquerading):**
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Remote Access`

## 🌐 Network Infrastructure (C2)

### Stage 1: ScreenConnect Relays
* `gqpplgq2g.anondns.net:8041`

### Stage 2: JWrapper / SimpleHelp Gateways
* `http://147.45.218.0:443`
* `http://91.215.85.219:443`
* `http://147.45.218.13:443`

## #️⃣ Known File Hashes (SHA-256)

| Filename | SHA-256 Hash |
| :--- | :--- |
| `e-Signature-Key...exe` | `b555ceff3236a8175b48b892c1ebc4977fc82c623f3c15ed1efab0c4ac61a9b6` |
| `rq.msi` | `924600a3a55c196b362e82151fbc3f9dcf03dc29e6c45e0bd113d7b0d95c6850` |
| `rqe.exe` | `959524efe7d4aa6a132a88daf7d1e1871fa14eae8a6025ba73ab1fb65f7e4f22` |
| `Remote_Access_Service.exe` | `bdbdbffb37bc421edac4ac5b20c72db1c72d7f6e819e115c96cde5413146bb36` |
| `StopSimpleGatewayService.exe` | `d26b8e1ba6383b1f7749a133cfbf90e85a22a4bece9f171ed57a3d1ab7833f48` |
| `SimpleService.exe` | `d14a1f14d6ca46bd2168b9d2acf281d8eea62d30e2869d47dd4bf0ad556fb9a2` |

## 🏷️ Campaign Identifiers

* **Active Campaign IDs:** * `Transport office101/103/AUTODETECT`
  * `Star 2026/AUTODETECT`
* **JWrapper Registration Key (reckey):** * `9F6D305069D23FF1265FA557A597E0CF5EBAE0BEA0EE1BA49A0546E15B809263EB5C0C6AFF2D08B8C9208BDB03B2EDD0A58915D052F76CD9C6B399C414471997`
* **Malware Services:** `Remote Access Service`, `ScreenConnect Client (*)`

## 🚨 Behavioral Signatures & TTPs

* **Execution:** Impersonates e-signature applications utilizing valid DigiCert code-signing certificates to bypass UAC prompts.
* **Defense Evasion:** * Disables all 13 user-facing notifications for ScreenConnect.
  * Modifies the `SafeBoot` registry hive to retain persistence in Safe Mode.
  * Executes hidden PowerShell scripts (`remove20msp20rmm*.ps1`) to forcefully uninstall legitimate RMM agents (e.g., Datto RMM).
* **Discovery:** Actively polls for the presence of `MBAMService` (Malwarebytes) and `WinDefend` (Windows Defender) using WMI.

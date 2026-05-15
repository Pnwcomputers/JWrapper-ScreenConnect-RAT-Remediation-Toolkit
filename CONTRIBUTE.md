# Contributing to the Medusa IAB IOC Repository

First off, thank you for considering contributing to this repository. It is through community collaboration that we can track, identify, and mitigate these highly organized intrusion chains.

This repository relies on real-world data gathered during incident response engagements. Your contributions help sysadmins and security engineers worldwide defend against Initial Access Brokers (IABs) and the ransomware deployments they facilitate.

---

## What to Contribute

We are actively looking for the following types of data related to **JWrapper/SimpleHelp** and **Weaponized ScreenConnect** infections:

- **File Hashes:** New SHA-256 hashes of droppers, installers, DLLs, or payload components.
- **Network IOCs:** New IP addresses, domains (especially dynamic DNS like `anondns.net`), relay ports, or C2 hostnames.
- **File Paths:** New directories or naming conventions used by the malware (e.g., new `toolbox` script names or lure filename patterns).
- **Registry Keys:** New persistence mechanisms, especially variations of the `SafeBoot` registry modification or new Scheduled Task names.
- **Campaign Identifiers:** New profile names, session IDs, or `reckey` values decoded from JWrapper logs.
- **Behavioral Signatures:** New TTPs, security product polling behavior, or RMM agent uninstall scripts observed in the wild.
- **Remediation Improvements:** Updates to `Check-System.ps1`, `Fix.ps1`, or `RUN_ME.bat` to handle new malware variants or edge cases.

---

## What NOT to Submit

To keep this repository safe and responsible:

- **Do not submit actual malware binaries, DLLs, or executable files.** Hashes and metadata only.
- **Do not submit embedded cryptographic keys, private tokens, or session credentials** extracted from malware samples.
- **Do not submit unredacted client data** of any kind — see sanitization requirements below.
- **Do not submit theoretical or unverified IOCs.** This repository is for field-confirmed data only.

---

## How to Contribute

### Option 1 — Report a New IOC via GitHub Issues (Easiest)

If you have new indicators but don't want to edit the documentation yourself:

1. Navigate to the **[Issues](../../issues)** tab.
2. Click **New Issue**.
3. Include as much context as possible:
   - What the file is and what it does
   - Where it was found (directory path)
   - SHA-256 hash
   - Date of first observation
   - Campaign name or profile identifier if known
   - Any associated network IOCs (defanged — see guidelines below)

### Option 2 — Submit a Pull Request

To add data directly to `indicators.md` or improve the remediation scripts:

1. **Fork** the repository to your own GitHub account.
2. **Clone** your fork to a local machine.
3. **Create a new branch** for your update:
   ```
   git checkout -b add-new-iocs-june-2026
   ```
4. **Make your changes** to `indicators.md` or the relevant script files. Keep formatting consistent with the existing layout.
5. **Commit** with a clear, descriptive message:
   ```
   git commit -m "Add new JWrapper C2 relay IP and updated campaign profile name"
   ```
6. **Push** your branch to your fork:
   ```
   git push origin add-new-iocs-june-2026
   ```
7. Open a **Pull Request** against the `main` branch of this repository.

---

## Contribution Guidelines

### Defang Network Indicators

When including IPs, domains, or URLs in Issues or PR descriptions, defang them to prevent accidental clicks:

```
147[.]45[.]218[.]0
hXXp://91[.]215[.]85[.]219:443
gqpplgq2g[.]anondns[.]net
```

In `indicators.md` itself, plain format is fine since the document is used for hunting and blocking — just be consistent with the existing style.

### Real-World Data Only

Only submit IOCs verified during an actual incident response or malware analysis engagement. No theoretical, generated, or hypothetical indicators.

### Context Is Everything

A file hash alone is useful. A file hash *plus* the directory it was found in *plus* the registry key that launched it *plus* the campaign profile it was associated with is far more valuable. Provide as much surrounding context as you legally and safely can.

### Sanitize Before Submitting — CRITICAL

Before submitting any logs, screenshots, config files, or extracted data, **scrub all of the following**:

- Internal hostnames and computer names
- Internal IP addresses (RFC 1918 ranges: 10.x, 172.16–31.x, 192.168.x)
- Usernames, employee names, or any PII
- Company names, client names, or identifying business information
- Email addresses (other than attacker infrastructure)
- File paths that contain usernames (e.g., `C:\Users\john.smith\...` → replace with `C:\Users\[USERNAME]\...`)

If you are unsure whether something is safe to share, err on the side of caution and open an Issue with a summary instead.

---

## Code of Conduct

By participating in this project, you agree to abide by standard open-source community guidelines. Be respectful, constructive, and focused on the shared goal of improving defensive cybersecurity. Contributions intended to enable offensive use of this data will be rejected.

---

*Pacific Northwest Computers — Vancouver, WA*
*jon@pnwcomputers.com | 360-624-7379*

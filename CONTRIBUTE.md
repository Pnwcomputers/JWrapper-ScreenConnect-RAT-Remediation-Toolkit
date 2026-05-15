# Contributing to the Medusa IAB IOC Repository

First off, thank you for considering contributing to this repository! It is exactly through community collaboration that we can track, identify, and mitigate these highly organized intrusion chains. 

This repository relies on real-world data gathered during incident response engagements. Your contributions help sysadmins and security engineers worldwide defend against Initial Access Brokers (IABs) and the ransomware deployments they facilitate.

## What to Contribute

We are actively looking for the following types of data related to **JWrapper/SimpleHelp** and **Weaponized ScreenConnect** infections:

* **File Hashes:** New SHA-256 hashes of droppers, installers, or malicious DLLs.
* **Network IOCs:** New IP addresses, domains (especially dynamic DNS like `anondns.net`), or specific ports used for Command and Control (C2).
* **File Paths:** New directories or naming conventions used by the malware (e.g., new `toolbox` script names).
* **Registry Keys:** Any new persistence mechanisms, especially variations of the `SafeBoot` registry modification.
* **Remediation Scripts:** Improvements to the PowerShell/Batch cleanup tools to handle new malware variants.

## How to Contribute

### 1. Reporting a New IOC (Easiest Method)
If you have new indicators but don't want to modify the documentation yourself:
1.  Navigate to the **Issues** tab.
2.  Click **New Issue**.
3.  Provide as much context as possible: What the file is, where it was found, the SHA-256 hash, and the date of discovery. 

### 2. Submitting a Pull Request (PR)
If you want to add the data directly to the `IOC_Data_Sheet.md` or improve the remediation scripts:
1.  **Fork** the repository to your own GitHub account.
2.  **Clone** the project to your local machine.
3.  **Create a new branch** for your update:
    `git checkout -b add-new-iocs-may-2026`
4.  **Make your changes** to the relevant Markdown files or scripts. Please keep formatting consistent with the existing layout.
5.  **Commit** your changes with a clear, descriptive message:
    `git commit -m "Add new ScreenConnect C2 relay domain"`
6.  **Push** your branch to your forked repository:
    `git push origin add-new-iocs-may-2026`
7.  Open a **Pull Request** from your branch to our `main` branch. 

## Contribution Guidelines

To ensure the data remains accurate and actionable, please adhere to the following guidelines:

* **Defanged Network Indicators:** When submitting URLs or IP addresses in Issues or PR comments, please "defang" them to prevent accidental clicking (e.g., `hXXp://147[.]45[.]218[.]0`). 
* **Real-World Data Only:** Please only submit IOCs that have been verified during an actual incident response or malware analysis engagement. Do not submit theoretical IOCs.
* **Context is Key:** A file hash on its own is okay, but a file hash *plus* the directory it was found in *plus* the registry key that launched it is incredibly valuable. Provide as much surrounding context as you legally and safely can.
* **Sanitize Your Data:** **CRITICAL:** Ensure you scrub any client-specific, identifiable, or sensitive information (usernames, internal hostnames, internal IPs) from your logs before submitting them to this public repository.

## Code of Conduct

By participating in this project, you agree to abide by standard open-source community guidelines. Be respectful, constructive, and focus on the shared goal of improving defensive cybersecurity.

# CAPE Host Scanner

A host-side detection utility that hunts a live or imaged Windows system for the
durable artifacts of [CAPE Sandbox](https://github.com/CAPESandbox/community)
behavioral signatures. CAPE signatures normally classify a malware sample *after*
detonation by inspecting its API-call trace; this utility extracts the
statically-reachable indicators from those signatures and checks for them on a
real host — registry autostart/tamper keys, on-disk file paths, services,
process command lines, network IOCs, and ransom-note-style file content.

Read-only. Makes no changes to the system it scans.

## Files

| File | Role | Runs on |
|------|------|---------|
| `extract_cape_indicators.py` | Mines the CAPE signature corpus, classifies each signature, builds the indicator pack | Any Python 3.8+ host |
| `indicator_pack.json` | The extracted indicators the scanner consumes (regenerate to update) | data |
| `Invoke-CapeHostScan.ps1` | The scanner — matches the pack against host state | Windows (PS 5.1 / 7+) |
| `ref_matcher.py` | Reference matching engine; validates scanner logic, never touches a host | Any Python (optional) |
| `coverage_report.md` | Human-readable reachability report for the signature set | reference |

## Coverage at a glance

Across **614** CAPE Windows signatures: **171 (28%)** are statically host-scannable,
2 are runtime-only (mutexes), and **441 (72%)** are behavioral-only — pure
API-sequence logic with no on-disk residue. This utility covers the 28%. The
behavioral majority needs live telemetry (Sysmon/Sigma); see *Roadmap*.

## Requirements

- **Windows PowerShell 5.1 or PowerShell 7+**
- Run **elevated** for full registry / service / process coverage
- Python 3.8+ only if you want to (re)generate the indicator pack

## Quick start

```powershell
# one-time setup in the scanner's folder
Unblock-File .\Invoke-CapeHostScan.ps1        # strip mark-of-the-web
Set-ExecutionPolicy -Scope Process Bypass     # this session only

# 1. verify the matching engine on your box (no system access)
.\Invoke-CapeHostScan.ps1 -Pack .\indicator_pack.json -SelfTest
#    expect: "4/4 expected signatures fired" + generic-FP suppressed

# 2. real scan
.\Invoke-CapeHostScan.ps1 -Pack .\indicator_pack.json -OutDir .\out -IncludeStringScan
```

Regenerating the pack (on any Python host):

```bash
python3 extract_cape_indicators.py --clone ./_cape
# -> indicator_pack.json + coverage_report.md
```

## Parameters

| Parameter | Purpose |
|-----------|---------|
| `-Pack <path>` | Path to `indicator_pack.json` (required) |
| `-OutDir <path>` | Output directory for JSON + CSV (default: current dir) |
| `-SelfTest` | Run engine against a synthetic host; no real access |
| `-Categories <list>` | Restrict to CAPE categories, e.g. `ransomware,persistence,stealth` |
| `-IncludeStringScan` | Enable file-content scanning (ransom notes etc.); slower |
| `-IncludeGeneric` | Include low-specificity patterns (high false-positive rate; off by default) |
| `-Root <path>` | Offline/imaged analysis root, e.g. `E:\mount\C` (filesystem + content only) |
| `-MaxFileSizeKB <n>` | Skip files larger than this (default 4096) |

## Output

Console prints a severity-sorted findings table. `OutDir` receives:

- `cape_hostscan_<timestamp>.json` — full evidence, for reports/pipelines
- `cape_hostscan_<timestamp>.csv` — flat triage view

Each finding includes: signature name, CAPE category, severity, MITRE ATT&CK
TTP(s), the pattern that matched, and the exact evidence (registry path, file,
command line, or host).

> **Findings are leads, not verdicts.** These are behavioral indicators
> repurposed as static checks. Legitimate software touches autostart keys and
> common paths, so verify each hit before acting.

## What it does and doesn't reach

- **Covers:** registry autostart/tamper keys, file-path indicators, services,
  process command lines, network IOCs, opt-in ransom-note content.
- **Skips by default:** 128 low-specificity patterns (e.g. "any `.dll`") that
  would flood results; re-enable with `-IncludeGeneric`.
- **Out of scope (Engine 2 territory):** the 441 behavioral-only signatures
  (injection, anti-debug, evasion chains). `coverage_report.md` lists each by
  name with its TTPs.
- **Offline limit:** with `-Root`, only filesystem and content are checked.
  Registry/service/process/network are live-host only.

## Validation

The matching engine — regex-vs-literal detection, generic-pattern suppression,
case handling, per-artifact dispatch — is validated at parity against the full
614-signature corpus via `ref_matcher.py`, and confirmed on Windows PowerShell
via `-SelfTest` (4/4 control signatures fire, generic false positive
suppressed). The Windows collector layer (registry/CIM/network/file walking) is
exercised by real runs.

## Roadmap

- **Engine 2** — translate the behavioral-only TTPs into Sysmon + Sigma rules to
  cover the remaining 72%.
- Offline registry-hive parsing for `-Root` (imaged-disk analysis).
- Scheduled-task XML parsing for persistence signatures.
- Per-signature finding de-duplication.

---

*Pacific Northwest Computers — IT support & cybersecurity, Vancouver WA.
Built on CAPE Sandbox community signatures (GPLv3).*

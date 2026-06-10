<#
.SYNOPSIS
    Invoke-CapeHostScan - Engine 1 of the CAPE-derived host detection utility.

    Consumes indicator_pack.json (produced by extract_cape_indicators.py) and
    checks a live or imaged Windows system for the durable artifacts of the
    ~171 statically-scannable CAPE Sandbox signatures: registry autostart/
    tamper keys, on-disk file paths, services, process command lines, network
    IOCs, and (optionally) ransom-note-style file content.

    Read-only. Makes no changes to the system.

    Matching engine mirrors a Python reference implementation validated against
    the full 614-signature corpus (specific vs generic pattern handling,
    regex vs literal detection, case-insensitive matching).

.PARAMETER Pack
    Path to indicator_pack.json.

.PARAMETER OutDir
    Directory for JSON/CSV output. Default: current directory.

.PARAMETER Root
    Filesystem root for OFFLINE/imaged analysis (e.g. 'E:\mount\C'). Registry,
    service, process and network checks are live-host only and are skipped when
    -Root is set.

.PARAMETER Categories
    Restrict to specific CAPE categories (e.g. ransomware,persistence,stealth).

.PARAMETER IncludeGeneric
    Include low-specificity patterns (e.g. "any .dll"). Off by default; these
    generate high false-positive rates.

.PARAMETER IncludeStringScan
    Enable file-content scanning for string indicators (ransom notes, etc.).
    Heavier; off by default.

.PARAMETER MaxFileSizeKB
    Skip files larger than this during file/content enumeration. Default 4096.

.PARAMETER SelfTest
    Run the matching engine against a built-in synthetic host (no real system
    access) to verify the engine end-to-end. Use this first.

.EXAMPLE
    .\Invoke-CapeHostScan.ps1 -Pack .\indicator_pack.json -SelfTest

.EXAMPLE
    .\Invoke-CapeHostScan.ps1 -Pack .\indicator_pack.json -OutDir .\out `
        -Categories ransomware,persistence,stealth -IncludeStringScan

.NOTES
    Run elevated for full registry/service coverage. PowerShell 5.1+ / 7+.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Pack,
    [string]   $OutDir = (Get-Location).Path,
    [string]   $Root,
    [string[]] $Categories,
    [switch]   $IncludeGeneric,
    [switch]   $IncludeStringScan,
    [int]      $MaxFileSizeKB = 4096,
    [switch]   $SelfTest
)

# ---------------------------------------------------------------------------
# Matching engine (validated parity with Python reference)
# ---------------------------------------------------------------------------
$script:RegexSignals = @('.*', '.+', '\', '[', '(?', '$', '^', '|')
$script:GenericTokens = @('dll','exe','sys','dat','bin','tmp','temp','log',
                          'txt','com','bat','cmd','ini','lnk','db','data')

function Test-IsRegex([string]$pat) {
    foreach ($s in $script:RegexSignals) { if ($pat.Contains($s)) { return $true } }
    if ($pat.Contains('(') -and $pat.Contains(')')) { return $true }
    return $false
}

function Get-LiteralTokens([string]$pat) {
    [regex]::Matches($pat, '[A-Za-z]{3,}') | ForEach-Object { $_.Value.ToLower() }
}

function Test-IsGeneric([string]$pat) {
    $toks = @(Get-LiteralTokens $pat | Select-Object -Unique)
    if ($toks.Count -eq 0) { return $true }
    foreach ($t in $toks) { if ($script:GenericTokens -notcontains $t) { return $false } }
    return $true   # every literal token is just an extension-like anchor
}

function Test-Match([string]$value, [string]$pat) {
    if ([string]::IsNullOrEmpty($value)) { return $false }
    if (Test-IsRegex $pat) {
        try { return [regex]::IsMatch($value, $pat, 'IgnoreCase') }
        catch { return $false }   # malformed upstream pattern
    }
    return $value.ToLower().Contains($pat.ToLower())
}

# artifact type -> host collection key
$script:Dispatch = @{
    registry    = 'registry'
    file        = 'files'
    service     = 'services'
    commandline = 'process_cmdlines'
    argument    = 'process_cmdlines'
    process     = 'process_names'
    network     = 'network'
    string      = 'file_contents'
    mutex       = 'mutexes'
}

# ---------------------------------------------------------------------------
# Load + index the pack
# ---------------------------------------------------------------------------
function Import-IndicatorPack {
    param([string]$Path, [string[]]$Categories, [bool]$IncludeGeneric)
    if (-not (Test-Path $Path)) { throw "indicator pack not found: $Path" }
    $pack = Get-Content -Raw -Path $Path | ConvertFrom-Json

    $index = @{}   # artifactType -> list of @{sig=...; pattern=...}
    $patTotal = 0; $patGeneric = 0; $sigCount = 0
    foreach ($sig in $pack.signatures) {
        if (-not $sig.scannable) { continue }
        if ($Categories -and -not ($sig.categories | Where-Object { $Categories -contains $_ })) { continue }
        $sigCount++
        foreach ($atype in $sig.artifacts.PSObject.Properties.Name) {
            if (-not $script:Dispatch.ContainsKey($atype)) { continue }
            foreach ($pat in $sig.artifacts.$atype) {
                $patTotal++
                if ((Test-IsGeneric $pat) -and -not $IncludeGeneric) { $patGeneric++; continue }
                if (-not $index.ContainsKey($atype)) { $index[$atype] = New-Object System.Collections.ArrayList }
                [void]$index[$atype].Add([pscustomobject]@{
                    Signature   = $sig.name
                    Category    = (@($sig.categories) + '?')[0]
                    Severity    = $sig.severity
                    Ttps        = @($sig.ttps | Where-Object { $_ -like 'T*' })
                    ArtifactType= $atype
                    Pattern     = $pat
                })
            }
        }
    }
    [pscustomobject]@{
        Index = $index; SignatureCount = $sigCount
        PatternTotal = $patTotal; PatternGeneric = $patGeneric
    }
}

# ---------------------------------------------------------------------------
# Host collectors (Windows live; -Root affects filesystem only)
# ---------------------------------------------------------------------------
$script:RegRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
    'HKLM:\SOFTWARE\Microsoft\Command Processor',
    'HKLM:\SYSTEM\CurrentControlSet\Services',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
    'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
)

function Get-RegistryArtifacts {
    $out = New-Object System.Collections.ArrayList
    foreach ($root in $script:RegRoots) {
        if (-not (Test-Path $root)) { continue }
        $keys = @($root)
        try { $keys += (Get-ChildItem -Path $root -Recurse -Depth 2 -ErrorAction SilentlyContinue).PSPath } catch {}
        foreach ($kp in $keys) {
            try {
                $norm = ($kp -replace '^Microsoft\.PowerShell\.Core\\Registry::','' `
                             -replace '^HKEY_LOCAL_MACHINE','HKLM' `
                             -replace '^HKEY_CURRENT_USER','HKCU')
                [void]$out.Add($norm)                            # key path itself
                $props = Get-ItemProperty -Path $kp -ErrorAction SilentlyContinue
                if ($props) {
                    foreach ($p in $props.PSObject.Properties) {
                        if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSProvider','PSDrive') { continue }
                        [void]$out.Add("$norm\$($p.Name)")        # value path
                        if ($p.Value -is [string] -and $p.Value) {
                            [void]$out.Add("$norm\$($p.Name)=$($p.Value)")
                        }
                    }
                }
            } catch {}
        }
    }
    $out
}

function Get-FileArtifacts {
    param([string]$Root, [int]$MaxKB)
    $bases = if ($Root) { @($Root) } else {
        @(
            "$env:SystemRoot\Tasks", "$env:SystemRoot\System32\Tasks",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA", "$env:LOCALAPPDATA", "$env:ProgramData",
            "$env:TEMP", "$env:PUBLIC", "C:\Users"
        ) | Select-Object -Unique
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($b in $bases) {
        if (-not (Test-Path $b)) { continue }
        try {
            Get-ChildItem -Path $b -Recurse -Depth 4 -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -le ($MaxKB * 1KB) } |
                ForEach-Object { [void]$out.Add($_.FullName) }
        } catch {}
    }
    $out
}

function Get-ServiceArtifacts {
    $out = New-Object System.Collections.ArrayList
    try {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$out.Add("$($_.Name)|$($_.DisplayName)|$($_.PathName)")
        }
    } catch {}
    $out
}

function Get-ProcessArtifacts {
    $cmd = New-Object System.Collections.ArrayList
    $names = New-Object System.Collections.ArrayList
    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$cmd.Add(("{0} {1}" -f $_.Name, $_.CommandLine))
            [void]$names.Add($_.Name)
        }
    } catch {}
    @{ cmd = $cmd; names = $names }
}

function Get-NetworkArtifacts {
    $out = New-Object System.Collections.ArrayList
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hosts) {
        Get-Content $hosts -ErrorAction SilentlyContinue |
            Where-Object { $_ -and $_ -notmatch '^\s*#' } |
            ForEach-Object { [void]$out.Add($_.Trim()) }
    }
    try { Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { [void]$out.Add($_.Entry) } } catch {}
    try {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$out.Add($_.RemoteAddress) }
    } catch {}
    $out
}

function Get-FileContentMatches {
    param([System.Collections.ArrayList]$Files, $Patterns, [int]$MaxKB)
    # only text-ish, small files in likely drop locations
    $exts = '.txt','.html','.htm','.hta','.rtf','.md','.log','.url','.nfo',''
    $hits = New-Object System.Collections.ArrayList
    foreach ($f in $Files) {
        $ext = [System.IO.Path]::GetExtension($f).ToLower()
        if ($exts -notcontains $ext) { continue }
        try {
            $content = Get-Content -Raw -Path $f -ErrorAction SilentlyContinue -TotalCount 2000
            if (-not $content) { continue }
            foreach ($p in $Patterns) {
                if (Test-Match $content $p.Pattern) {
                    [void]$hits.Add([pscustomobject]@{ Meta = $p; Evidence = $f })
                }
            }
        } catch {}
    }
    $hits
}

# ---------------------------------------------------------------------------
# Synthetic host for -SelfTest (parity with Python reference fixture)
# ---------------------------------------------------------------------------
function Get-SyntheticHost {
    @{
        registry = @(
            'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Chrome',
            'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater',
            'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
        )
        files = @(
            'C:\Windows\System32\kernel32.dll',
            'C:\Users\jon\AppData\Roaming\tor\torrc',
            'C:\Users\jon\AppData\Roaming\tor\cached-certs'
        )
        services         = @('Spooler|Print Spooler|C:\Windows\System32\spoolsv.exe')
        process_cmdlines = @('explorer.exe C:\Windows\explorer.exe',
                             'schtasks.exe schtasks.exe /CREATE /SC MINUTE /TN evil /TR calc.exe')
        process_names    = @('explorer.exe','svchost.exe')
        network          = @('www.microsoft.com','torproject.org')
        file_contents    = @('Welcome to the company wiki.',
                             'All your files have been encrypted with AES-256. Send bitcoin to recover your data.')
        mutexes          = @()
    }
}

# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------
function Invoke-Scan {
    param($Index, $HostData, [bool]$DoStringScan, [System.Collections.ArrayList]$RawFiles, [int]$MaxKB)
    $findings = New-Object System.Collections.ArrayList

    foreach ($atype in $Index.Keys) {
        if ($atype -eq 'string') { continue }   # handled via content scan below
        $collKey = $script:Dispatch[$atype]
        $items = $HostData[$collKey]
        if (-not $items) { continue }
        foreach ($meta in $Index[$atype]) {
            foreach ($item in $items) {
                if (Test-Match $item $meta.Pattern) {
                    [void]$findings.Add([pscustomobject]@{
                        Signature = $meta.Signature; Category = $meta.Category
                        Severity  = $meta.Severity;  Ttps = ($meta.Ttps -join ',')
                        ArtifactType = $meta.ArtifactType; Pattern = $meta.Pattern
                        Evidence = $item
                    })
                }
            }
        }
    }

    # string/content indicators
    if ($Index.ContainsKey('string')) {
        if ($HostData.ContainsKey('file_contents')) {
            # self-test path: file_contents provided directly
            foreach ($meta in $Index['string']) {
                foreach ($c in $HostData['file_contents']) {
                    if (Test-Match $c $meta.Pattern) {
                        [void]$findings.Add([pscustomobject]@{
                            Signature=$meta.Signature; Category=$meta.Category
                            Severity=$meta.Severity; Ttps=($meta.Ttps -join ',')
                            ArtifactType='string'; Pattern=$meta.Pattern; Evidence=$c
                        })
                    }
                }
            }
        } elseif ($DoStringScan -and $RawFiles) {
            $cm = Get-FileContentMatches -Files $RawFiles -Patterns $Index['string'] -MaxKB $MaxKB
            foreach ($h in $cm) {
                [void]$findings.Add([pscustomobject]@{
                    Signature=$h.Meta.Signature; Category=$h.Meta.Category
                    Severity=$h.Meta.Severity; Ttps=($h.Meta.Ttps -join ',')
                    ArtifactType='string'; Pattern=$h.Meta.Pattern; Evidence=$h.Evidence
                })
            }
        }
    }
    $findings
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
Write-Host "[*] Loading indicator pack: $Pack"
$loaded = Import-IndicatorPack -Path $Pack -Categories $Categories -IncludeGeneric:$IncludeGeneric.IsPresent
Write-Host ("[*] {0} scannable signatures | {1} patterns active, {2} generic skipped" -f `
    $loaded.SignatureCount, ($loaded.PatternTotal - $loaded.PatternGeneric), $loaded.PatternGeneric)

if ($SelfTest) {
    Write-Host "[*] SELF-TEST: scanning synthetic host (no real system access)`n" -ForegroundColor Cyan
    $hostData = Get-SyntheticHost
    $findings = Invoke-Scan -Index $loaded.Index -HostData $hostData -DoStringScan:$false -RawFiles $null -MaxKB $MaxFileSizeKB
    $fired = $findings | Select-Object -ExpandProperty Signature -Unique | Sort-Object
    $findings | Sort-Object Severity -Descending | Format-Table Signature,Category,ArtifactType,Evidence -AutoSize | Out-Host
    $expected = 'network_tor','stealth_hiddenreg','ransomware_message','persistence_autorun'
    $ok = ($expected | Where-Object { $fired -contains $_ }).Count
    Write-Host ("[=] {0}/4 expected signatures fired: {1}" -f $ok, ($fired -join ', '))
    if ($fired -contains 'dotnet_code_compile') {
        Write-Host "[!] generic-pattern FP present (dotnet_code_compile) - generic filter not applied" -ForegroundColor Yellow
    } else {
        Write-Host "[+] generic-pattern FP (kernel32.dll) correctly suppressed" -ForegroundColor Green
    }
    if ($ok -eq 4) { Write-Host "[+] matching engine PASS" -ForegroundColor Green }
    else           { Write-Host "[!] matching engine FAIL - investigate" -ForegroundColor Red }
    return
}

# real scan
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning "Not elevated - registry/service coverage will be partial." }
if ($Root)        { Write-Warning "-Root set: registry/service/process/network checks skipped (live-host only)." }

Write-Host "[*] Collecting host artifacts..."
$rawFiles = Get-FileArtifacts -Root $Root -MaxKB $MaxFileSizeKB
$hostData = @{ files = $rawFiles }
if (-not $Root) {
    $hostData['registry']         = Get-RegistryArtifacts
    $hostData['services']         = Get-ServiceArtifacts
    $proc                         = Get-ProcessArtifacts
    $hostData['process_cmdlines'] = $proc.cmd
    $hostData['process_names']    = $proc.names
    $hostData['network']          = Get-NetworkArtifacts
}
Write-Host ("[*] Collected: files={0} registry={1} services={2} procs={3} net={4}" -f `
    $rawFiles.Count, $hostData['registry'].Count, $hostData['services'].Count,
    $hostData['process_cmdlines'].Count, $hostData['network'].Count)

$findings = Invoke-Scan -Index $loaded.Index -HostData $hostData `
    -DoStringScan:$IncludeStringScan.IsPresent -RawFiles $rawFiles -MaxKB $MaxFileSizeKB

# ---- report ----
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonOut = Join-Path $OutDir "cape_hostscan_$stamp.json"
$csvOut  = Join-Path $OutDir "cape_hostscan_$stamp.csv"

$report = [pscustomobject]@{
    scanned_at      = (Get-Date).ToString('o')
    host            = $env:COMPUTERNAME
    root            = if ($Root) { $Root } else { 'live' }
    elevated        = $isAdmin
    signatures      = $loaded.SignatureCount
    patterns_active = $loaded.PatternTotal - $loaded.PatternGeneric
    finding_count   = $findings.Count
    findings        = $findings
}
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonOut -Encoding UTF8
$findings | Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8

Write-Host ""
if ($findings.Count -eq 0) {
    Write-Host "[+] No matches against scannable CAPE signatures." -ForegroundColor Green
} else {
    Write-Host ("[!] {0} finding(s):" -f $findings.Count) -ForegroundColor Yellow
    $findings | Sort-Object Severity -Descending |
        Format-Table Severity,Signature,Category,ArtifactType,
            @{n='Evidence';e={ if ($_.Evidence.Length -gt 70) { $_.Evidence.Substring(0,70)+'...' } else { $_.Evidence } }} `
            -AutoSize | Out-Host
}
Write-Host "[+] JSON: $jsonOut"
Write-Host "[+] CSV : $csvOut"
Write-Host "`nNote: covers ~28% of CAPE Windows signatures (the statically-reachable set)."
Write-Host "The behavioral-only majority needs Engine 2 (Sysmon/Sigma via the TTP worklist)."

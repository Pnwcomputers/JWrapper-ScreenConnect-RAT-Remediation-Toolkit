#!/usr/bin/env python3
"""Reference implementation of the host-scanner matching engine, used to
validate logic before mirroring it in PowerShell. Same is_regex heuristic
and match semantics the PS scanner will use."""
import json, re, sys

REGEX_SIGNALS = (".*", ".+", "\\", "[", "(", "$", "^", "|", "?")

def is_regex(pat: str) -> bool:
    # treat as regex only if it carries real regex structure; bare literals
    # (incl. domains like torproject.org) are matched as escaped substrings
    return any(sig in pat for sig in (".*", ".+", "\\", "[", "(?", "$", "^", "|")) \
        or ("(" in pat and ")" in pat)

def matches(value: str, pat: str) -> bool:
    if value is None:
        return False
    if is_regex(pat):
        try:
            return re.search(pat, value, re.IGNORECASE) is not None
        except re.error:
            return False
    return pat.lower() in value.lower()

# patterns whose only literal anchors are these are too broad for host scanning
GENERIC_TOKENS = {"dll", "exe", "sys", "dat", "bin", "tmp", "temp", "log",
                  "txt", "com", "bat", "cmd", "ini", "lnk", "db", "data"}

def literal_tokens(pat: str):
    # alphabetic runs of len>=3 that aren't regex metachars
    return [t.lower() for t in re.findall(r"[A-Za-z]{3,}", pat)]

def is_generic(pat: str) -> bool:
    toks = set(literal_tokens(pat))
    if not toks:
        return True                       # nothing but metachars -> matches everything
    return toks.issubset(GENERIC_TOKENS)  # only extension-like anchors

# artifact type -> which host collection it is checked against
DISPATCH = {
    "registry": "registry",
    "file": "files",
    "service": "services",
    "commandline": "process_cmdlines",
    "argument": "process_cmdlines",   # args also matched against cmdlines
    "process": "process_names",
    "network": "network",
    "string": "file_contents",        # content indicators
    "mutex": "mutexes",
}

def scan(pack, host, skip_generic=True):
    hits = []
    skipped = 0
    for sig in pack["signatures"]:
        if not sig["scannable"]:
            continue
        for atype, patterns in sig["artifacts"].items():
            coll_key = DISPATCH.get(atype)
            if not coll_key:
                continue
            for pat in patterns:
                if skip_generic and is_generic(pat):
                    skipped += 1
                    continue
                for item in host.get(coll_key, []):
                    if matches(item, pat):
                        hits.append({
                            "signature": sig["name"],
                            "category": (sig["categories"] or ["?"])[0],
                            "ttps": [t for t in sig["ttps"] if t.startswith("T")][:3],
                            "artifact_type": atype,
                            "pattern": pat,
                            "evidence": item,
                        })
    scan.skipped = skipped
    return hits

# --------------------- synthetic host (validation fixture) ---------------------
HOST = {
    "registry": [
        # benign
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Chrome",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        # SHOULD HIT persistence (Run key) + hidden-reg + IFEO debugger
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
    ],
    "files": [
        r"C:\Windows\System32\kernel32.dll",                       # benign
        r"C:\Users\jon\AppData\Roaming\tor\torrc",                 # SHOULD HIT network_tor
        r"C:\Users\jon\AppData\Roaming\tor\cached-certs",          # SHOULD HIT network_tor
    ],
    "services": [
        "Spooler|C:\\Windows\\System32\\spoolsv.exe",
    ],
    "process_cmdlines": [
        r"C:\Windows\explorer.exe",                                # benign
        r'schtasks.exe /CREATE /SC MINUTE /TN evil /TR calc.exe',  # may hit task-persistence
    ],
    "process_names": ["explorer.exe", "svchost.exe"],
    "network": ["www.microsoft.com", "torproject.org"],            # torproject.org SHOULD HIT
    "file_contents": [
        "Welcome to the company wiki. Nothing to see here.",       # benign
        "All your files have been encrypted with AES-256. "
        "To recover your data send bitcoin to decrypt your files.",# SHOULD HIT ransomware_message
    ],
    "mutexes": [],
}

if __name__ == "__main__":
    pack = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "indicator_pack.json"))
    hits = scan(pack, HOST)
    by_sig = {}
    for h in hits:
        by_sig.setdefault(h["signature"], []).append(h)
    print(f"=== {len(hits)} hits across {len(by_sig)} signatures ===\n")
    for name, hs in sorted(by_sig.items()):
        h0 = hs[0]
        print(f"[{h0['category']:<12}] {name}  ttps={h0['ttps']}")
        for h in hs:
            ev = h["evidence"]
            print(f"    {h['artifact_type']:<11} pat={h['pattern'][:45]!r}")
            print(f"                evidence={ev[:70]!r}")
    print("\n--- expected hits present? ---")
    for want in ["network_tor", "stealth_hiddenreg", "ransomware_message"]:
        print(f"  {want:<22}: {'YES' if want in by_sig else 'NO'}")
    # persistence: any persistence-category sig firing on the Run key?
    persist = [n for n,hs in by_sig.items() if hs[0]['category']=='persistence']
    print(f"  persistence sigs fired : {persist if persist else 'NONE'}")

"""Core static-analysis engine for PAYLOADLAB.

All routines operate on raw bytes only. Nothing is ever executed, decoded into
runnable form, or written back to disk. Findings are heuristic capability
signals, each carrying a severity weight that rolls up into a verdict.
"""
from __future__ import annotations

import base64
import math
import re
import struct
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}


@dataclass
class Finding:
    rule: str
    severity: str          # info|low|medium|high|critical
    description: str
    evidence: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Report:
    path: str
    size: int
    fmt: str
    sha_hint: str          # cheap rolling hash, not crypto - just an id
    entropy: float
    verdict: str = "clean"
    score: int = 0
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _cheap_hash(data: bytes) -> str:
    # FNV-1a 32-bit; only used as a short stable identifier in output.
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return f"{h:08x}"


def _printable_strings(data: bytes, minlen: int = 5) -> List[str]:
    out: List[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "ignore"))
            cur.clear()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out


def _wide_strings(data: bytes, minlen: int = 5) -> List[str]:
    # crude UTF-16LE extraction: printable byte followed by 0x00
    out: List[str] = []
    cur = bytearray()
    i = 0
    n = len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if 0x20 <= lo < 0x7F and hi == 0x00:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "ignore"))
            cur.clear()
            i += 1
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out


URL_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
IP_RE = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")

SUSPICIOUS_IMPORTS = {
    b"VirtualAlloc": ("high", "allocates executable memory (shellcode loader)"),
    b"VirtualProtect": ("high", "changes memory protection (unpacker/injector)"),
    b"WriteProcessMemory": ("critical", "writes into another process (injection)"),
    b"CreateRemoteThread": ("critical", "runs code in another process (injection)"),
    b"SetWindowsHookEx": ("high", "installs a hook (keylogger/injection)"),
    b"LoadLibrary": ("medium", "dynamic module loading"),
    b"GetProcAddress": ("medium", "dynamic API resolution (evasion)"),
    b"WinExec": ("high", "executes a command"),
    b"ShellExecute": ("high", "executes a command/opens a handler"),
    b"URLDownloadToFile": ("critical", "downloads a file (dropper)"),
    b"InternetOpen": ("medium", "network client (C2/download)"),
    b"CryptEncrypt": ("high", "encryption (ransomware/packer)"),
    b"IsDebuggerPresent": ("medium", "anti-debug check"),
    b"CheckRemoteDebuggerPresent": ("medium", "anti-debug check"),
}

ELF_SUSPICIOUS = {
    b"ptrace": ("medium", "anti-debug / process tracing"),
    b"mprotect": ("high", "changes memory protection (unpacker)"),
    b"/bin/sh": ("high", "shell invocation"),
    b"system": ("high", "executes a command"),
    b"dlopen": ("medium", "dynamic library loading"),
    b"socket": ("medium", "network capability (C2)"),
}

MACRO_TRIGGERS = {
    b"AutoOpen": ("high", "runs automatically when document opens"),
    b"Document_Open": ("high", "runs automatically when document opens"),
    b"Auto_Open": ("high", "runs automatically when document opens"),
    b"Workbook_Open": ("high", "runs automatically when workbook opens"),
    b"Shell": ("high", "VBA Shell() executes a command"),
    b"CreateObject": ("medium", "instantiates COM objects (WScript/ADODB)"),
    b"WScript.Shell": ("high", "spawns shell commands"),
    b"powershell": ("high", "invokes PowerShell"),
    b"GetObject": ("medium", "binds to a running COM object"),
    b"Environ": ("low", "reads environment variables"),
    b"URLDownloadToFile": ("critical", "downloads a payload"),
}

PS_TRIGGERS = {
    b"-enc": ("high", "base64-encoded PowerShell command"),
    b"-EncodedCommand": ("high", "base64-encoded PowerShell command"),
    b"-w hidden": ("high", "hidden window execution"),
    b"-nop": ("medium", "no-profile execution"),
    b"DownloadString": ("high", "in-memory download (fileless)"),
    b"IEX": ("high", "Invoke-Expression (runs downloaded code)"),
    b"FromBase64String": ("medium", "decodes embedded payload"),
    b"bitsadmin": ("high", "LOLBin download"),
    b"certutil": ("high", "LOLBin decode/download"),
    b"rundll32": ("high", "LOLBin proxy execution"),
    b"mshta": ("high", "LOLBin HTA execution"),
}


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"\x4c\x00\x00\x00":
        return "lnk"
    # OLE compound file (legacy .doc/.xls and OneNote .one share a magic
    # family); OneNote files start with a specific GUID header.
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:16] == b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3":
        return "onenote"
    if data[:4] == b"PK\x03\x04":
        return "ooxml"   # zip-based docx/xlsm/pptm
    return "unknown"


# ---------------------------------------------------------------------------
# Generic signal extraction (runs on every format)
# ---------------------------------------------------------------------------

def _scan_strings(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    urls = sorted({m.group(0) for m in URL_RE.finditer(data)})
    for u in urls[:20]:
        findings.append(Finding(
            "network.embedded_url", "medium",
            "embedded URL (possible C2 / download)",
            u.decode("ascii", "ignore")))
    # raw IPv4 literals without an accompanying URL are notable in binaries
    if not urls:
        ips = sorted({m.group(0) for m in IP_RE.finditer(data)})
        good = [ip for ip in ips if not ip.startswith((b"0.", b"255.")) and ip != b"127.0.0.1"]
        for ip in good[:10]:
            findings.append(Finding(
                "network.embedded_ip", "low",
                "hardcoded IPv4 literal", ip.decode("ascii", "ignore")))
    return findings


def _scan_base64_blobs(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    for m in B64_RE.finditer(data):
        blob = m.group(0)
        if len(blob) % 4 != 0 and not blob.endswith(b"="):
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        ent = shannon_entropy(decoded)
        if decoded[:2] == b"MZ":
            findings.append(Finding(
                "encode.embedded_pe_b64", "critical",
                "base64 blob decodes to a PE executable (dropper)",
                f"{len(blob)} chars"))
        elif ent > 6.5 and len(decoded) > 64:
            findings.append(Finding(
                "encode.high_entropy_b64", "medium",
                "large high-entropy base64 blob (packed/encrypted payload)",
                f"{len(blob)} chars, entropy {ent}"))
        if len(findings) >= 5:
            break
    return findings


def _scan_table(data: bytes, table: Dict[bytes, Tuple[str, str]],
                rule_prefix: str, search: bytes = None) -> List[Finding]:
    hay = search if search is not None else data
    low = hay.lower()
    findings: List[Finding] = []
    for needle, (sev, desc) in table.items():
        if needle.lower() in low:
            findings.append(Finding(
                f"{rule_prefix}.{needle.decode('ascii','ignore').strip('-')}",
                sev, desc, needle.decode("ascii", "ignore")))
    return findings


# ---------------------------------------------------------------------------
# Format-specific analyzers
# ---------------------------------------------------------------------------

def _analyze_pe(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    if len(data) < 0x40:
        return findings
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 <= len(data) and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        nsect = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        arch = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
        findings.append(Finding(
            "pe.header", "info", f"valid PE, {arch}, {nsect} sections", arch))
    else:
        findings.append(Finding(
            "pe.truncated", "low", "MZ header but PE signature not found", ""))
    # import-name heuristics (works on raw bytes; no full parse needed)
    findings.extend(_scan_table(data, SUSPICIOUS_IMPORTS, "pe.import"))
    # high-entropy overlay / packing
    if shannon_entropy(data) > 7.2:
        findings.append(Finding(
            "pe.packed", "medium",
            "very high overall entropy (packed/encrypted)",
            f"entropy {shannon_entropy(data)}"))
    return findings


def _analyze_elf(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    if len(data) >= 20:
        bits = "64-bit" if data[4] == 2 else "32-bit"
        endian = "LE" if data[5] == 1 else "BE"
        etype = struct.unpack_from("<H", data, 16)[0]
        kind = {1: "REL", 2: "EXEC", 3: "DYN/PIE", 4: "CORE"}.get(etype, str(etype))
        findings.append(Finding(
            "elf.header", "info", f"ELF {bits} {endian} {kind}", kind))
    findings.extend(_scan_table(data, ELF_SUSPICIOUS, "elf.sym"))
    return findings


def _analyze_lnk(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    findings.append(Finding("lnk.header", "info", "Windows shell link (.lnk)", ""))
    if len(data) >= 24:
        flags = struct.unpack_from("<I", data, 20)[0]
        if flags & 0x00000020:   # HasArguments
            findings.append(Finding(
                "lnk.has_arguments", "medium",
                "shortcut carries command-line arguments", f"flags {flags:#x}"))
    # LNK abuse usually surfaces in the embedded command line strings
    wide = ("\n".join(_wide_strings(data))).encode("ascii", "ignore")
    findings.extend(_scan_table(data, PS_TRIGGERS, "lnk.cmd", search=wide + data.lower()))
    if b"cmd.exe" in data.lower() or b"c\x00m\x00d\x00.\x00e\x00x\x00e" in data:
        findings.append(Finding(
            "lnk.cmd.cmd_exe", "high",
            "shortcut launches cmd.exe (common malspam lure)", "cmd.exe"))
    return findings


def _analyze_macro(data: bytes, fmt: str) -> List[Finding]:
    findings: List[Finding] = []
    label = "OLE compound document" if fmt == "ole" else "OOXML (zip) document"
    findings.append(Finding(f"{fmt}.header", "info", label, ""))
    if fmt == "ooxml" and b"vbaProject.bin" in data:
        findings.append(Finding(
            "macro.vba_present", "medium",
            "document embeds a VBA macro project", "vbaProject.bin"))
    findings.extend(_scan_table(data, MACRO_TRIGGERS, "macro"))
    findings.extend(_scan_table(data, PS_TRIGGERS, "macro.ps"))
    return findings


def _analyze_onenote(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    findings.append(Finding("onenote.header", "info", "OneNote (.one) section", ""))
    # OneNote malspam hides embedded files (PE/JS/HTA/cmd) in the data store.
    if b"MZ" in data and (b"This program cannot be run" in data):
        findings.append(Finding(
            "onenote.embedded_pe", "critical",
            "embedded Windows PE inside OneNote attachment store", "MZ"))
    for ext, sev in ((b".hta", "high"), (b".vbs", "high"), (b".js", "high"),
                     (b".cmd", "high"), (b".bat", "high"), (b".ps1", "high")):
        if ext in data.lower():
            findings.append(Finding(
                f"onenote.attachment{ext.decode()}", sev,
                f"embedded {ext.decode()} attachment (OneNote malspam pattern)",
                ext.decode()))
    findings.extend(_scan_table(data, PS_TRIGGERS, "onenote.ps"))
    return findings


# ---------------------------------------------------------------------------
# Verdict scoring
# ---------------------------------------------------------------------------

def score_verdict(findings: List[Finding]) -> Tuple[int, str]:
    score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    has_crit = any(f.severity == "critical" for f in findings)
    if has_crit or score >= 18:
        verdict = "malicious"
    elif score >= 8:
        verdict = "suspicious"
    elif score >= 3:
        verdict = "low-risk"
    else:
        verdict = "clean"
    return score, verdict


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_bytes(data: bytes, path: str = "<bytes>") -> Report:
    fmt = detect_format(data)
    report = Report(
        path=path,
        size=len(data),
        fmt=fmt,
        sha_hint=_cheap_hash(data),
        entropy=shannon_entropy(data),
    )
    findings: List[Finding] = []
    if fmt == "pe":
        findings += _analyze_pe(data)
    elif fmt == "elf":
        findings += _analyze_elf(data)
    elif fmt == "lnk":
        findings += _analyze_lnk(data)
    elif fmt in ("ole", "ooxml"):
        findings += _analyze_macro(data, fmt)
    elif fmt == "onenote":
        findings += _analyze_onenote(data)
    else:
        findings.append(Finding(
            "format.unknown", "info",
            "unrecognized container; running generic string heuristics", ""))
    # generic passes on every format
    findings += _scan_strings(data)
    findings += _scan_base64_blobs(data)

    # de-dup by (rule, evidence)
    seen = set()
    deduped: List[Finding] = []
    for f in findings:
        key = (f.rule, f.evidence)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    report.findings = deduped
    report.score, report.verdict = score_verdict(deduped)
    return report


def analyze_file(path: str) -> Report:
    with open(path, "rb") as fh:
        data = fh.read()
    return analyze_bytes(data, path=path)

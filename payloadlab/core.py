"""PAYLOADLAB — JSON rule engine."""
from __future__ import annotations
import json, time, re
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "PAYLOADLAB"
TOOL_VERSION = "0.1.0"
RULES = [{'id': 'PL-MACRO-001', 'severity': 'high', 'weight': 2.5, 'title': 'VBA_AUTOEXEC', 'when': {'vba_autoexec': True}, 'remediation': 'Treat as live malware; analyze in isolated VM.'}, {'id': 'PL-SHELL-001', 'severity': 'high', 'weight': 2.5, 'title': 'SHELL_EXEC_CAPABILITY', 'when': {'capa_shell_exec': True}, 'remediation': 'Detonate in sandbox to characterize.'}, {'id': 'PL-PERSIST-001', 'severity': 'critical', 'weight': 3.0, 'title': 'PERSISTENCE_REG', 'when': {'persistence_registry': True}, 'remediation': 'Persistent malware; full host triage required.'}]

def _match(item, rule):
    # rule: {"id","severity","weight","title","when": {field: regex_or_eq}, "remediation"}
    when = rule.get("when", {})
    for k, expected in when.items():
        val = str(item.get(k,""))
        if isinstance(expected, list):
            if val not in expected: return False
        elif isinstance(expected, bool):
            if bool(item.get(k)) != expected: return False
        else:
            if not re.search(expected, val): return False
    return True

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    items: list[dict] = []
    if p.is_file() and p.suffix == ".json":
        data = json.loads(p.read_text())
        items = data if isinstance(data, list) else [data]
    elif p.is_dir():
        for jf in p.rglob("*.json"):
            try:
                data = json.loads(jf.read_text())
                if isinstance(data, list): items.extend(data)
                else: items.append(data)
            except Exception: continue
    result.items_scanned = len(items)
    for item in items:
        for rule in RULES:
            if _match(item, rule):
                result.add(Finding(
                    id=rule["id"], severity=rule["severity"], weight=rule["weight"],
                    title=rule["title"],
                    description=rule.get("title") + ": " + json.dumps({k: item.get(k) for k in list(item)[:3]}),
                    location=str(target),
                    remediation=rule.get("remediation",""), category="malware-triage",
                    metadata=item,
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result

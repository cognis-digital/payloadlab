"""Command-line interface for PAYLOADLAB.

Usage:
    payloadlab scan FILE [FILE ...] [--format {table,json}]
    payloadlab --version
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze_file, Report

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _render_table(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"FILE     : {report.path}")
    lines.append(f"FORMAT   : {report.fmt}")
    lines.append(f"SIZE     : {report.size} bytes")
    lines.append(f"ID       : {report.sha_hint}")
    lines.append(f"ENTROPY  : {report.entropy}")
    lines.append(f"VERDICT  : {report.verdict.upper()} (score {report.score})")
    lines.append("-" * 60)
    if not report.findings:
        lines.append("  (no findings)")
    else:
        ordered = sorted(report.findings,
                         key=lambda f: _SEV_ORDER.get(f.severity, 9))
        for f in ordered:
            tag = f"[{f.severity.upper():>8}]"
            ev = f"  <- {f.evidence}" if f.evidence else ""
            lines.append(f"{tag} {f.rule}: {f.description}{ev}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static malicious payload analyzer (PE/ELF/LNK/macro/OneNote).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="statically analyze one or more files")
    scan.add_argument("files", nargs="+", help="file path(s) to analyze")
    scan.add_argument("--format", choices=("table", "json"), default="table",
                      help="output format (default: table)")
    scan.add_argument("--fail-on", choices=("malicious", "suspicious", "low-risk"),
                      default="malicious",
                      help="minimum verdict that yields a non-zero exit")
    return p


_VERDICT_RANK = {"clean": 0, "low-risk": 1, "suspicious": 2, "malicious": 3}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help(sys.stderr)
        return 2

    reports: List[Report] = []
    had_error = False
    for path in args.files:
        try:
            reports.append(analyze_file(path))
        except (OSError, IOError) as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            had_error = True

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for i, r in enumerate(reports):
            if i:
                print()
            print(_render_table(r))

    if had_error:
        return 3

    threshold = _VERDICT_RANK[args.fail_on]
    if any(_VERDICT_RANK.get(r.verdict, 0) >= threshold for r in reports):
        return 1
    return 0

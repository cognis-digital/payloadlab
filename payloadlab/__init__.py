"""PAYLOADLAB - static malicious payload analyzer.

Detects file format (PE / ELF / LNK / Office macro / OneNote) and extracts
capability signals (suspicious imports, embedded URLs, encoded blobs, command
strings) without executing anything. Inspired by mandiant/capa.

Standard library only. Zero install.
"""
from .core import (
    analyze_bytes,
    analyze_file,
    detect_format,
    score_verdict,
    Finding,
    Report,
)

TOOL_NAME = "payloadlab"
TOOL_VERSION = "1.0.0"

__all__ = [
    "analyze_bytes",
    "analyze_file",
    "detect_format",
    "score_verdict",
    "Finding",
    "Report",
    "TOOL_NAME",
    "TOOL_VERSION",
]

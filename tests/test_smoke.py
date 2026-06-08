"""Smoke + behavior tests for PAYLOADLAB. No network. Standard library only."""
import base64
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from payloadlab import (  # noqa: E402
    analyze_bytes, detect_format, score_verdict, TOOL_NAME, TOOL_VERSION,
)
from payloadlab.cli import main  # noqa: E402
from payloadlab.core import Finding, shannon_entropy  # noqa: E402


def _fake_pe(extra=b"") -> bytes:
    # MZ header + e_lfanew at 0x3C pointing to a PE\0\0 signature.
    buf = bytearray(b"MZ" + b"\x00" * 0x3E)
    pe_off = 0x40
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf += b"PE\x00\x00"
    buf += struct.pack("<H", 0x8664)   # machine x64
    buf += struct.pack("<H", 3)        # 3 sections
    buf += b"\x00" * 16
    return bytes(buf) + extra


class TestFormatDetection(unittest.TestCase):
    def test_pe(self):
        self.assertEqual(detect_format(_fake_pe()), "pe")

    def test_elf(self):
        self.assertEqual(detect_format(b"\x7fELF" + b"\x00" * 30), "elf")

    def test_lnk(self):
        self.assertEqual(detect_format(b"\x4c\x00\x00\x00" + b"\x00" * 30), "lnk")

    def test_onenote(self):
        guid = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
        self.assertEqual(detect_format(guid + b"x"), "onenote")

    def test_unknown(self):
        self.assertEqual(detect_format(b"just text here"), "unknown")


class TestEntropy(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)

    def test_uniform_high(self):
        self.assertGreater(shannon_entropy(bytes(range(256))), 7.9)


class TestPEAnalysis(unittest.TestCase):
    def test_suspicious_imports_flagged(self):
        data = _fake_pe(b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread")
        rep = analyze_bytes(data, "evil.exe")
        self.assertEqual(rep.fmt, "pe")
        rules = {f.rule for f in rep.findings}
        self.assertIn("pe.import.WriteProcessMemory", rules)
        self.assertEqual(rep.verdict, "malicious")

    def test_clean_pe_not_malicious(self):
        rep = analyze_bytes(_fake_pe(), "hello.exe")
        self.assertNotEqual(rep.verdict, "malicious")


class TestEncodedPayloads(unittest.TestCase):
    def test_embedded_pe_b64_is_critical(self):
        pe_blob = base64.b64encode(b"MZ" + b"\x90" * 80)
        rep = analyze_bytes(b"data: " + pe_blob + b" end", "doc.txt")
        rules = {f.rule for f in rep.findings}
        self.assertIn("encode.embedded_pe_b64", rules)
        self.assertEqual(rep.verdict, "malicious")


class TestOneNote(unittest.TestCase):
    def test_demo_sample(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "demos", "01-basic", "sample.one")
        with open(path, "rb") as fh:
            data = fh.read()
        rep = analyze_bytes(data, path)
        self.assertEqual(rep.fmt, "onenote")
        self.assertEqual(rep.verdict, "malicious")
        rules = {f.rule for f in rep.findings}
        self.assertTrue(any(r.startswith("onenote.attachment") for r in rules))
        self.assertTrue(any(r.startswith("network.") for r in rules))


class TestVerdictScoring(unittest.TestCase):
    def test_critical_forces_malicious(self):
        score, verdict = score_verdict([Finding("x", "critical", "d")])
        self.assertEqual(verdict, "malicious")

    def test_clean(self):
        score, verdict = score_verdict([Finding("x", "info", "d")])
        self.assertEqual(verdict, "clean")


class TestCLI(unittest.TestCase):
    def _sample_path(self):
        return os.path.join(os.path.dirname(__file__), "..",
                            "demos", "01-basic", "sample.one")

    def test_json_output_and_exit(self):
        rc = main(["scan", self._sample_path(), "--format", "json"])
        self.assertEqual(rc, 1)   # malicious -> non-zero by default

    def test_table_output(self):
        rc = main(["scan", self._sample_path(), "--format", "table"])
        self.assertEqual(rc, 1)

    def test_missing_file_errors(self):
        rc = main(["scan", "/nonexistent/path/xyz.bin"])
        self.assertEqual(rc, 3)

    def test_no_command_returns_usage_code(self):
        rc = main([])
        self.assertEqual(rc, 2)

    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "payloadlab")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()

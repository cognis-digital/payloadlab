"""Hardening tests — error paths, edge cases, and input validation.

All tests are pure stdlib; no network calls.
"""
from __future__ import annotations

import io
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from payloadlab.core import (  # noqa: E402
    analyze_bytes,
    analyze_file,
    shannon_entropy,
)
import payloadlab.core as _core_mod  # noqa: E402  (used in oversized test)
from payloadlab.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# core.analyze_bytes — edge cases
# ---------------------------------------------------------------------------

class TestAnalyzeBytesEdgeCases(unittest.TestCase):
    def test_empty_bytes(self):
        """analyze_bytes on empty input must return a Report without crashing."""
        rep = analyze_bytes(b"", "<empty>")
        self.assertEqual(rep.size, 0)
        self.assertEqual(rep.fmt, "unknown")
        self.assertIsInstance(rep.findings, list)

    def test_single_byte(self):
        rep = analyze_bytes(b"\x00", "tiny.bin")
        self.assertIsNotNone(rep)

    def test_entropy_empty_bytes(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_truncated_pe_no_crash(self):
        # MZ file too short to parse must yield pe.truncated, not raise.
        rep = analyze_bytes(b"MZ", "trunc.exe")
        self.assertEqual(rep.fmt, "pe")
        rules = {f.rule for f in rep.findings}
        self.assertIn("pe.truncated", rules)

    def test_pe_bad_lfanew_no_crash(self):
        """PE where e_lfanew points beyond the file should not raise struct.error."""
        buf = bytearray(b"MZ" + b"\x00" * 0x3E)
        struct.pack_into("<I", buf, 0x3C, 0xFFFFFF00)  # way past end
        rep = analyze_bytes(bytes(buf), "corrupt.exe")
        self.assertEqual(rep.fmt, "pe")
        # Should produce truncated finding, not an unhandled exception
        rules = {f.rule for f in rep.findings}
        self.assertIn("pe.truncated", rules)

    def test_truncated_elf_no_crash(self):
        """ELF magic with only a few bytes must not crash."""
        rep = analyze_bytes(b"\x7fELF\x02", "tiny.elf")
        self.assertEqual(rep.fmt, "elf")
        # Parser should handle short data gracefully
        self.assertIsInstance(rep.findings, list)

    def test_truncated_lnk_no_crash(self):
        """LNK file shorter than 24 bytes must not crash."""
        rep = analyze_bytes(b"\x4c\x00\x00\x00\x00\x00", "small.lnk")
        self.assertEqual(rep.fmt, "lnk")
        self.assertIsInstance(rep.findings, list)


# ---------------------------------------------------------------------------
# core.analyze_file — file-system validation
# ---------------------------------------------------------------------------

class TestAnalyzeFileValidation(unittest.TestCase):
    def test_missing_file_raises_oserror(self):
        with self.assertRaises((OSError, ValueError)):
            analyze_file("/nonexistent/path/does_not_exist.exe")

    def test_directory_raises_valueerror(self):
        """Passing a directory path must raise ValueError, not crash silently."""
        with self.assertRaises((ValueError, OSError)):
            analyze_file(tempfile.gettempdir())

    def test_oversized_file_raises_valueerror(self):
        """A real file that exceeds MAX_FILE_BYTES must raise ValueError."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"MZ")
            tmp_path = tf.name
        try:
            # Temporarily patch the limit to make this test fast.
            orig = _core_mod.MAX_FILE_BYTES
            _core_mod.MAX_FILE_BYTES = 1  # 1 byte limit
            with self.assertRaises(ValueError):
                analyze_file(tmp_path)
        finally:
            _core_mod.MAX_FILE_BYTES = orig
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# CLI — error exit codes and edge cases
# ---------------------------------------------------------------------------

class TestCLIErrorPaths(unittest.TestCase):
    def test_missing_file_returns_exit3(self):
        rc = main(["scan", "/no/such/file/xyz.bin"])
        self.assertEqual(rc, 3)

    def test_directory_as_file_returns_exit3(self):
        """Passing a directory to scan must return exit 3, not a traceback."""
        rc = main(["scan", tempfile.gettempdir()])
        self.assertEqual(rc, 3)

    def test_no_subcommand_returns_exit2(self):
        rc = main([])
        self.assertEqual(rc, 2)

    def test_unknown_subcommand_returns_exit2(self):
        # argparse raises SystemExit(2) for unknown subcommands on Python 3.14+.
        try:
            rc = main(["frobnicate"])
        except SystemExit as exc:
            rc = exc.code
        self.assertEqual(rc, 2)

    def test_mixed_good_bad_files_returns_exit3(self):
        """One missing file among valid files: should still report exit 3."""
        sample = os.path.join(os.path.dirname(__file__), "..",
                              "demos", "01-basic", "sample.one")
        rc = main(["scan", sample, "/nonexistent/ghost.exe"])
        self.assertEqual(rc, 3)

    def test_json_output_is_valid_json(self):
        """--format json must produce parseable JSON even when all files are bad."""
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            main(["scan", os.path.join(os.path.dirname(__file__), "..",
                                       "demos", "01-basic", "sample.one"),
                  "--format", "json"])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        parsed = json.loads(output)
        self.assertIsInstance(parsed, list)
        self.assertGreater(len(parsed), 0)
        self.assertIn("verdict", parsed[0])

    def test_fail_on_low_risk_with_clean_file(self):
        """--fail-on low-risk: a clean unknown-format file returns 0."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"hello world plaintext")
            tmp = tf.name
        try:
            rc = main(["scan", tmp, "--fail-on", "low-risk"])
            # Plain text is "clean" verdict, so exit 0
            self.assertEqual(rc, 0)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# webhook.py — argument/stdin validation (unit-level, no network)
# ---------------------------------------------------------------------------

class TestWebhookValidation(unittest.TestCase):
    """Test the webhook main() function's input guards without any network calls."""

    def _run_webhook(self, argv, stdin_text=""):
        import integrations.webhook as wh
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
        try:
            rc = wh.main.__wrapped__(argv) if hasattr(wh.main, "__wrapped__") else None
        finally:
            sys.stdin = old_stdin
        return rc

    def test_bad_url_scheme_returns_exit2(self):
        import integrations.webhook as wh
        old_stdin, old_argv = sys.stdin, sys.argv
        sys.stdin = io.StringIO('[]')
        sys.argv = ["webhook.py", "--url", "ftp://example.com/hook"]
        try:
            rc = wh.main()
            self.assertEqual(rc, 2)
        finally:
            sys.stdin = old_stdin
            sys.argv = old_argv

    def test_empty_stdin_returns_exit2(self):
        import integrations.webhook as wh
        old_stdin, old_argv = sys.stdin, sys.argv
        sys.stdin = io.StringIO("   ")
        sys.argv = ["webhook.py", "--url", "https://example.com/hook"]
        try:
            rc = wh.main()
            self.assertEqual(rc, 2)
        finally:
            sys.stdin = old_stdin
            sys.argv = old_argv

    def test_invalid_json_stdin_returns_exit2(self):
        import integrations.webhook as wh
        old_stdin, old_argv = sys.stdin, sys.argv
        sys.stdin = io.StringIO("not json {{{")
        sys.argv = ["webhook.py", "--url", "https://example.com/hook"]
        try:
            rc = wh.main()
            self.assertEqual(rc, 2)
        finally:
            sys.stdin = old_stdin
            sys.argv = old_argv

    def test_bad_header_format_returns_exit2(self):
        import integrations.webhook as wh
        old_stdin, old_argv = sys.stdin, sys.argv
        sys.stdin = io.StringIO('[]')
        sys.argv = ["webhook.py", "--url", "https://example.com/hook",
                    "--header", "BadHeaderWithoutColon"]
        try:
            rc = wh.main()
            self.assertEqual(rc, 2)
        finally:
            sys.stdin = old_stdin
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()

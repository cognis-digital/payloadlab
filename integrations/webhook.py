#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST payloadlab JSON findings to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="destination URL (http/https)")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header in 'Key: Value' form (repeatable)")
    args = ap.parse_args()

    # Validate URL scheme before doing any I/O.
    if not args.url.startswith(("http://", "https://")):
        print(f"error: --url must start with http:// or https://: {args.url!r}",
              file=sys.stderr)
        return 2

    # Validate header format so mistyped headers produce a clear message.
    for h in args.header:
        if ":" not in h:
            print(f"error: --header value must be 'Key: Value', got: {h!r}",
                  file=sys.stderr)
            return 2

    raw = sys.stdin.read()
    if not raw.strip():
        print("error: stdin is empty — nothing to post", file=sys.stderr)
        return 2

    # Validate that stdin is valid JSON before sending.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook HTTP error {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook connection error: {exc.reason}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

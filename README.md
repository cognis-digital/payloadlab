# PAYLOADLAB — Static malicious payload analyzer — PE/ELF/LNK/macro/OneNote

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `red-team`

[![PyPI](https://img.shields.io/pypi/v/cognis-payloadlab.svg)](https://pypi.org/project/cognis-payloadlab/)
[![CI](https://github.com/cognis-digital/payloadlab/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/payloadlab/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Static malicious payload analyzer — PE/ELF/LNK/macro/OneNote.

## Install

```bash
pip install cognis-payloadlab
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
payloadlab --version
payloadlab scan demos/                          # run against bundled demo
payloadlab scan demos/ --format sarif --out r.sarif --fail-on high
payloadlab mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-phishing-doc/` — see [`SCENARIO.md`](demos/01-phishing-doc/SCENARIO.md)
- `demos/02-installer-with-persistence/` — see [`SCENARIO.md`](demos/02-installer-with-persistence/SCENARIO.md)
- `demos/03-onenote-payload/` — see [`SCENARIO.md`](demos/03-onenote-payload/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*

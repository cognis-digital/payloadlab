# Demo 01 - basic OneNote malspam triage

A mailbox SOC analyst receives a `.one` attachment flagged by a user. Detonating
it in a sandbox is slow, so they want a quick static verdict first.

The file `sample.one` in this directory is a **synthetic, inert** OneNote
section crafted to mimic the 2023-era OneNote malspam pattern: a real OneNote
GUID header wrapping an embedded "script" attachment and a PowerShell download
cradle. It contains no executable shellcode and cannot run anything.

## Run it

```
python -m payloadlab scan demos/01-basic/sample.one
python -m payloadlab scan demos/01-basic/sample.one --format json
```

## What you should see

PAYLOADLAB detects the OneNote container by its GUID magic, then surfaces:

- `onenote.attachment.cmd` / `.ps1` - embedded script attachments (the lure)
- `onenote.ps.*` - PowerShell download-cradle indicators (`IEX`, `DownloadString`,
  `certutil`, hidden window)
- `network.embedded_url` - the hardcoded staging URL

The rolled-up **VERDICT** is `MALICIOUS`, and the process exits non-zero, so this
command drops cleanly into a mail-gateway or CI quarantine pipeline:

```
python -m payloadlab scan attachment.one && echo CLEAN || echo BLOCKED
```

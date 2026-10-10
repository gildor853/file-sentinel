# Security policy

## Supported versions

Only the `main` branch and the latest `0.x` version receive security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/gildor853/file-sentinel/security/advisories/new>
(repository **Security** tab → **Report a vulnerability**).

Please include the affected version, a minimal input that reproduces the
problem and its impact. You can expect an acknowledgement within 7 days.
Fixes are released as a patch version and credited in the advisory unless you
prefer otherwise.

## Scope

This is a zero-dependency static file scanner. It never executes, renders or
evaluates the files it inspects. In scope:

- Crashes or uncaught exceptions on crafted inputs (any format the scanner
  accepts)
- Excessive CPU or memory use (zip bombs, entity expansion, deeply nested
  containers, ReDoS) that bypasses the documented limits
- Prototype pollution through hostile property names in parsed structures
- Logic bugs that make a finding's `severity` or `verdict` wrong in a way that
  hides a high/critical rule that did fire

Out of scope (ordinary bugs / product limitations, not vulnerabilities):

- A novel or obfuscated payload that the heuristic rules do not recognise —
  this is a static heuristic scanner, not an antivirus
- False positives on unusual but legitimate files
- Formats that are only identified and not unpacked (7z, RAR, …), as documented

## Disclaimer

This project is provided as is, without warranty. See [DISCLAIMER.md](./DISCLAIMER.md)
for the full disclaimer and limitation of liability.

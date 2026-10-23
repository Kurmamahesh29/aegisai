# Security policy

AegisAI is a security tool, so we treat vulnerabilities in AegisAI itself as high priority.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

1. Use GitHub's private vulnerability reporting on the repository ("Security" tab, "Report a
   vulnerability"), if enabled, or email the maintainers at the address listed in the
   repository profile.
2. Include a description, reproduction steps, affected versions and any proof-of-concept.
3. You will receive an acknowledgement within 5 business days and a remediation plan or
   decision within 30 days.

We ask that you give us a reasonable time to fix the issue before public disclosure and that
you do not access or modify data that is not yours while researching.

## What counts as a vulnerability in AegisAI

- Scanner code execution or file writes triggered by scanned content (the scanner must be
  read-only and must never execute scanned code).
- Path traversal or symlink escapes from the selected project root.
- Secret values leaking unredacted into reports, logs, telemetry or exceptions.
- Shell injection through integration arguments or configured executable paths.
- Any behaviour that makes a scan look clean when it failed or was incomplete.

False negatives in a detection rule (a missed vulnerability in scanned code) are important but
are tracked as regular issues unless they are caused by a bypass of a security property above.

## Dependencies

Runtime dependencies are pinned to compatible ranges and checked with OSV-Scanner in CI
(`.github/workflows/security.yml`). Dependabot opens update pull requests weekly.

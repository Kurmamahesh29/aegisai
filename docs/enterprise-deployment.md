# Enterprise deployment

AegisAI 0.1.0 is a local, stateless CLI. This guide covers rolling it out across many
repositories and developers; the centralized service/dashboard is on the roadmap, not shipped.

## Distribution

- **Python package**: build with `python -m build` in `packages/scanner` and publish the wheel
  to your internal index (Artifactory, Nexus, Azure Artifacts). Pin `aegisai==0.1.0` in CI.
- **External scanners**: mirror the Gitleaks and OSV-Scanner release binaries internally and
  point `integrations.<name>.executable` at the installed absolute path, or install them into a
  base CI image. `aegisai doctor` verifies availability.
- **VS Code extension**: distribute the VSIX through your internal extension gallery or
  `code --install-extension`. Set `aegisai.executablePath` through a machine or workspace
  settings policy so every developer uses the sanctioned binary.

## Organisation-wide policy

- Ship a baseline `.aegisai.yaml` through a repository template. Key settings:
  `ci.fail_on`, `ci.strict_integrations: true`, `integrations.osv_scanner.enabled` (consider
  disabling in air-gapped networks), and an initial `rules.overrides` block for severity
  adjustments agreed with the security team.
- Require a `reason` (already mandatory) and an `expires` date on suppressions; review
  `.aegisai.yaml` and inline `# aegisai: ignore` changes in code review (CODEOWNERS).
- Use the reusable workflow with `upload-sarif: true` so findings aggregate in GitHub code
  scanning with the rule id, severity and fingerprint preserved.
- Use baselines to adopt AegisAI on existing codebases without blocking teams on day one; plan
  burn-down of `existing` findings.

## Air-gapped environments

- `--no-integrations` or disable `osv_scanner` to avoid any network activity.
- Semgrep accepts only local rule files; vendor `rules/semgrep/*.yaml` into the repository.
- No telemetry exists, so nothing needs to be blocked.

## Hardening the scan environment

- Run scans with a least-privilege user; AegisAI never needs write access to the repository.
- Set `scan.max_file_size_kb`, `scan.max_files` and `scan.timeout_seconds` for very large
  monorepos; scans that hit limits report `incomplete` (exit 3) instead of pretending to be
  complete.
- Treat JSON/SARIF reports as sensitive artifacts (they contain file paths and snippets).

## Compliance mapping

Each rule carries CWE identifiers and, where applicable, references to the OWASP Top 10 for
LLM Applications (2025) and the OWASP Top 10 (2021). These are *references*, not a compliance
attestation: AegisAI detects specific patterns and does not certify coverage of any standard.

## Upgrades

Rule versions are embedded in findings (`rule_version`). When a rule's detection logic changes
its version is bumped and the change is listed in `CHANGELOG.md`; fingerprints are designed to
stay stable so baselines survive upgrades unless evidence text changes.

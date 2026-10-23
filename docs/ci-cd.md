# CI/CD integration

## Exit-code contract

| Code | Meaning | CI interpretation |
|------|---------|-------------------|
| 0 | no active finding at/above `fail_on` | pass |
| 1 | findings at/above `fail_on` | **vulnerability** - fix or suppress with a reason |
| 2 | scan failed (arguments, configuration, unreadable root, internal error) | **infrastructure** - fix the pipeline |
| 3 | scan incomplete (timeout, limits, required scanner unavailable) | **infrastructure** - install the scanner or raise limits |
| 130 | cancelled | n/a |

When `--baseline` is used, only findings with `status: new` count towards `fail_on`.

## GitHub Actions (reusable workflow)

```yaml
# .github/workflows/aegisai.yml in your repository
name: aegisai
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    uses: Kurmamahesh29/aegisai/.github/workflows/aegisai-scan.yml@v0.1.0
    with:
      profile: all
      fail-on: high
      strict: true            # missing scanners fail the job with exit 3
      upload-sarif: true      # publish to the Security tab
    permissions:
      contents: read
      security-events: write  # only needed for upload-sarif
```

What it does: checks out the code, sets up Python, installs AegisAI (PyPI or the repository
checkout), installs Gitleaks and OSV-Scanner from pinned release versions, runs `aegisai doctor`,
scans with terminal + JSON + SARIF output, uploads the reports as a workflow artifact
(`aegisai-reports`), writes a step summary that says whether a failure was a vulnerability or a
scanner problem, and optionally uploads SARIF with `github/codeql-action/upload-sarif`.

Inputs: `path`, `profile`, `fail-on`, `aegisai-version`, `install-gitleaks`,
`install-osv-scanner`, `strict`, `upload-sarif`, `baseline`, `python-version`.

Permissions: ordinary scanning needs only `contents: read`. `security-events: write` is
required solely for SARIF upload. The workflow pins third-party actions to commit SHAs.

### Inline job (without the reusable workflow)

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install aegisai
- run: |
    aegisai scan . --profile all --fail-on high --strict --no-progress \
      --format json --output reports/aegisai.json \
      --format sarif --output reports/aegisai.sarif
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: aegisai-reports, path: reports/ }
```

## Other CI systems

Any runner that can execute Python works the same way: install, run `aegisai scan` with
`--format sarif/json --output`, archive the reports, and branch on the exit code. Use
`--quiet` for compact logs and `--no-color`. For GitLab, map SARIF to the SAST report format
with a converter or archive the JSON report as an artifact.

## Baselines in CI

```bash
aegisai baseline create . --output aegis-baseline.json    # commit this file
aegisai scan . --baseline aegis-baseline.json --fail-on high
```

Regenerate the baseline deliberately (reviewed PR) rather than on every run; a baseline can
never hide scan failures or missing scanners.

## Pre-commit

`.pre-commit-config.yaml` in this repository runs Ruff and a quick `aegisai scan --profile code
--no-integrations` on staged file types. Adapt the `files:` pattern and profile to your needs.

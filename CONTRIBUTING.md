# Contributing to AegisAI

Thank you for helping make AI applications safer. This guide covers setup, quality gates and
how to add a rule. See `docs/adding-rules.md` for the detailed rule-authoring walkthrough.

## Development setup

Prerequisites: Python 3.12+, Node.js 20+ (extension only), Git.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   POSIX: source .venv/bin/activate
pip install -e "packages/scanner[dev]"
pre-commit install          # optional but recommended
```

Verify everything works:

```bash
make test        # or: cd packages/scanner && python -m pytest -q
make lint        # ruff check + format check
make typecheck   # mypy --strict
aegisai scan examples --no-integrations
```

On Windows without GNU make, run the commands shown in the Makefile targets directly.

## Quality gates (enforced in CI)

- `ruff check` and `ruff format --check` must pass.
- `mypy` in strict mode must pass for `src/aegisai`.
- All tests must pass on Linux, macOS and Windows.
- Every rule needs positive and negative tests.
- Every fixed false positive needs a regression test under `tests/regression/`.
- No secrets, no network calls in tests, no execution of fixture code.

## Pull requests

1. Open an issue first for new rules or behaviour changes so the scope can be agreed.
2. Keep PRs focused; one rule or one fix per PR.
3. Update `CHANGELOG.md` under "Unreleased".
4. Regenerate `docs/supported-rules.md` and `docs/schema/` with `make rules-doc` when rule
   metadata or models change.
5. Describe how you tested the change and any known limitations.

## Adding a rule (short version)

1. Create a module under `packages/scanner/src/aegisai/rules/<pack>/`.
2. Subclass `aegisai.engine.registry.Rule`, fill in `RuleMetadata` completely (id, version,
   description, severity, confidence behaviour, impact, remediation, references, CWE).
3. Implement `check(ctx)` using `ctx.dataflow`, `ctx.python_module` or `ctx.structured`.
4. Register the rule in `aegisai/rules/__init__.py`.
5. Add tests in `tests/unit/rules/` with at least one positive and one negative case.
6. Add the rule to the relevant example application if it demonstrates a realistic pattern.

Rule ids are `<PACK><NNN>`; never reuse an id. Bump `version` when detection logic changes.

## Reporting bugs and false positives

Open an issue with a minimal code sample that reproduces the finding, the rule id, and the
AegisAI version (`aegisai version`). Do not include real secrets in issues.

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0.

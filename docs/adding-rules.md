# Adding a rule

This walkthrough adds a hypothetical rule `LLM005` that flags model output written to a file
path. Every built-in rule follows the same pattern.

## 1. Pick the pack and id

Packs: `code`, `secrets`, `dependencies`, `llm`, `agents`, `rag`, `mcp`. Ids are
`<PACK-PREFIX><NNN>` (`SEC`, `CFG`, `DEP`, `SMG`, `LLM`, `AGT`, `RAG`, `MCP`) and are never
reused. Check `docs/supported-rules.md` for the next free number.

## 2. Write the rule

`packages/scanner/src/aegisai/rules/llm/output_to_file.py`:

```python
from aegisai.analyzers.dataflow import SinkKind, SourceKind
from aegisai.engine.registry import FileContext, Rule
from aegisai.models.finding import Category, Confidence, Finding, Severity
from aegisai.models.rule import ArtifactType, RuleMetadata, RulePack
from aegisai.rules.common import adjusted_confidence, finding_from_flow, has_strong_guard


class LLMOutputToFileRule(Rule):
    metadata = RuleMetadata(
        rule_id="LLM005",
        name="LLM output used as a file path",
        version="1.0.0",
        description="Model output is used as a filesystem path without a recognised validation step.",
        category=Category.LLM,
        pack=RulePack.LLM,
        default_severity=Severity.HIGH,
        default_confidence=Confidence.HIGH,
        confidence_behavior="High for a direct path; medium when a validation-looking check references the value.",
        artifact_types=[ArtifactType.PYTHON],
        impact="Path traversal driven by prompt injection.",
        remediation="Map model output to an allow-listed identifier and resolve paths inside a fixed root.",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
        cwe_ids=["CWE-22"],
    )

    def check(self, ctx: FileContext) -> list[Finding]:
        dataflow = ctx.dataflow
        if dataflow is None:          # not Python or failed to parse
            return []
        findings = []
        for flow in dataflow.flows_matching({SourceKind.LLM_OUTPUT}, {SinkKind.FILE_PATH}):
            if has_strong_guard(flow):   # allow-list membership / equality on the value
                continue
            confidence, review = adjusted_confidence(flow, Confidence.HIGH)
            findings.append(finding_from_flow(ctx, self, flow, severity=Severity.HIGH, confidence=confidence, review_required=review))
        return findings
```

Guidelines:

- Fill every metadata field honestly. Mark the rule `heuristic=True` when findings cannot be
  confirmed statically; such findings should set `review_required=True`.
- Only cite CWE/OWASP identifiers you have verified against the catalogues.
- Use `ctx.new_finding(...)` for non-dataflow rules; it validates, redacts and fingerprints.
- Rules must not read files outside `ctx`, execute code, or make network calls.
- Prefer precise evidence: source, path, sink and guards (see `rules/common.py`).

For structured config rules use `ctx.structured` and `analyzers.configuration.locate_path`
to anchor findings to real lines. For regex/text rules iterate `ctx.lines`.

## 3. Register it

Add the class to `rules/llm/__init__.py` and to the list in `rules/__init__.py`. If the rule
overlaps a more generic rule at the same line, add it to `RULE_PRECEDENCE`.

## 4. Test it

`packages/scanner/tests/unit/rules/test_llm_rules.py`:

```python
def test_llm005_positive(project):
    code = '''
        from openai import OpenAI
        client = OpenAI()
        def go(q):
            name = client.responses.create(model="m", input=q).output_text
            open(name).read()
    '''
    found = findings_for(scan_code(project, code, profiles=[Profile.LLM]), "LLM005")
    assert len(found) == 1 and found[0].location.start_line == 5

def test_llm005_negative(project):
    code = '''
        from openai import OpenAI
        client = OpenAI()
        FILES = {"a": "/data/a.txt"}
        def go(q):
            key = client.responses.create(model="m", input=q).output_text
            open(FILES[key]).read()
    '''
    assert "LLM005" not in rule_ids(scan_code(project, code, profiles=[Profile.LLM]))
```

Add a realistic instance to an example application if it demonstrates a common pattern, and
list the rule in that example's README table so `scripts/measure_detection.py` checks it.

## 5. Document it

```bash
python scripts/generate_rule_docs.py      # regenerates docs/supported-rules.md
```

Add a CHANGELOG entry. Bump the rule's `version` whenever detection logic changes later.

## Extending the analyzer

New sources/sinks live in `analyzers/dataflow.py` tables (`_SHELL_NAMES`, `RETRIEVAL_TAILS`,
`USER_INPUT_ATTRS`, ...). Add unit tests in `tests/unit/test_dataflow.py` for each new entry
and re-run `scripts/measure_detection.py` to confirm no regressions on the corpus.

# Manifest Authoring Guide

How to write, test, and contribute a Kyvvu manifest.

## YAML structure

Every manifest must have:

```yaml
# SPDX-License-Identifier: Apache-2.0
name: "Human-readable manifest name"
description: |
  What this manifest enforces, which regulation it covers, and
  any deployment notes.
version: "1.0.0"

policies:
  - name: "Policy name"
    description: |
      What the policy does and why. Cite specific regulation articles.
    rule_type: <rule_name>
    params:
      <param_key>: <param_value>
    severity: <low|medium|high|critical>
    enforcement_point: <agent_registration|step_execution>
```

Optional per-policy fields: `risk_classification` (scopes the policy to a specific risk tier).

## Finding available rules

The engine has 26 registered rules. To list them:

```python
from kyvvu_engine import PolicyRule

rules = PolicyRule.get_all_rules()
for name, meta in sorted(rules.items()):
    print(f"{name}: enforcement_points={meta['enforcement_points']}")
    for k, v in meta["params_schema"].items():
        print(f"  {k}: type={v['type']}, required={v.get('required', False)}")
```

## Checking params

Every `params` block must match the rule's `params_schema`. Required params must be present; unknown keys are rejected by the test suite.

Regexes in `field_matches_regex.pattern` use RE2 syntax. Lookaround and backreferences are rejected when the policy loads. Use `not` around a positive `field_matches_regex` condition to invert a match.

```python
rules = PolicyRule.get_all_rules()
print(rules["step_requires_gate"]["params_schema"])
```

## Enforcement points

| Enforcement point | When evaluated | Data available |
|-------------------|---------------|----------------|
| `agent_registration` | When an agent registers or updates | Agent profile fields: `name`, `purpose`, `risk_classification`, `owner_id`, `maintainer_id`, `declared_tools` |
| `step_execution` | Before every agent action at runtime | Current step (`kind`, `verb`, `step_name`, `properties`, `input`) plus full task history |

Any param named `field`, including `trigger_condition.field`, is a full path from the enforcement view. For step rules use `kind`, `verb`, `step_name`, `input.<path>`, or `properties.<path>`; for registration rules use an agent profile attribute such as `purpose` or `metadata.team`. Params beginning with `property_` stay relative to step properties, so `property_path: usage.total_tokens` has no `properties.` prefix.

## Severity levels

Severity determines the enforcement action when a policy is violated:

| Severity | Action | Use when |
|----------|--------|----------|
| `critical` | **block** — the step is prevented | Safety-critical violations that must stop execution |
| `high` | **warn** — violation logged, step proceeds | Important violations that should be addressed |
| `medium` | **warn** — violation logged, step proceeds | Notable but non-urgent issues |
| `low` | **warn** — violation logged, step proceeds | Best-practice recommendations |

Only `critical` severity produces a `block` action. All other severities produce `warn`.

## Common patterns

### Gate-before-action

Require a completed `step.gate` with `properties.kind: human` and
`output.decision: pass` before certain action kinds:

```yaml
rule_type: step_requires_gate
params:
  target_kinds: ["step.resource"]
  target_verb: DELETE
  gate_kind: human
```

### Taint tracking

Permanently block target steps after a taint step appears in history:

```yaml
rule_type: tainted_path_block
params:
  taint_kind: step.resource
  taint_verb: GET
  taint_property_filter:
    data.classification: pii
  target_kinds: ["step.message"]
  target_verb: POST
```

The taint is permanent within a task — no gate can clear it.

### Compound rules

Combine multiple conditions with `all_of`, `any_of`, and `not`:

```yaml
rule_type: not
params:
  condition:
    rule_type: all_of
    params:
      conditions:
        - rule_type: current_is
          params:
            kind: step.exec
        - rule_type: history_contains
          params:
            kind: step.resource
            count_attempts: true
            verb: GET
            property_filter:
              target.trust: external
```

### Tool allowlisting

Fail-closed enforcement — agents without a declared allowlist are blocked:

```yaml
rule_type: step_name_in_allowlist
params:
  agent_field: declared_tools
  target_kinds: ["step.resource", "step.exec"]
```

## Testing workflow

1. Write your manifest YAML in the appropriate subdirectory.
2. Add agent trace tests in `tests/agents/` — at least one compliant (allow) and
   one violating (deny) trace per policy. Build the trace with `engine.record(...)`
   for prior steps and `engine.evaluate(...)` for the intended step, then assert on
   `result.action` and the per-policy `result.policies[*].rule_type`. This match /
   no-match fixture style is the shared convention for behavioral coverage.
3. Run validation:

```bash
pip install -r requirements-dev.txt
yamllint manifests/
pytest tests/ -v
ruff check tests/
```

4. Open a pull request and complete the checklist.

## Risk classification values

Use lowercase values: `high`, `limited`, `minimal`. The engine performs exact string matching — uppercase values will not match.

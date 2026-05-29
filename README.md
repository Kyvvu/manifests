# Kyvvu Manifests

A manifest is a YAML bundle of compliance policies that governs how AI agents behave at runtime. Bind a manifest to an agent via the Kyvvu CLI or dashboard to enforce it.

## Manifests

| Manifest | Directory | Scope | Basis |
|----------|-----------|-------|-------|
| `eu-ai-act-minimal` | `compliance/` | Registration + Step | EU AI Act Art. 6, 13, 50 |
| `eu-ai-act-high-risk` | `compliance/` | Registration + Step | EU AI Act Art. 6-15 |
| `gdpr-data-subject-rights` | `compliance/` | Registration + Step | GDPR Art. 5, 13, 17, 22 |
| `healthcare-nen7510-hipaa` | `compliance/` | Registration + Step | NEN 7510, HIPAA |
| `financial-services-dora-mifid` | `compliance/` | Registration + Step | DORA, MiFID II |
| `owasp-agentic-default` | `security/` | Registration + Step | OWASP Agentic Top 10 (2026) |
| `data-exfiltration-guard` | `security/` | Step | Data loss prevention |
| `internal-ai-starter` | `operational/` | Registration + Step | General responsible AI |
| `demo` | `operational/` | Registration + Step | Getting started |

## Quickstart

```bash
pip install kyvvu-engine pyyaml

# Run the exfiltration guard demo (no API key needed)
cd examples
python exfiltration_demo.py
```

To assign a manifest to a live agent, use the Kyvvu dashboard or API:

1. Connect a manifest repository under **Settings > Repos**.
2. Navigate to **Agents > Manifests** and assign a manifest file to the agent.
3. The engine evaluates every agent step against the manifest's policies.

## Manifest anatomy

Every manifest is a YAML file with this structure:

```yaml
# SPDX-License-Identifier: Apache-2.0
name: "My Manifest"
description: |
  What this manifest enforces and why.
version: "1.0.0"

policies:
  # Registration-time check
  - name: "Agent must have a purpose"
    description: |
      EU AI Act Article 13 requires documentation of AI system purpose.
    rule_type: field_not_empty
    params:
      field: purpose
    severity: high
    scope: agent_registration

  # Runtime step check
  - name: "DELETE requires human approval"
    description: |
      Destructive operations must be preceded by a human approval gate.
    rule_type: step_requires_gate
    params:
      target_step_types: ["step.resource"]
      target_verb: DELETE
      gate_check_type: human_approval
    severity: critical
    scope: step_execution
```

**Scopes**: `agent_registration` policies evaluate when an agent registers. `step_execution` policies evaluate before every agent action at runtime.

**Severity levels**: `critical` triggers a **block** (the action is prevented). `high`, `medium`, and `low` trigger a **warn** (the violation is logged but the action proceeds).

## Path-dependent enforcement

Most agent governance tools evaluate each API call in isolation. Kyvvu policies are functions of the full execution history — a step that was safe in one context becomes a violation after a sensitive read, a tainted credential access, or a missing approval gate.

**Example**: the `data-exfiltration-guard` manifest uses `tainted_path_block` to permanently block outbound messages after a sensitive data read. The same `step.message POST` is allowed in a clean task but blocked once PII-classified data enters the task history. See [`examples/exfiltration_demo.py`](examples/exfiltration_demo.py) for a runnable demonstration.

Path-dependent rules available in the engine:

| Rule | What it does |
|------|-------------|
| `tainted_path_block` | Permanently blocks target steps after a taint step appears in history |
| `step_requires_gate` | Requires a gate step (with optional check_type) anywhere in history |
| `step_preceded_by_without_intervening` | Requires a predecessor with no forbidden step types between |
| `step_requires_dedicated_predecessor` | Each target consumes its own predecessor (one gate, one action) |
| `history_contains` | Checks whether a specific step type exists in history |
| `sequence_forbidden` | Blocks a forbidden ordered sequence of step types |
| `usage_budget` | Tracks cumulative property values across the task |
| `execution_max_steps` | Caps the count of a step type within a task |
| `max_consecutive_same_type` | Limits consecutive occurrences of a step type |

## Authoring and contributing

See [docs/authoring-guide.md](docs/authoring-guide.md) for how to write a manifest and [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow.

## License

Manifests are licensed under Apache 2.0 — see [LICENSE](LICENSE). The Kyvvu engine that evaluates them is licensed under BSL 1.1.

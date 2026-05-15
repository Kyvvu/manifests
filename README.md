# Kyvvu Manifests

Compliance policy manifests for the [Kyvvu](https://kyvvu.com) AI governance platform.

## What are manifests?

Manifests are YAML files containing compliance policies that can be assigned to AI agents via the Kyvvu platform. Each manifest defines a set of rules — evaluated at agent registration and at runtime before each step executes.

## Available manifests

| Manifest | Policies | Description |
|----------|----------|-------------|
| `owasp_agentic_default.yaml` | 8 | OWASP Top 10 for Agentic Applications (2026) — baseline security for any agent |
| `ai_act_comprehensive.yaml` | 21 | EU AI Act full coverage (Articles 6-95) — for high-risk deployments |
| `ai_act_practical.yaml` | 11 | EU AI Act practical subset — focused on HIGH risk obligations |
| `eu_ai_act_basic.yaml` | 6 | EU AI Act minimum — Article 13 transparency requirements |
| `data_minimization.yaml` | 4 | GDPR data minimization best practices |
| `kyvvu_demo.yaml` | 2 | Getting started — minimal manifest for onboarding |

## Usage

### Dashboard

1. Go to **Manifests** in the Kyvvu dashboard
2. Connect this repository (paste the URL + a GitHub token with read access)
3. Browse manifests, preview policies, assign to agents

### CLI

```bash
kyvvu list-manifests
kyvvu assign-manifest --agent-id <id> --repo-id <id> --manifest owasp_agentic_default.yaml
```

### Manifest structure

```yaml
name: "Manifest Name"
description: |
  What this manifest covers and why.
version: "1.0"

policies:
  - name: "Policy name"
    description: "What this policy enforces"
    rule_type: field_not_empty       # rule from kyvvu-engine
    params:
      field: purpose
    severity: high                   # low | medium | high | critical
    scope: agent_registration        # agent_registration | step_execution
    risk_classification: high        # optional: minimal | limited | high
```

## Writing custom manifests

Fork this repo and add your own YAML files. The Kyvvu platform validates manifests on import — invalid files are flagged with clear error messages.

Available rule types are documented at [docs.kyvvu.com](https://docs.kyvvu.com) and can be listed via the API: `GET /api/v1/policies/rules`.

## License

Copyright 2026 Kyvvu B.V. All rights reserved.

These manifests are provided for use with the Kyvvu platform. Redistribution or use outside the Kyvvu platform requires written permission.

## Contact

- Platform: [platform.kyvvu.com](https://platform.kyvvu.com)
- Documentation: [docs.kyvvu.com](https://docs.kyvvu.com)
- Email: hello@kyvvu.com
- Website: [kyvvu.com](https://kyvvu.com)

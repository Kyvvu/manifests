# Contributing to Kyvvu Manifests

Thank you for your interest in contributing to the Kyvvu manifest library!

## Proposing a new manifest

1. Open an issue using the **New Manifest Proposal** template.
2. Describe the regulatory basis, target risk classifications, and draft policies.
3. A maintainer will review and provide feedback before implementation begins.

## Manifest authoring workflow

1. Fork the repository and create a feature branch.
2. Write your manifest YAML in the appropriate subdirectory (`manifests/compliance/`,
   `manifests/security/`, or `manifests/operational/`).
3. Ensure every `rule_type` exists in `kyvvu-engine` and every `params` block
   matches the rule's `params_schema`.
4. Add an SPDX header as the first line: `# SPDX-License-Identifier: Apache-2.0`
5. Add tests for your manifest in `tests/agents/` — at least one compliant trace
   and one violating trace.
6. Run validation locally:
   ```bash
   pip install -r requirements-dev.txt
   yamllint manifests/
   pytest tests/ -v
   ```
7. Open a pull request and complete the PR checklist.

For detailed guidance, see [docs/authoring-guide.md](docs/authoring-guide.md)
(coming in Phase 2).

## Contributor License Agreement

By submitting a pull request, you agree to the [Contributor License Agreement](CLA.md).

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Please report unacceptable behaviour to maintainers@kyvvu.com.

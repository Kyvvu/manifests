"""Structural validation tests for all manifest YAML files.

Every manifest in the library is automatically tested via the parametrized
``manifest_path`` / ``manifest_data`` fixtures defined in ``conftest.py``.

Tests cover:
1. YAML parsing
2. Required top-level fields (name, policies, version)
3. Policy structure (name, rule_type, severity, enforcement_point)
4. Severity and enforcement_point enum values
5. Rule existence in kyvvu-engine registry
6. Rule enforcement_point compatibility
7. Params schema validation (required keys present, no unknown keys)
8. Recursive validation for compound rules (not, all_of, any_of)
9. SPDX license header
"""

from __future__ import annotations

from typing import Any

from kyvvu_engine.rules import PolicyRule

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_ENFORCEMENT_POINTS = {"agent_registration", "step_execution"}

# Compound rule types whose params contain nested rule references.
_SINGLE_CHILD_RULES = {"not"}  # params.condition
_MULTI_CHILD_RULES = {"all_of", "any_of"}  # params.conditions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_rule_types(policy: dict[str, Any]) -> list[tuple[str, str]]:
    """Recursively collect ``(rule_type, enforcement_point)`` from a policy
    and its children.

    Compound rules (``not``, ``all_of``, ``any_of``) embed nested rule
    references inside their ``params``.  This function walks the tree and
    returns every ``rule_type`` encountered together with the owning
    policy's enforcement point so that enforcement-point compatibility
    checks can be applied.

    Returns:
        List of ``(rule_type, enforcement_point)`` tuples.
    """
    results: list[tuple[str, str]] = []
    _walk(policy, policy.get("enforcement_point", "step_execution"), results)
    return results


def _walk(
    node: dict[str, Any],
    enforcement_point: str,
    acc: list[tuple[str, str]],
) -> None:
    """Depth-first walk of a policy / sub-condition node."""
    rt = node.get("rule_type", "")
    if rt:
        acc.append((rt, enforcement_point))

    params = node.get("params", {})

    # Single-child compound rules: not → params.condition
    if rt in _SINGLE_CHILD_RULES and "condition" in params:
        _walk(params["condition"], enforcement_point, acc)

    # Multi-child compound rules: all_of / any_of → params.conditions
    if rt in _MULTI_CHILD_RULES and "conditions" in params:
        for child in params["conditions"]:
            _walk(child, enforcement_point, acc)


def _collect_leaf_params(policy: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Recursively collect ``(rule_type, params)`` for leaf (non-compound) rules."""
    results: list[tuple[str, dict[str, Any]]] = []
    _walk_params(policy, results)
    return results


def _walk_params(
    node: dict[str, Any],
    acc: list[tuple[str, dict[str, Any]]],
) -> None:
    """Depth-first walk collecting params for leaf rules only."""
    rt = node.get("rule_type", "")
    params = node.get("params", {})

    if rt in _SINGLE_CHILD_RULES:
        if "condition" in params:
            _walk_params(params["condition"], acc)
    elif rt in _MULTI_CHILD_RULES:
        if "conditions" in params:
            for child in params["conditions"]:
                _walk_params(child, acc)
    elif rt:
        # Leaf rule — strip internal keys before validation.
        clean = {k: v for k, v in params.items() if not k.startswith("_")}
        acc.append((rt, clean))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestYamlParsing:
    """Every manifest file must parse as valid YAML."""

    def test_parses_without_error(self, manifest_data: dict[str, Any]) -> None:
        assert manifest_data is not None


class TestRequiredFields:
    """Every manifest must have name, version, and a non-empty policies list."""

    def test_has_name(self, manifest_data: dict[str, Any]) -> None:
        assert "name" in manifest_data, "Manifest must have a 'name' field"
        assert isinstance(manifest_data["name"], str)
        assert len(manifest_data["name"]) > 0

    def test_has_version(self, manifest_data: dict[str, Any]) -> None:
        assert "version" in manifest_data, "Manifest must have a 'version' field"
        assert isinstance(manifest_data["version"], str)

    def test_has_policies(self, manifest_data: dict[str, Any]) -> None:
        assert "policies" in manifest_data, "Manifest must have a 'policies' field"
        assert isinstance(manifest_data["policies"], list)
        assert len(manifest_data["policies"]) > 0, "Policies list must not be empty"


class TestPolicyStructure:
    """Every policy must have the required structural fields."""

    def test_policy_has_required_fields(self, manifest_data: dict[str, Any]) -> None:
        required = {"name", "rule_type", "severity", "enforcement_point"}
        for i, policy in enumerate(manifest_data["policies"]):
            missing = required - set(policy.keys())
            assert not missing, (
                f"Policy #{i} ({policy.get('name', '<unnamed>')}) "
                f"is missing required fields: {missing}"
            )


class TestSeverityValues:
    """Policy severity must be one of low, medium, high, critical."""

    def test_valid_severity(self, manifest_data: dict[str, Any]) -> None:
        for policy in manifest_data["policies"]:
            assert policy["severity"] in VALID_SEVERITIES, (
                f"Policy '{policy['name']}' has invalid severity: "
                f"{policy['severity']!r}. Must be one of {VALID_SEVERITIES}"
            )


class TestEnforcementPointValues:
    """Policy enforcement_point must be agent_registration or step_execution."""

    def test_valid_enforcement_point(self, manifest_data: dict[str, Any]) -> None:
        for policy in manifest_data["policies"]:
            assert policy["enforcement_point"] in VALID_ENFORCEMENT_POINTS, (
                f"Policy '{policy['name']}' has invalid enforcement_point: "
                f"{policy['enforcement_point']!r}. Must be one of "
                f"{VALID_ENFORCEMENT_POINTS}"
            )


class TestRuleExistence:
    """Every rule_type (including nested compound children) must exist in the engine."""

    def test_all_rule_types_exist(self, manifest_data: dict[str, Any]) -> None:
        all_rules = PolicyRule.get_all_rules()
        for policy in manifest_data["policies"]:
            for rule_type, _ep in _collect_rule_types(policy):
                assert rule_type in all_rules, (
                    f"Policy '{policy['name']}' references unknown rule_type: "
                    f"{rule_type!r}. Available: {sorted(all_rules.keys())}"
                )


class TestRuleEnforcementPointMatch:
    """Each policy's enforcement_point must be in the rule's supported list.

    ``enforcement_points`` here is the kyvvu-engine rule-registry metadata
    key, renamed alongside the platform rename.
    """

    def test_enforcement_point_in_supported_list(
        self, manifest_data: dict[str, Any]
    ) -> None:
        all_rules = PolicyRule.get_all_rules()
        for policy in manifest_data["policies"]:
            for rule_type, enforcement_point in _collect_rule_types(policy):
                if rule_type not in all_rules:
                    continue  # Already caught by TestRuleExistence
                supported = all_rules[rule_type].get("enforcement_points", [])
                assert enforcement_point in supported, (
                    f"Policy '{policy['name']}' uses rule_type={rule_type!r} "
                    f"with enforcement_point={enforcement_point!r}, but rule "
                    f"only supports: {supported}"
                )


class TestParamsValidation:
    """Params must match the rule's params_schema: required keys present, no unknown keys."""

    def test_params_schema_compliance(self, manifest_data: dict[str, Any]) -> None:
        all_rules = PolicyRule.get_all_rules()
        for policy in manifest_data["policies"]:
            for rule_type, params in _collect_leaf_params(policy):
                if rule_type not in all_rules:
                    continue  # Already caught by TestRuleExistence

                schema = all_rules[rule_type].get("params_schema", {})
                required_keys = {
                    k for k, v in schema.items() if v.get("required", False)
                }
                allowed_keys = set(schema.keys())

                missing = required_keys - set(params.keys())
                assert not missing, (
                    f"Policy '{policy['name']}' rule_type={rule_type!r} "
                    f"is missing required params: {missing}"
                )

                unknown = set(params.keys()) - allowed_keys
                assert not unknown, (
                    f"Policy '{policy['name']}' rule_type={rule_type!r} "
                    f"has unknown params: {unknown}. "
                    f"Allowed: {allowed_keys}"
                )


class TestSpdxHeader:
    """Every manifest YAML file must start with the SPDX license identifier."""

    def test_spdx_header_present(self, manifest_path: str) -> None:
        with open(manifest_path) as f:
            first_line = f.readline().strip()
        assert first_line == "# SPDX-License-Identifier: Apache-2.0", (
            f"{manifest_path} does not start with SPDX header. "
            f"First line: {first_line!r}"
        )

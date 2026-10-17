"""Shipped gate policies use AAG gate kinds in both manifest catalogs."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from kyvvu_engine.engine import PolicyEngine
from kyvvu_engine.schemas import ActionKind, Behavior

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "kyvvu-manifests-public" / "manifests"
API = ROOT / "kyvvu-api" / "app" / "library" / "manifests"
BASELINE = ROOT / "kyvvu-sdk" / "kyvvu" / "baseline"

HUMAN_GATE_POLICIES = {
    "External sends require an exfiltration review gate",
    "PHI access requires patient consent gate",
    "Financial write operations require human approval",
    "HIGH risk - Mutating resource operations require human approval",
    "HIGH risk - Destructive operations require human approval",
    "Erasure operations require an approval gate",
    "Automated decisions on personal data require consent gate",
    "Destructive operations require human approval",
}


def _leaf_policies(policy: dict[str, Any]) -> Iterator[dict[str, Any]]:
    rule = policy["rule_type"]
    params = policy.get("params", {})
    if rule == "not":
        yield from _leaf_policies(params["condition"])
    elif rule in {"all_of", "any_of"}:
        for child in params["conditions"]:
            yield from _leaf_policies(child)
    else:
        yield policy


def _gate_policies(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in root.rglob("*.yaml"):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        for policy in manifest["policies"]:
            for leaf in _leaf_policies(policy):
                if leaf["rule_type"] == "step_requires_gate":
                    assert leaf["name"] not in result, leaf["name"]
                    result[leaf["name"]] = leaf["params"]
    return result


def test_public_and_api_gate_policies_require_human_kind() -> None:
    public = _gate_policies(PUBLIC)
    api = _gate_policies(API)
    baseline_names = set(_gate_policies(BASELINE))
    assert set(public) == HUMAN_GATE_POLICIES | baseline_names
    assert api == public
    for name in HUMAN_GATE_POLICIES:
        params = public[name]
        assert params["gate_kind"] == "human", name
        assert "gate_check_type" not in params, name
        assert "gate_result" not in params, name


def test_bundled_baseline_gate_policies_keep_a_kind_agnostic_pass_requirement() -> None:
    baseline = _gate_policies(BASELINE)
    assert len(baseline) == 3
    for name, params in baseline.items():
        assert "gate_kind" not in params, name
        assert "gate_decision" not in params, name
        assert "gate_check_type" not in params, name
        assert "gate_result" not in params, name


def test_every_shipped_policy_tree_omits_retired_gate_parameters() -> None:
    for root in (PUBLIC, API, BASELINE):
        for path in root.rglob("*.yaml"):
            manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
            for policy in manifest["policies"]:
                for leaf in _leaf_policies(policy):
                    params = leaf.get("params", {})
                    assert "gate_check_type" not in params, f"{path}: {leaf['rule_type']}"
                    assert "gate_result" not in params, f"{path}: {leaf['rule_type']}"


def test_exfiltration_example_records_a_passed_human_gate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    source = ROOT / "kyvvu-manifests-public" / "examples" / "exfiltration_demo.py"
    spec = importlib.util.spec_from_file_location("exfiltration_gate_example", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gates: list[Behavior] = []
    original_record = PolicyEngine.record

    def capture_gate(self: PolicyEngine, behavior: Behavior) -> Behavior:
        recorded = original_record(self, behavior)
        if behavior.kind is ActionKind.step_gate:
            gates.append(recorded)
        return recorded

    monkeypatch.setattr(PolicyEngine, "record", capture_gate)
    module.run_clean_path(module.load_policies())
    lines = capsys.readouterr().out.splitlines()
    assert any("step.message POST" in line and "-> ALLOW" in line for line in lines)
    assert len(gates) == 1
    assert gates[0].properties["kind"] == "human"
    assert "guard" not in gates[0].properties
    assert gates[0].output["decision"] == "pass"

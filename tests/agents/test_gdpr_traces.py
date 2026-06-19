"""Agent trace tests for the GDPR data subject rights manifest."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
import yaml

from kyvvu_engine.engine import PolicyEngine
from kyvvu_engine.schemas import (
    Action,
    Behavior,
    EvalContext,
    Scope,
    StepType,
    Verb,
)

MANIFEST_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "manifests",
    "compliance",
    "gdpr-data-subject-rights.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the GDPR manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx() -> EvalContext:
    return EvalContext(
        agent_id="gdpr-agent",
        task_id="task-1",
        environment="production",
    )


def _behavior(
    step_type: StepType,
    verb: Verb | None = None,
    *,
    step_name: str = "test_step",
    properties: dict | None = None,
) -> Behavior:
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="gdpr-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


class TestRegistration:
    """GDPR registration policies."""

    def test_compliant_registration(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Process customer support tickets and resolve data subject requests",
                "maintainer_id": "dpo@example.com",
            },
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_empty_purpose(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {"purpose": "", "maintainer_id": "dpo@example.com"},
            _ctx(),
        )
        assert result.action != Action.allow

    def test_violating_short_purpose_regex(self, policies: list[dict]) -> None:
        """A non-empty purpose under 30 chars passes field_not_empty but fails the regex."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {"purpose": "support tickets", "maintainer_id": "dpo@example.com"},
            _ctx(),
        )
        assert result.action != Action.allow
        violated = {p.rule_type for p in result.policies if p.violated}
        assert "field_matches_regex" in violated
        assert "field_not_empty" not in violated  # the field is present, just too short


class TestErasureGate:
    """Article 17: DELETE operations require an erasure_approval gate."""

    def test_compliant_delete_with_gate(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="erasure_approval",
                properties={
                    "guard": {"check_type": "erasure_approval", "result": "pass"}
                },
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_record"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_delete_without_gate(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_record"),
            ctx,
        )
        assert result.action == Action.block


class TestAutomatedDecisionGate:
    """Article 22: model calls require a data_subject_consent gate."""

    def test_compliant_model_with_consent(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="consent_check",
                properties={
                    "guard": {"check_type": "data_subject_consent", "result": "pass"}
                },
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="classify_request"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_model_without_consent(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="classify_request"),
            ctx,
        )
        assert result.action == Action.block

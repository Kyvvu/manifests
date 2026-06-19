"""Agent trace tests for the EU AI Act high-risk manifest.

Tests registration-time enhanced documentation, human oversight gates
(Article 14), and robustness limits (Article 15).
"""

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
    "eu-ai-act-high-risk.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the EU AI Act high-risk manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(risk: str = "high") -> EvalContext:
    return EvalContext(
        agent_id="high-risk-agent",
        task_id="task-1",
        environment="production",
        risk_classification=risk,
    )


def _behavior(
    step_type: StepType,
    verb: Verb | None = None,
    *,
    step_name: str = "test_step",
    properties: dict | None = None,
) -> Behavior:
    """Build a minimal Behavior for evaluation."""
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="high-risk-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


class TestRegistration:
    """Registration-scope policies for high-risk agents."""

    def test_compliant_high_risk_registration(self, policies: list[dict]) -> None:
        """HIGH risk agent with all required fields passes."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "risk_classification": "high",
                "purpose": (
                    "Automated credit scoring system for consumer loan applications "
                    "using financial history and behavioural data"
                ),
                "name": "Credit Scorer v3",
                "owner_id": "compliance@bank.example.com",
                "maintainer_id": "mlops@bank.example.com",
            },
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_short_purpose_for_high_risk(self, policies: list[dict]) -> None:
        """HIGH risk agent with a purpose under 50 chars fails."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "risk_classification": "high",
                "purpose": "Credit scoring",  # only 14 chars
                "name": "Credit Scorer v3",
                "owner_id": "compliance@bank.example.com",
                "maintainer_id": "mlops@bank.example.com",
            },
            _ctx(),
        )
        assert result.action != Action.allow

    def test_violating_missing_maintainer_for_high_risk(self, policies: list[dict]) -> None:
        """HIGH risk agent without a maintainer_id violates field_not_empty."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "risk_classification": "high",
                "purpose": (
                    "Automated credit scoring system for consumer loan applications "
                    "using financial history and behavioural data"
                ),
                "name": "Credit Scorer v3",
                "owner_id": "compliance@bank.example.com",
                # maintainer_id deliberately omitted
            },
            _ctx(),
        )
        assert result.action != Action.allow
        assert any(
            p.violated
            and p.rule_type == "field_not_empty"
            and p.name == "HIGH risk agents must have a designated maintainer"
            for p in result.policies
        )


class TestDataQualityGate:
    """Article 10: a step.gate must precede any step.model (step_requires_predecessor)."""

    def test_compliant_model_after_gate(self, policies: list[dict]) -> None:
        """A model call preceded by a gate satisfies the data-quality predecessor."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="data_quality_check",
                properties={"guard": {"check_type": "data_quality", "result": "pass"}},
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="score_applicant"),
            ctx,
        )
        assert not any(
            p.violated and p.rule_type == "step_requires_predecessor"
            for p in result.policies
        )

    def test_violating_model_without_predecessor_gate(self, policies: list[dict]) -> None:
        """A model call with no prior step.gate violates step_requires_predecessor."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="score_applicant"),
            ctx,
        )
        assert result.action != Action.allow
        assert any(
            p.violated and p.rule_type == "step_requires_predecessor"
            for p in result.policies
        )


class TestHumanOversight:
    """Article 14: human oversight gates on mutating operations."""

    def test_compliant_resource_post_with_gate(self, policies: list[dict]) -> None:
        """Resource POST preceded by a human_approval gate passes."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record a human approval gate.
        gate = _behavior(
            StepType.step_gate,
            step_name="human_approval",
            properties={"guard": {"check_type": "human_approval", "result": "pass"}},
        )
        engine.record(gate)
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="update_record"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_resource_post_without_gate(self, policies: list[dict]) -> None:
        """Resource POST without any gate in history is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="update_record"),
            ctx,
        )
        assert result.action == Action.block

    def test_compliant_resource_delete_with_gate(self, policies: list[dict]) -> None:
        """Resource DELETE preceded by a human_approval gate passes."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        gate = _behavior(
            StepType.step_gate,
            step_name="human_approval",
            properties={"guard": {"check_type": "human_approval", "result": "pass"}},
        )
        engine.record(gate)
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_record"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_resource_delete_without_gate(self, policies: list[dict]) -> None:
        """Resource DELETE without gate is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_record"),
            ctx,
        )
        assert result.action == Action.block


class TestRobustness:
    """Article 15: execution limits prevent runaway behaviour."""

    def test_compliant_within_resource_limit(self, policies: list[dict]) -> None:
        """A few resource calls are well within the 50-step limit."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
            ctx,
        )
        # GET on step.resource with no gate — only the gate policies
        # target POST/DELETE, so GET should pass the oversight policies.
        # The execution_max_steps policy should also pass (0 prior steps).
        assert result.action == Action.allow

    def test_violating_exceeds_resource_limit(self, policies: list[dict]) -> None:
        """Exceeding 50 resource calls triggers execution_max_steps."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        for _ in range(50):
            engine.record(
                _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data")
            )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
            ctx,
        )
        assert result.action != Action.allow

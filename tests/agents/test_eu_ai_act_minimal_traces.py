"""Agent trace tests for the EU AI Act minimal/limited risk manifest.

Tests registration-time documentation policies and Article 50 transparency
obligations (chatbot disclosure, AI-generated content marking).
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
    "eu-ai-act-minimal.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the EU AI Act minimal manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(risk: str = "limited") -> EvalContext:
    return EvalContext(
        agent_id="minimal-agent",
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
        agent_id="minimal-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


class TestRegistration:
    """Registration-scope policies: documentation baseline."""

    def test_compliant_registration(self, policies: list[dict]) -> None:
        """Agent with all required fields passes registration."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Provide customer support via chat interface",
                "name": "Support Bot",
                "risk_classification": "limited",
                "owner_id": "team-compliance@example.com",
            },
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_empty_purpose(self, policies: list[dict]) -> None:
        """Agent with empty purpose fails the field_not_empty check."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "",
                "name": "Support Bot",
                "risk_classification": "limited",
                "owner_id": "team@example.com",
            },
            _ctx(),
        )
        assert result.action != Action.allow

    def test_violating_invalid_risk_classification(self, policies: list[dict]) -> None:
        """Agent with an invalid risk classification is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Provide customer support via chat interface",
                "name": "Support Bot",
                "risk_classification": "unacceptable",
                "owner_id": "team@example.com",
            },
            _ctx(),
        )
        assert result.action != Action.allow

    def test_violating_short_purpose_regex(self, policies: list[dict]) -> None:
        """A non-empty purpose under 20 chars fails the substantive-purpose regex."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "demo",  # non-empty but < 20 chars
                "name": "Support Bot",
                "risk_classification": "limited",
                "owner_id": "team@example.com",
            },
            _ctx(),
        )
        assert result.action != Action.allow
        violated = {p.rule_type for p in result.policies if p.violated}
        assert "field_matches_regex" in violated
        assert "field_not_empty" not in violated


class TestTransparencyObligations:
    """Step-execution policies: Article 50 transparency gates."""

    def test_compliant_message_with_gate(self, policies: list[dict]) -> None:
        """Outbound message preceded by a disclosure gate passes."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record a disclosure gate.
        gate = _behavior(
            StepType.step_gate,
            step_name="chatbot_disclosure",
            properties={"guard": {"result": "pass"}},
        )
        engine.record(gate)
        # Evaluate outbound message.
        result = engine.evaluate(
            _behavior(StepType.step_message, Verb.POST, step_name="send_reply"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_message_without_gate(self, policies: list[dict]) -> None:
        """Outbound message without any gate in history triggers a violation.

        The chatbot disclosure policy has severity ``high`` which maps to
        ``warn`` (only ``critical`` severity produces ``block``).
        """
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_message, Verb.POST, step_name="send_reply"),
            ctx,
        )
        assert result.action != Action.allow

    def test_compliant_model_call_with_gate(self, policies: list[dict]) -> None:
        """Model call with a preceding gate passes Article 50(3)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        gate = _behavior(
            StepType.step_gate,
            step_name="content_marking",
        )
        engine.record(gate)
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="generate_text"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_model_call_without_gate(self, policies: list[dict]) -> None:
        """Model call without a preceding gate violates Article 50(3)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="generate_text"),
            ctx,
        )
        assert result.action != Action.allow

"""Agent trace tests for the demo manifest.

Each test builds a minimal Behavior sequence and evaluates it through the
kyvvu-engine PolicyEngine, asserting that compliant traces are allowed and
violating traces produce the expected block/warn action.
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
    os.path.dirname(__file__), "..", "..", "manifests", "operational", "demo.yaml"
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the demo manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx() -> EvalContext:
    return EvalContext(
        agent_id="demo-agent", task_id="task-1", environment="development"
    )


def _behavior(
    step_type: StepType,
    verb: Verb | None = None,
    *,
    step_name: str = "test_step",
) -> Behavior:
    """Build a minimal Behavior for evaluation."""
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="demo-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
    )


class TestDemoRegistration:
    """Registration-scope policies from the demo manifest."""

    def test_compliant_registration(self, policies: list[dict]) -> None:
        """Agent with a documented purpose passes registration."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate_registration(
            {"purpose": "A helpful demo agent for testing the Kyvvu platform"},
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_registration_empty_purpose(self, policies: list[dict]) -> None:
        """Agent with an empty purpose fails registration."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate_registration({"purpose": ""}, ctx)
        assert result.action != Action.allow


class TestDemoStepExecution:
    """Step-execution policies from the demo manifest."""

    def test_compliant_model_call_within_limit(self, policies: list[dict]) -> None:
        """A single model call is well within the max_steps limit."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="call_llm"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_exceeds_model_call_limit(self, policies: list[dict]) -> None:
        """Exceeding 10 model calls triggers the execution_max_steps policy."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record 10 model calls.
        for _ in range(10):
            b = _behavior(StepType.step_model, Verb.POST, step_name="call_llm")
            engine.record(b)
        # The 11th should be blocked.
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="call_llm"),
            ctx,
        )
        assert result.action == Action.block

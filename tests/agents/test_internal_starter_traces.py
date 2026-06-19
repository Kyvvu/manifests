"""Agent trace tests for the internal AI starter manifest."""

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
    "operational",
    "internal-ai-starter.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the internal AI starter manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(*, agent_allowed_tools: list[str] | None = None) -> EvalContext:
    return EvalContext(
        agent_id="starter-agent",
        task_id="task-1",
        environment="development",
        agent_allowed_tools=agent_allowed_tools,
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
        agent_id="starter-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


class TestRegistration:
    """Registration policies for the internal starter."""

    def test_compliant_registration(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "name": "Internal Helper Bot",
                "purpose": "Assist employees with common IT tasks",
                "owner_id": "it@example.com",
            },
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_no_owner(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {"name": "Bot", "purpose": "Help with IT tasks", "owner_id": ""},
            _ctx(),
        )
        assert result.action != Action.allow


class TestToolAllowlist:
    """Fail-closed tool allowlisting."""

    def test_compliant_tool_in_allowlist(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["fetch_data", "send_email"])
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_tool_not_in_allowlist(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["fetch_data", "send_email"])
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="execute_code"),
            ctx,
        )
        assert result.action == Action.block

    def test_violating_no_allowlist_declared(self, policies: list[dict]) -> None:
        """Agent with no declared_tools is blocked (fail-closed)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=None)
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
            ctx,
        )
        assert result.action == Action.block


class TestTokenBudget:
    """usage_budget: cap cumulative step.model token usage at 100,000 per task."""

    def test_compliant_within_budget(self, policies: list[dict]) -> None:
        """Cumulative tokens under budget passes (kept under the consecutive
        limit by interleaving a non-model step)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["call_llm", "fetch_data"])
        engine.record(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="call_llm",
                properties={"usage": {"total_tokens": 40000}},
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="call_llm",
                properties={"usage": {"total_tokens": 5000}},
            ),
            ctx,
        )
        assert not any(
            p.violated and p.rule_type == "usage_budget" for p in result.policies
        )

    def test_violating_exceeds_budget(self, policies: list[dict]) -> None:
        """Cumulative recorded tokens over 100k blocks the next model call."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["call_llm", "fetch_data"])
        # Two recorded model calls totalling 120k tokens (interleaved with a
        # non-model step so the consecutive-loop rule does not also trip).
        engine.record(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="call_llm",
                properties={"usage": {"total_tokens": 60000}},
            )
        )
        engine.record(_behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"))
        engine.record(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="call_llm",
                properties={"usage": {"total_tokens": 60000}},
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="call_llm",
                properties={"usage": {"total_tokens": 1000}},
            ),
            ctx,
        )
        assert result.action == Action.block
        assert any(
            p.violated and p.rule_type == "usage_budget" for p in result.policies
        )


class TestDestructiveGate:
    """step_requires_gate: DELETE operations require a preceding human gate."""

    def test_compliant_delete_with_gate(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["delete_record"])
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="approval",
                properties={"guard": {"check_type": "human_approval", "result": "pass"}},
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_record"),
            ctx,
        )
        assert not any(
            p.violated and p.rule_type == "step_requires_gate" for p in result.policies
        )

    def test_violating_delete_without_gate(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["delete_record"])
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_record"),
            ctx,
        )
        assert result.action == Action.block
        assert any(
            p.violated and p.rule_type == "step_requires_gate" for p in result.policies
        )


class TestLlmCallLimit:
    """execution_max_steps: cap step.model calls at 50 per task."""

    def test_violating_exceeds_llm_limit(self, policies: list[dict]) -> None:
        """A 51st model call exceeds the 50-call limit.

        Model calls are interleaved with a non-model step so the
        consecutive-loop rule (limit 5) is not what trips first.
        """
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["call_llm", "fetch_data"])
        for _ in range(50):
            engine.record(
                _behavior(StepType.step_model, Verb.POST, step_name="call_llm")
            )
            engine.record(
                _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data")
            )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="call_llm"),
            ctx,
        )
        assert result.action == Action.block
        assert any(
            p.violated and p.rule_type == "execution_max_steps"
            for p in result.policies
        )


class TestConsecutiveLimit:
    """Prevent infinite LLM loops (max 5 consecutive step.model)."""

    def test_compliant_within_limit(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["call_llm"])
        for _ in range(4):
            engine.record(
                _behavior(StepType.step_model, Verb.POST, step_name="call_llm")
            )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="call_llm"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_exceeds_consecutive_limit(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["call_llm"])
        for _ in range(5):
            engine.record(
                _behavior(StepType.step_model, Verb.POST, step_name="call_llm")
            )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="call_llm"),
            ctx,
        )
        assert result.action == Action.block

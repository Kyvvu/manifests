"""Agent trace tests for the OWASP agentic default security manifest.

Tests the tool-allowlist enforcement, gate requirements for code execution
and destructive operations, the compound taint policy, and runaway
prevention.
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
    "security",
    "owasp-agentic-default.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the OWASP manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(
    *,
    agent_allowed_tools: list[str] | None = None,
) -> EvalContext:
    return EvalContext(
        agent_id="owasp-agent",
        task_id="task-1",
        environment="production",
        risk_classification="high",
        agent_allowed_tools=agent_allowed_tools,
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
        agent_id="owasp-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


class TestToolAllowlist:
    """step_name_in_allowlist: blocks tool calls not in declared_tools."""

    def test_compliant_tool_in_allowlist(self, policies: list[dict]) -> None:
        """Tool call whose step_name is in declared_tools passes."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["search_web", "send_email"])
        # Record a gate first so gate-requiring policies don't interfere.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="approval",
                properties={"guard": {"result": "pass"}},
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="search_web"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_tool_not_in_allowlist(self, policies: list[dict]) -> None:
        """Tool call with step_name not in declared_tools is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["search_web"])
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="exfiltrate_data"),
            ctx,
        )
        assert result.action == Action.block


class TestCodeExecutionGate:
    """step_requires_gate: code execution needs a preceding gate."""

    def test_compliant_exec_with_gate(self, policies: list[dict]) -> None:
        """step.exec preceded by a gate with result=pass is allowed."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["run_script"])
        gate = _behavior(
            StepType.step_gate,
            step_name="code_review",
            properties={"guard": {"result": "pass"}},
        )
        engine.record(gate)
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="run_script"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_exec_without_gate(self, policies: list[dict]) -> None:
        """step.exec without any gate in history is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["run_script"])
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="run_script"),
            ctx,
        )
        assert result.action == Action.block


class TestDestructiveOperationGate:
    """step_requires_gate: DELETE operations need a preceding gate."""

    def test_compliant_delete_with_gate(self, policies: list[dict]) -> None:
        """Resource DELETE preceded by a gate passes."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["delete_file"])
        gate = _behavior(
            StepType.step_gate,
            step_name="delete_approval",
            properties={"guard": {"result": "pass"}},
        )
        engine.record(gate)
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_file"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_delete_without_gate(self, policies: list[dict]) -> None:
        """Resource DELETE without gate is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["delete_file"])
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.DELETE, step_name="delete_file"),
            ctx,
        )
        assert result.action == Action.block


class TestExternalContentTaint:
    """Compound taint policy: high-impact action after external content
    requires a FRESH gate immediately preceding it."""

    def test_compliant_exec_after_external_with_fresh_gate(
        self, policies: list[dict]
    ) -> None:
        """External fetch -> fresh gate -> exec is allowed."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["run_script", "fetch_url"])
        # Step 1: fetch external content.
        engine.record(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="fetch_url",
                properties={"target": {"trust": "external"}},
            )
        )
        # Step 2: fresh gate immediately before exec.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="fresh_approval",
                properties={"guard": {"result": "pass"}},
            )
        )
        # Step 3: exec — gate is immediate predecessor, so taint policy passes.
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="run_script"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_exec_after_external_without_fresh_gate(
        self, policies: list[dict]
    ) -> None:
        """External fetch -> (no gate) -> exec is blocked by taint policy."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["run_script", "fetch_url"])
        # Step 1: fetch external content.
        engine.record(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="fetch_url",
                properties={"target": {"trust": "external"}},
            )
        )
        # Step 2: exec without a fresh gate — taint policy blocks.
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="run_script"),
            ctx,
        )
        assert result.action == Action.block

    def test_compliant_exec_without_external_content(
        self, policies: list[dict]
    ) -> None:
        """Exec with no external content in history — taint policy does not apply."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["run_script"])
        # Only a gate, no external fetch — taint conditions not all met.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="approval",
                properties={"guard": {"result": "pass"}},
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="run_script"),
            ctx,
        )
        assert result.action == Action.allow


class TestRunawayPrevention:
    """execution_max_steps: bounds resource calls per task."""

    def test_compliant_within_limit(self, policies: list[dict]) -> None:
        """Resource calls within the 50-step limit pass."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["fetch_data"])
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_exceeds_limit(self, policies: list[dict]) -> None:
        """Exceeding 50 resource calls triggers the block."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx(agent_allowed_tools=["fetch_data"])
        for _ in range(50):
            engine.record(
                _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data")
            )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
            ctx,
        )
        assert result.action != Action.allow

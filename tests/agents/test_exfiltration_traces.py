"""Agent trace tests for the data exfiltration guard manifest.

The flagship path-dependent manifest. Tests the tainted_path_block rule
(Layer 1), gate requirement (Layer 2), and credential-to-message sequence
prohibition (Layer 5).
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
    "data-exfiltration-guard.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the exfiltration guard manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx() -> EvalContext:
    return EvalContext(
        agent_id="exfil-agent",
        task_id="task-1",
        environment="production",
        risk_classification="high",
    )


def _behavior(
    step_type: StepType,
    verb: Verb | None = None,
    *,
    step_name: str = "test_step",
    properties: dict | None = None,
    input_data: dict | None = None,
) -> Behavior:
    """Build a minimal Behavior for evaluation."""
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="exfil-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
        input=input_data,
    )


class TestTaintedPathBlock:
    """Layer 1: sensitive data read permanently taints the task path."""

    def test_violating_send_after_sensitive_read(self, policies: list[dict]) -> None:
        """step.resource GET (pii) -> step.message POST -> BLOCK.

        The taint is permanent — no gate can clear it within the same task.
        """
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record a sensitive data read.
        engine.record(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="read_customer_db",
                properties={
                    "data": {"classification": "pii"},
                    "target": {"host": "internal.example.com"},
                },
            )
        )
        # Record an exfiltration review gate (does NOT clear taint).
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="exfiltration_review",
                properties={
                    "guard": {"check_type": "exfiltration_review", "result": "pass"}
                },
            )
        )
        # Attempt outbound message — should be blocked by taint.
        result = engine.evaluate(
            _behavior(
                StepType.step_message,
                Verb.POST,
                step_name="send_email",
                properties={"target": {"host": "internal.example.com"}},
            ),
            ctx,
        )
        assert result.action == Action.block

    def test_compliant_send_without_sensitive_read(self, policies: list[dict]) -> None:
        """No sensitive read in history -> step.message POST is allowed.

        The path is clean (no data.classification=pii), so the taint
        policy does not fire.
        """
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record a non-sensitive resource read.
        engine.record(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="read_public_api",
                properties={
                    "data": {"classification": "public"},
                    "target": {"host": "api.example.com"},
                },
            )
        )
        # Record the required exfiltration review gate.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="exfiltration_review",
                properties={
                    "guard": {"check_type": "exfiltration_review", "result": "pass"}
                },
            )
        )
        # Outbound message on an allowed domain — should pass.
        result = engine.evaluate(
            _behavior(
                StepType.step_message,
                Verb.POST,
                step_name="send_notification",
                properties={"target": {"host": "internal.example.com"}},
            ),
            ctx,
        )
        assert result.action == Action.allow


class TestGateRequirement:
    """Layer 2: step.message requires an exfiltration_review gate."""

    def test_violating_message_without_gate(self, policies: list[dict]) -> None:
        """Outbound message without exfiltration_review gate is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(
                StepType.step_message,
                Verb.POST,
                step_name="send_email",
                properties={"target": {"host": "internal.example.com"}},
            ),
            ctx,
        )
        assert result.action == Action.block


class TestSequenceForbidden:
    """Layer 5: credential read -> message is forbidden."""

    def test_violating_credential_then_message(self, policies: list[dict]) -> None:
        """step.credential -> step.message is a forbidden sequence."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record credential read.
        engine.record(
            _behavior(StepType.step_credential, Verb.GET, step_name="read_api_key")
        )
        # Record gate to satisfy Layer 2.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="exfiltration_review",
                properties={
                    "guard": {"check_type": "exfiltration_review", "result": "pass"}
                },
            )
        )
        # Attempt message — blocked by sequence_forbidden.
        result = engine.evaluate(
            _behavior(
                StepType.step_message,
                Verb.POST,
                step_name="send_message",
                properties={"target": {"host": "internal.example.com"}},
            ),
            ctx,
        )
        assert result.action == Action.block

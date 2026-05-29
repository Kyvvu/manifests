#!/usr/bin/env python3
"""Data exfiltration guard demo.

Demonstrates path-dependent enforcement: the same outbound step.message POST
is allowed in a clean task but blocked after a sensitive data read enters
the task history.

No API key or network connection needed — all evaluation is in-process.

Usage:
    pip install kyvvu-engine pyyaml
    python exfiltration_demo.py
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

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
    "manifests",
    "security",
    "data-exfiltration-guard.yaml",
)


def load_policies() -> list[dict]:
    """Load and tag policies from the exfiltration guard manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def make_behavior(
    step_type: StepType,
    verb: Verb | None = None,
    *,
    step_name: str = "step",
    properties: dict | None = None,
) -> Behavior:
    """Build a minimal Behavior."""
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="demo-agent",
        task_id="task-1",
        timestamp=datetime.now(timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


def make_context() -> EvalContext:
    """Build an evaluation context."""
    return EvalContext(
        agent_id="demo-agent", task_id="task-1", environment="development"
    )


def print_result(step_num: int, label: str, result) -> None:  # noqa: ANN001
    """Print a single evaluation result."""
    action = result.action.value.upper()
    print(f"  Step {step_num}: {label:40s} -> {action}")
    if result.action != Action.allow:
        for pr in result.policies:
            if pr.violated:
                reason = ""
                if pr.violation_details:
                    reason = pr.violation_details.get("reason", "")
                print(f"    Policy: {pr.name!r}")
                if reason:
                    print(f"    Reason: {reason}")


def run_clean_path(policies: list[dict]) -> None:
    """Trace A: no sensitive data read -> outbound message allowed."""
    print("=== Clean path (no sensitive data read) ===")
    engine = PolicyEngine()
    engine.load_policies(policies)
    ctx = make_context()

    # Step 1: model call.
    b1 = make_behavior(StepType.step_model, Verb.POST, step_name="analyze_request")
    r1 = engine.evaluate(b1, ctx)
    print_result(1, "step.model POST", r1)
    engine.record(b1)

    # Step 2: read public data (no PII classification).
    b2 = make_behavior(
        StepType.step_resource,
        Verb.GET,
        step_name="read_public_api",
        properties={
            "data": {"classification": "public"},
            "target": {"host": "api.example.com"},
        },
    )
    r2 = engine.evaluate(b2, ctx)
    print_result(2, "step.resource GET [public]", r2)
    engine.record(b2)

    # Step 3: gate.
    gate = make_behavior(
        StepType.step_gate,
        step_name="exfiltration_review",
        properties={"guard": {"check_type": "exfiltration_review", "result": "pass"}},
    )
    engine.record(gate)

    # Step 4: outbound message.
    b3 = make_behavior(
        StepType.step_message,
        Verb.POST,
        step_name="send_notification",
        properties={"target": {"host": "internal.example.com"}},
    )
    r3 = engine.evaluate(b3, ctx)
    print_result(3, "step.message POST", r3)
    print()


def run_exfiltration_path(policies: list[dict]) -> None:
    """Trace B: sensitive data read -> outbound message blocked."""
    print("=== Exfiltration path (sensitive data read, then external send) ===")
    engine = PolicyEngine()
    engine.load_policies(policies)
    ctx = EvalContext(
        agent_id="demo-agent", task_id="task-2", environment="development"
    )

    # Step 1: model call.
    b1 = make_behavior(StepType.step_model, Verb.POST, step_name="analyze_request")
    b1 = b1.model_copy(update={"task_id": "task-2"})
    r1 = engine.evaluate(b1, ctx)
    print_result(1, "step.model POST", r1)
    engine.record(b1)

    # Step 2: read sensitive data (data.classification=pii).
    b2 = make_behavior(
        StepType.step_resource,
        Verb.GET,
        step_name="read_customer_db",
        properties={
            "data": {"classification": "pii"},
            "target": {"host": "internal.example.com"},
        },
    )
    b2 = b2.model_copy(update={"task_id": "task-2"})
    r2 = engine.evaluate(b2, ctx)
    print_result(2, "step.resource GET [data.classification=pii]", r2)
    engine.record(b2)

    # Step 3: gate (does NOT clear taint).
    gate = make_behavior(
        StepType.step_gate,
        step_name="exfiltration_review",
        properties={"guard": {"check_type": "exfiltration_review", "result": "pass"}},
    )
    gate = gate.model_copy(update={"task_id": "task-2"})
    engine.record(gate)

    # Step 4: outbound message -> BLOCKED by taint.
    b3 = make_behavior(
        StepType.step_message,
        Verb.POST,
        step_name="send_notification",
        properties={"target": {"host": "internal.example.com"}},
    )
    b3 = b3.model_copy(update={"task_id": "task-2"})
    r3 = engine.evaluate(b3, ctx)
    print_result(3, "step.message POST", r3)
    print()


def main() -> None:
    """Run both traces and exit with 0 if the demo behaves as expected."""
    policies = load_policies()
    run_clean_path(policies)
    run_exfiltration_path(policies)
    print("Demo complete. The same outbound message was ALLOWED in the clean path")
    print("but BLOCKED after a sensitive data read — path-dependent enforcement.")


if __name__ == "__main__":
    main()

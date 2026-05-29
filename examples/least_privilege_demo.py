#!/usr/bin/env python3
"""Least-privilege tool allowlist demo.

Demonstrates fail-closed tool allowlisting: agents can only call tools
that are in their declared_tools allowlist. Agents without an allowlist
are blocked from all tool calls.

No API key or network connection needed — all evaluation is in-process.

Usage:
    pip install kyvvu-engine pyyaml
    python least_privilege_demo.py
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
    "operational",
    "internal-ai-starter.yaml",
)


def load_policies() -> list[dict]:
    """Load and tag policies from the internal AI starter manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def make_behavior(
    step_type: StepType, verb: Verb | None, *, step_name: str
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
    )


def print_result(label: str, result) -> None:  # noqa: ANN001
    """Print a single evaluation result."""
    action = result.action.value.upper()
    print(f"  {label:55s} -> {action}")
    if result.action != Action.allow:
        for pr in result.policies:
            if pr.violated:
                print(f"    Policy: {pr.name!r}")


def main() -> None:
    """Run three traces demonstrating tool allowlist enforcement."""
    policies = load_policies()

    # Trace A: tool in allowlist -> ALLOW
    print("=== Trace A: tool in declared allowlist ===")
    engine = PolicyEngine()
    engine.load_policies(policies)
    ctx = EvalContext(
        agent_id="demo-agent",
        task_id="task-1",
        environment="development",
        agent_allowed_tools=["fetch_data", "send_email"],
    )
    r = engine.evaluate(
        make_behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
        ctx,
    )
    print_result('step_name="fetch_data" (in allowlist)', r)
    print()

    # Trace B: tool NOT in allowlist -> BLOCK
    print("=== Trace B: tool NOT in declared allowlist ===")
    engine = PolicyEngine()
    engine.load_policies(policies)
    ctx = EvalContext(
        agent_id="demo-agent",
        task_id="task-2",
        environment="development",
        agent_allowed_tools=["fetch_data", "send_email"],
    )
    r = engine.evaluate(
        make_behavior(StepType.step_exec, None, step_name="execute_code"),
        ctx,
    )
    print_result('step_name="execute_code" (NOT in allowlist)', r)
    print()

    # Trace C: no allowlist declared -> BLOCK (fail-closed)
    print("=== Trace C: no allowlist declared (fail-closed) ===")
    engine = PolicyEngine()
    engine.load_policies(policies)
    ctx = EvalContext(
        agent_id="demo-agent",
        task_id="task-3",
        environment="development",
        agent_allowed_tools=None,
    )
    r = engine.evaluate(
        make_behavior(StepType.step_resource, Verb.GET, step_name="fetch_data"),
        ctx,
    )
    print_result('step_name="fetch_data" (no allowlist)', r)
    print()

    print("Demo complete. Tool calls are fail-closed: only declared tools are allowed.")


if __name__ == "__main__":
    main()

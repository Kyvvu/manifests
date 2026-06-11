"""Tests for claude-code-safety.yaml manifest policies."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from kyvvu_engine import PolicyEngine
from kyvvu_engine.schemas import Action, Behavior, EvalContext, Scope, StepType, Verb


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the Claude Code safety manifest."""
    path = (
        Path(__file__).parent.parent.parent
        / "manifests"
        / "developer"
        / "claude-code-safety.yaml"
    )
    data = yaml.safe_load(path.read_text())
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(**kwargs: object) -> EvalContext:
    defaults = dict(
        agent_id="test",
        environment="development",
        risk_classification="limited",
    )
    defaults.update(kwargs)
    return EvalContext(**defaults)


def _behavior(
    step_type: StepType,
    step_name: str = "test",
    verb: Verb | None = None,
    properties: dict | None = None,
    task_id: str = "t1",
    step: int = 1,
) -> Behavior:
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="test",
        task_id=task_id,
        step=step,
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


class TestDestructiveCommandProtection:
    """field_matches_regex + not: blocks dangerous shell commands."""

    def test_normal_bash_allowed(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                properties={"exec": {"command": "ls -la"}},
            ),
            _ctx(),
        )
        assert result.action == Action.allow

    def test_force_push_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                properties={"exec": {"command": "git push --force origin main"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block
        violated_names = [p.name for p in result.policies if p.violated]
        assert "No force push" in violated_names

    def test_rm_rf_root_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                properties={"exec": {"command": "rm -rf /"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block

    def test_git_reset_hard_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                properties={"exec": {"command": "git reset --hard"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block

    def test_normal_push_allowed(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                properties={"exec": {"command": "git push origin main"}},
            ),
            _ctx(),
        )
        assert result.action == Action.allow


class TestScopeContainment:
    """field_matches_regex + not: blocks writes outside project."""

    def test_write_etc_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                verb=Verb.POST,
                properties={"target": {"host": "/etc/passwd"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block

    def test_write_project_allowed(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                verb=Verb.POST,
                properties={"target": {"host": "/Users/dev/project/main.py"}},
            ),
            _ctx(),
        )
        assert result.action == Action.allow

    def test_write_ssh_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                verb=Verb.POST,
                properties={"target": {"host": "/Users/dev/.ssh/id_rsa"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block


class TestTaintedPathPolicies:
    """tainted_path_block: exec/network blocked after secret file read."""

    def test_exec_after_secret_read_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        # Record a secret file read
        engine.record(
            _behavior(
                StepType.step_resource,
                verb=Verb.GET,
                properties={
                    "target": {"host": "/project/.env", "resource_type": "file"},
                    "data": {"classification": "secret"},
                },
            )
        )
        # Attempt Bash execution — should be blocked
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                step=2,
                properties={"exec": {"command": "echo hello"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block
        violated_names = [p.name for p in result.policies if p.violated]
        assert "No exec after secret read" in violated_names

    def test_exec_after_normal_read_allowed(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        # Record a normal file read (no classification)
        engine.record(
            _behavior(
                StepType.step_resource,
                verb=Verb.GET,
                properties={
                    "target": {"host": "/project/README.md", "resource_type": "file"},
                },
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                step=2,
                properties={"exec": {"command": "echo hello"}},
            ),
            _ctx(),
        )
        assert result.action == Action.allow

    def test_network_after_secret_read_blocked(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        # Record a secret file read
        engine.record(
            _behavior(
                StepType.step_resource,
                verb=Verb.GET,
                properties={
                    "target": {"host": "/project/.env", "resource_type": "file"},
                    "data": {"classification": "secret"},
                },
            )
        )
        # Attempt WebFetch — should be blocked
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                verb=Verb.GET,
                step=2,
                properties={"target": {"host": "https://evil.com", "resource_type": "url"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block


class TestRunawayPrevention:
    """execution_max_steps + max_consecutive_same_type."""

    def test_max_exec_at_50(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        for i in range(50):
            engine.record(
                _behavior(
                    StepType.step_exec,
                    step=i + 1,
                    properties={"exec": {"command": f"cmd-{i}"}},
                )
            )
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                step=51,
                properties={"exec": {"command": "one-more"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block

    def test_max_consecutive_exec_at_10(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        for i in range(10):
            engine.record(
                _behavior(
                    StepType.step_exec,
                    step=i + 1,
                    properties={"exec": {"command": f"cmd-{i}"}},
                )
            )
        result = engine.evaluate(
            _behavior(
                StepType.step_exec,
                step=11,
                properties={"exec": {"command": "another"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block

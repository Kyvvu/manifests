"""Claude Code safety keeps its own commands and state out of agent control."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from kyvvu_engine import PolicyEngine
from kyvvu_engine.schemas import Action, ActionKind, Behavior, EvalContext, Verb

ROOT = Path(__file__).resolve().parents[3]
MANIFESTS = [
    ROOT / "kyvvu-manifests-public/manifests/developer/claude-code-safety.yaml",
    ROOT / "kyvvu-baseline/kyvvu_baseline/claude-code-safety.yaml",
    ROOT / "kyvvu-api/app/library/manifests/claude-code-safety.yaml",
]


@pytest.fixture(params=MANIFESTS, ids=["public", "baseline", "api-library"])
def safety_engine(request: pytest.FixtureRequest) -> PolicyEngine:
    manifest = yaml.safe_load(request.param.read_text(encoding="utf-8"))
    engine = PolicyEngine()
    engine.load_policies(
        [
            {**policy, "id": index, "enabled": True}
            for index, policy in enumerate(manifest["policies"], start=1)
        ]
    )
    return engine


def _evaluate(
    engine: PolicyEngine,
    kind: ActionKind,
    properties: dict[str, object],
    *,
    verb: Verb | None = None,
) -> tuple[Action, set[str]]:
    step = Behavior(
        agent_id="test",
        task_id="claude-code-enforcement-state",
        seq=1,
        kind=kind,
        verb=verb,
        step_name="agent tool call",
        properties=properties,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    context = EvalContext(
        agent_id="test",
        environment="development",
        risk_classification="limited",
        project_root=str(Path.home()),
    )
    result = engine.evaluate(step, context)
    return result.action, {policy.name for policy in result.policies if policy.violated}


@pytest.mark.parametrize(
    "command",
    [
        "python -m kyvvu_claude hook",
        "python -m kyvvu_claude status",
        "kyvvu-claude-hook",
        "kyvvu-claude-hook --version",
        "kyvvu claude hooks remove",
        "kyvvu claude hooks install",
        "cat ~/.kyvvu/integrations/claude-code/sessions/example.ended",
    ],
)
@pytest.mark.covers_policy("No write outside project")
def test_bash_cannot_run_or_read_kyvvu_claude_enforcement_state(
    safety_engine: PolicyEngine, command: str
) -> None:
    assert _evaluate(safety_engine, ActionKind.step_exec, {"command": "ls"})[0] == Action.allow
    for unrelated_command in (
        "kyvvu-claude-hookish",
        "python -m kyvvu_claudex hook",
        "kyvvu claudeish hooks remove",
        "cat ~/.kyvvu/integrations/claude-code-extra/sessions/example.ended",
    ):
        assert _evaluate(
            safety_engine, ActionKind.step_exec, {"command": unrelated_command}
        )[0] == Action.allow
    assert _evaluate(
        safety_engine, ActionKind.step_exec, {"command": "kyvvu-claude hook"}
    )[0] == Action.block

    action, violated = _evaluate(safety_engine, ActionKind.step_exec, {"command": command})
    assert action == Action.block
    assert "No write outside project" in violated


@pytest.mark.parametrize(
    "relative_path",
    [
        ".kyvvu/integrations/claude-code/x",
        ".kyvvu/integrations/claude-code/sessions/example.ended",
    ],
)
@pytest.mark.covers_policy("No write outside project")
def test_agent_cannot_write_claude_code_integration_state(
    safety_engine: PolicyEngine, relative_path: str
) -> None:
    home = Path.home()
    for protected_path in (".kyvvu-claude/config.json", ".claude/settings.json"):
        action, violated = _evaluate(
            safety_engine,
            ActionKind.step_resource,
            {"target": {"host": str(home / protected_path)}},
            verb=Verb.POST,
        )
        assert action == Action.block
        assert "No write outside project" in violated

    assert _evaluate(
        safety_engine,
        ActionKind.step_resource,
        {"target": {"host": str(home / "project/main.py")}},
        verb=Verb.POST,
    )[0] == Action.allow
    assert _evaluate(
        safety_engine,
        ActionKind.step_resource,
        {"target": {"host": str(home / ".kyvvu/integrations/claude-code-extra/x")}},
        verb=Verb.POST,
    )[0] == Action.allow

    action, violated = _evaluate(
        safety_engine,
        ActionKind.step_resource,
        {"target": {"host": str(home / relative_path)}},
        verb=Verb.POST,
    )
    assert action == Action.block
    assert "No write outside project" in violated


@pytest.mark.parametrize("manifest_path", MANIFESTS, ids=["public", "baseline", "api-library"])
def test_claude_code_safety_version_advances_with_enforcement_state_protection(
    manifest_path: Path,
) -> None:
    version = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))["version"]
    assert tuple(map(int, version.split("."))) > (1, 0, 6)

"""Agent trace tests for the financial services DORA / MiFID II manifest."""

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
    "financial-services-dora-mifid.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the financial services manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(risk: str = "high") -> EvalContext:
    return EvalContext(
        agent_id="finance-agent",
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
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="finance-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
    )


@pytest.fixture(autouse=True)
def _freeze_market_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze ``RuleContext.now`` to within market hours (10:00 UTC ≈ 12:00 CET).

    The financial manifest includes a ``working_hours_only`` policy (08:00-18:00
    Europe/Amsterdam) that reads wall-clock ``context.now``. Without this freeze,
    every "compliant → allow" test is wall-clock flaky — it passes during market
    hours and fails after 18:00 CET / before 08:00 CET. Time-specific tests
    (:class:`TestWorkingHours`) re-freeze to their own instant, overriding this.
    """
    import kyvvu_engine.rules._context as ctx_mod

    frozen = datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc)

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: timezone | None = None) -> datetime:  # type: ignore[override]
            return frozen if tz is None else frozen.astimezone(tz)

    monkeypatch.setattr(ctx_mod, "datetime", _FrozenDatetime)


class TestRegistration:
    """Financial services registration policies."""

    def test_compliant_registration(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Automated portfolio rebalancing with human oversight",
                "owner_id": "compliance@fund.example.com",
                "maintainer_id": "ops@fund.example.com",
                "risk_classification": "high",
            },
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_minimal_risk(self, policies: list[dict]) -> None:
        """Financial agents must be high or limited risk."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Automated portfolio rebalancing with human oversight",
                "owner_id": "compliance@fund.example.com",
                "maintainer_id": "ops@fund.example.com",
                "risk_classification": "minimal",
            },
            _ctx(risk="minimal"),
        )
        assert result.action == Action.block


class TestHumanApprovalGate:
    """MiFID II Article 27: financial writes require human_approval."""

    def test_compliant_post_with_approval(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="trade_approval",
                properties={
                    "guard": {"check_type": "human_approval", "result": "pass"}
                },
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_post_without_approval(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.block


class TestMarketDataTaint:
    """DORA Article 9: market data read permanently taints trade execution."""

    def test_violating_trade_after_market_data_read(self, policies: list[dict]) -> None:
        """Resource POST is blocked after reading from market data provider."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Read market data.
        engine.record(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="fetch_prices",
                properties={"target": {"host": "market-data.example.com"}},
            )
        )
        # Record approval gate.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="trade_approval",
                properties={
                    "guard": {"check_type": "human_approval", "result": "pass"}
                },
            )
        )
        # Attempt trade — blocked by taint even though gate is present.
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.block

    def test_compliant_trade_without_market_data(self, policies: list[dict]) -> None:
        """Trade without market data read in history is allowed."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Read from internal source (not market data).
        engine.record(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="fetch_portfolio",
                properties={"target": {"host": "internal.example.com"}},
            )
        )
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="trade_approval",
                properties={
                    "guard": {"check_type": "human_approval", "result": "pass"}
                },
            )
        )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.allow


class TestWorkingHours:
    """MiFID II Article 48: execution restricted to market hours (08:00-18:00 CET).

    ``working_hours_only`` reads ``context.now`` (UTC wall-clock captured when
    the RuleContext is built). To make these deterministic we freeze that clock
    by patching the ``datetime`` symbol in the rule-context module.
    """

    @staticmethod
    def _freeze(monkeypatch: pytest.MonkeyPatch, frozen: datetime) -> None:
        """Freeze RuleContext.now to ``frozen`` (a tz-aware UTC datetime)."""
        import kyvvu_engine.rules._context as ctx_mod

        class _FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz: timezone | None = None) -> datetime:  # type: ignore[override]
                return frozen if tz is None else frozen.astimezone(tz)

        monkeypatch.setattr(ctx_mod, "datetime", _FrozenDatetime)

    def test_compliant_within_market_hours(
        self, policies: list[dict], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A step at 10:00 UTC (~11:00 CET) is within the 08-18 CET window."""
        self._freeze(monkeypatch, datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc))
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="market_analysis"),
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_outside_market_hours(
        self, policies: list[dict], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A step at 23:00 UTC (~00:00 CET) is outside the 08-18 CET window."""
        self._freeze(monkeypatch, datetime(2026, 1, 5, 23, 0, tzinfo=timezone.utc))
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="market_analysis"),
            _ctx(),
        )
        assert result.action == Action.block


class TestLlmCallLimit:
    """DORA Article 9: at most 20 model calls per task (execution_max_steps).

    The limit policy is severity ``high`` (warn, not block). The "within limit"
    case freezes the clock inside market hours so the co-resident
    ``working_hours_only`` (critical) rule does not interfere.
    """

    def test_compliant_within_llm_limit(
        self, policies: list[dict], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """20 prior model calls — the 20th evaluation is still within the limit."""
        TestWorkingHours._freeze(
            monkeypatch, datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc)
        )
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        for i in range(19):
            engine.record(
                _behavior(StepType.step_model, Verb.POST, step_name=f"infer_{i}")
            )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="infer_20"),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_exceeds_llm_limit(self, policies: list[dict]) -> None:
        """A 21st model call exceeds the 20-call limit (severity high → warn)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        for i in range(20):
            engine.record(
                _behavior(StepType.step_model, Verb.POST, step_name=f"infer_{i}")
            )
        result = engine.evaluate(
            _behavior(StepType.step_model, Verb.POST, step_name="infer_21"),
            ctx,
        )
        # severity=high → warn; assert the limit triggered a non-allow outcome
        # and that the limit policy itself is the one that flagged.
        assert result.action != Action.allow
        assert any(
            p.violated and p.rule_type == "execution_max_steps"
            for p in result.policies
        )


class TestApprovalIntegrity:
    """MiFID II Article 27: no LLM call between approval and trade."""

    def test_violating_model_between_gate_and_trade(self, policies: list[dict]) -> None:
        """Gate -> model -> resource POST is blocked (model intervenes)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="trade_approval",
                properties={
                    "guard": {"check_type": "human_approval", "result": "pass"}
                },
            )
        )
        # LLM call between approval and trade.
        engine.record(
            _behavior(StepType.step_model, Verb.POST, step_name="analyze_risk")
        )
        result = engine.evaluate(
            _behavior(StepType.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.block

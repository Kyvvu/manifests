"""Agent trace tests for the financial services DORA / MiFID II manifest."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
import yaml
from kyvvu_engine.engine import PolicyEngine
from kyvvu_engine.schemas import (
    Action,
    ActionKind,
    Behavior,
    EvalContext,
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


# 10:00 UTC is 11:00 CET: within the financial manifest's market hours.
_MARKET_HOURS = datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc)


def _behavior(
    step_type: ActionKind,
    verb: Verb | None = None,
    *,
    step_name: str = "test_step",
    properties: dict | None = None,
    output: dict | None = None,
    timestamp: datetime = _MARKET_HOURS,
) -> Behavior:
    """Build a behaviour, stamped within market hours unless told otherwise.

    ``working_hours_only`` evaluates against the behaviour's ``timestamp``, so the default stamp keeps every "compliant → allow" case inside
    the 08:00-18:00 Europe/Amsterdam window, whatever the wall clock says.
    """
    return Behavior(
        agent_id="finance-agent",
        task_id="task-1",
        timestamp=timestamp,
        kind=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
        output=output,
    )


class TestRegistration:
    """Financial services registration policies."""

    @pytest.mark.covers_policy('Agent must document its financial services purpose', 'Agent must designate a responsible owner', 'Agent must designate a maintainer', violated=False)
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

    @pytest.mark.covers_policy('Financial agents must be high or limited risk')
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
                ActionKind.step_gate,
                step_name="trade_approval",
                properties={"kind": "human"}, output={"decision": "pass"},
            )
        )
        result = engine.evaluate(
            _behavior(ActionKind.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.allow

    @pytest.mark.covers_policy('Financial write operations require human approval')
    def test_violating_post_without_approval(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(ActionKind.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.block


class TestMarketDataTaint:
    """DORA Article 9: market data read permanently taints trade execution."""

    @pytest.mark.covers_policy('Market data read taints downstream trade execution')
    def test_violating_trade_after_market_data_read(self, policies: list[dict]) -> None:
        """Resource POST is blocked after reading from market data provider."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Read market data.
        engine.record(
            _behavior(
                ActionKind.step_resource,
                Verb.GET,
                step_name="fetch_prices",
                properties={"target": {"host": "market-data.example.com"}},
            )
        )
        # Record approval gate.
        engine.record(
            _behavior(
                ActionKind.step_gate,
                step_name="trade_approval",
                properties={"kind": "human"}, output={"decision": "pass"},
            )
        )
        # Attempt trade — blocked by taint even though gate is present.
        result = engine.evaluate(
            _behavior(ActionKind.step_resource, Verb.POST, step_name="execute_trade"),
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
                ActionKind.step_resource,
                Verb.GET,
                step_name="fetch_portfolio",
                properties={"target": {"host": "internal.example.com"}},
            )
        )
        engine.record(
            _behavior(
                ActionKind.step_gate,
                step_name="trade_approval",
                properties={"kind": "human"}, output={"decision": "pass"},
            )
        )
        result = engine.evaluate(
            _behavior(ActionKind.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.allow


class TestWorkingHours:
    """MiFID II Article 48: execution restricted to market hours (08:00-18:00 CET).

    ``working_hours_only`` evaluates against the behaviour's ``timestamp``,
    recorded when the intent was formed, so each case stamps the
    behaviour with the time it is about and no clock is patched.
    """

    def test_compliant_within_market_hours(self, policies: list[dict]) -> None:
        """A step at 10:00 UTC (~11:00 CET) is within the 08-18 CET window."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                ActionKind.step_model, None, step_name="market_analysis",
                timestamp=datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc),
            ),
            _ctx(),
        )
        assert result.action == Action.allow

    @pytest.mark.covers_policy('Restrict execution to market hours')
    def test_violating_outside_market_hours(self, policies: list[dict]) -> None:
        """A step at 23:00 UTC (~00:00 CET) is outside the 08-18 CET window."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                ActionKind.step_model, None, step_name="market_analysis",
                timestamp=datetime(2026, 1, 5, 23, 0, tzinfo=timezone.utc),
            ),
            _ctx(),
        )
        assert result.action == Action.block


class TestLlmCallLimit:
    """DORA Article 9: at most 20 model calls per task (execution_max_steps).

    The limit policy is severity ``high`` (warn, not block). Every behaviour is
    stamped inside market hours by default, so the co-resident
    ``working_hours_only`` (critical) rule does not interfere.
    """

    def test_compliant_within_llm_limit(self, policies: list[dict]) -> None:
        """20 prior model calls — the 20th evaluation is still within the limit."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        for i in range(19):
            engine.record(
                _behavior(ActionKind.step_model, None, step_name=f"infer_{i}")
            )
        result = engine.evaluate(
            _behavior(ActionKind.step_model, None, step_name="infer_20"),
            ctx,
        )
        assert result.action == Action.allow

    @pytest.mark.covers_policy('Limit LLM calls per task')
    def test_violating_exceeds_llm_limit(self, policies: list[dict]) -> None:
        """A 21st model call exceeds the 20-call limit (severity high → warn)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        for i in range(20):
            engine.record(
                _behavior(ActionKind.step_model, None, step_name=f"infer_{i}")
            )
        result = engine.evaluate(
            _behavior(ActionKind.step_model, None, step_name="infer_21"),
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

    @pytest.mark.covers_policy('No LLM call between approval and trade execution')
    def test_violating_model_between_gate_and_trade(self, policies: list[dict]) -> None:
        """Gate -> model -> resource POST is blocked (model intervenes)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                ActionKind.step_gate,
                step_name="trade_approval",
                properties={"kind": "human"}, output={"decision": "pass"},
            )
        )
        # LLM call between approval and trade.
        engine.record(
            _behavior(ActionKind.step_model, None, step_name="analyze_risk")
        )
        result = engine.evaluate(
            _behavior(ActionKind.step_resource, Verb.POST, step_name="execute_trade"),
            ctx,
        )
        assert result.action == Action.block

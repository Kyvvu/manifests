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

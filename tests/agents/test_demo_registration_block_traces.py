"""Agent trace tests for the demo registration-block manifest.

A demo fixture: its one critical registration policy must block the demo
agents (which register no change ticket) and allow an agent that does.
"""

from __future__ import annotations

import os

import pytest
import yaml
from kyvvu_engine.engine import PolicyEngine
from kyvvu_engine.schemas import Action, EvalContext

MANIFEST_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "manifests", "operational", "demo-registration-block.yaml"
)

#: What the Customer Support Router demo registers with: a full profile, and
#: no change ticket.
_SUPPORT_DEMO = {
    "name": "Customer Support Agent",
    "purpose": (
        "Handles incoming customer support tickets: fetches from queue, classifies by "
        "category (technical/billing/general), escalates to Jira when needed, drafts "
        "responses with LLM, and sends after human approval."
    ),
    "owner_id": "demo-owner@kyvvu.com",
    "risk_classification": "high",
    "declared_tools": ["fetch_ticket", "classify_ticket", "send_response"],
    "metadata": None,
}


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _evaluate(policies: list[dict], agent: dict) -> Action:
    engine = PolicyEngine()
    engine.load_policies(policies)
    ctx = EvalContext(agent_id="demo-agent", task_id="registration", environment="development")
    return engine.evaluate_registration(agent, ctx).action


@pytest.mark.covers_policy("Agent must reference an approved change ticket")
def test_the_support_demo_is_blocked(policies: list[dict]) -> None:
    """The point of the fixture: a complete, otherwise compliant profile is refused."""
    assert _evaluate(policies, _SUPPORT_DEMO) == Action.block


def test_an_agent_with_a_change_ticket_registers(policies: list[dict]) -> None:
    agent = {**_SUPPORT_DEMO, "metadata": {"change_ticket": "CHG-1234"}}

    assert _evaluate(policies, agent) == Action.allow

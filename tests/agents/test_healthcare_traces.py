"""Agent trace tests for the healthcare NEN 7510 / HIPAA manifest."""

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
    "healthcare-nen7510-hipaa.yaml",
)


@pytest.fixture(scope="module")
def policies() -> list[dict]:
    """Load policy dicts from the healthcare manifest."""
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)
    return [{**p, "id": i + 1, "enabled": True} for i, p in enumerate(data["policies"])]


def _ctx(risk: str = "high") -> EvalContext:
    return EvalContext(
        agent_id="healthcare-agent",
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
    input_data: dict | None = None,
) -> Behavior:
    scope = Scope.task if step_type.value.startswith("task.") else Scope.step
    return Behavior(
        agent_id="healthcare-agent",
        task_id="task-1",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        scope=scope,
        step_type=step_type,
        verb=verb,
        step_name=step_name,
        properties=properties or {},
        input=input_data,
    )


class TestRegistration:
    """Healthcare registration policies."""

    def test_compliant_registration(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Clinical decision support for radiology reports",
                "owner_id": "ciso@hospital.example.com",
                "risk_classification": "high",
            },
            _ctx(),
        )
        assert result.action == Action.allow

    def test_violating_non_high_risk(self, policies: list[dict]) -> None:
        """Healthcare agents must be classified as high risk."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate_registration(
            {
                "purpose": "Clinical decision support for radiology reports",
                "owner_id": "ciso@hospital.example.com",
                "risk_classification": "minimal",
            },
            _ctx(risk="minimal"),
        )
        assert result.action == Action.block


class TestPiiDetection:
    """PHI pattern scanning in outbound payloads."""

    def test_violating_ssn_in_payload(self, policies: list[dict]) -> None:
        """Payload containing a US SSN pattern triggers pii_in_request."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        # Record a consent gate to satisfy other policies.
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="consent",
                properties={
                    "guard": {"check_type": "patient_consent", "result": "pass"}
                },
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="analyze_report",
                properties={"target": {"host": "ehr.example.com"}},
                input_data={"patient_ssn": "123-45-6789"},
            ),
            ctx,
        )
        assert result.action == Action.block

    def test_compliant_no_pii(self, policies: list[dict]) -> None:
        """Clean payload passes pii_in_request."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="consent",
                properties={
                    "guard": {"check_type": "patient_consent", "result": "pass"}
                },
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_model,
                Verb.POST,
                step_name="analyze_report",
                properties={"target": {"host": "ehr.example.com"}},
                input_data={"report_text": "Normal chest X-ray findings"},
            ),
            ctx,
        )
        assert result.action == Action.allow


class TestPatientConsentGate:
    """PHI access (step.resource) requires a patient_consent gate first."""

    def test_compliant_resource_after_consent(self, policies: list[dict]) -> None:
        """A resource access preceded by a patient_consent gate is permitted."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="consent",
                properties={"guard": {"check_type": "patient_consent", "result": "pass"}},
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="read_patient_record",
                properties={"target": {"host": "ehr.example.com"}},
            ),
            ctx,
        )
        assert result.action == Action.allow

    def test_violating_resource_without_consent(self, policies: list[dict]) -> None:
        """A resource access with no consent gate in history is blocked."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="read_patient_record",
                properties={"target": {"host": "ehr.example.com"}},
            ),
            _ctx(),
        )
        assert result.action == Action.block
        assert any(
            p.violated and p.rule_type == "step_requires_gate"
            for p in result.policies
        )


class TestHealthcareDomainAllowlist:
    """PHI access restricted to approved healthcare domains."""

    def test_violating_off_allowlist_domain(self, policies: list[dict]) -> None:
        """A resource call to an unapproved host is blocked (even with consent)."""
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        engine.record(
            _behavior(
                StepType.step_gate,
                step_name="consent",
                properties={"guard": {"check_type": "patient_consent", "result": "pass"}},
            )
        )
        result = engine.evaluate(
            _behavior(
                StepType.step_resource,
                Verb.GET,
                step_name="read_external",
                properties={"target": {"host": "leak.example.org"}},
            ),
            ctx,
        )
        assert result.action == Action.block
        assert any(
            p.violated and p.rule_type == "domain_allowlist"
            for p in result.policies
        )


class TestCodeExecutionForbidden:
    """step.exec is forbidden for high-risk healthcare agents."""

    def test_violating_exec_for_high_risk(self, policies: list[dict]) -> None:
        engine = PolicyEngine()
        engine.load_policies(policies)
        ctx = _ctx()
        result = engine.evaluate(
            _behavior(StepType.step_exec, step_name="run_script"),
            ctx,
        )
        assert result.action == Action.block

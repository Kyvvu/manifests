"""Require declared trace coverage to observe the named policy's outcome."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from kyvvu_engine.engine import PolicyEngine


@pytest.fixture(autouse=True)
def assert_covered_policy_outcomes(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """A coverage marker is an assertion about a real engine evaluation."""
    expected = {
        (name, marker.kwargs.get("violated", True))
        for marker in request.node.iter_markers("covers_policy")
        for name in marker.args
    }
    if not expected:
        yield
        return

    observed: set[tuple[str, bool]] = set()
    for method_name in ("evaluate", "evaluate_registration"):
        original = getattr(PolicyEngine, method_name)

        def record(self: PolicyEngine, *args: object, _original=original, **kwargs: object):
            result = _original(self, *args, **kwargs)
            observed.update((policy.name, policy.violated) for policy in result.policies)
            return result

        monkeypatch.setattr(PolicyEngine, method_name, record)

    yield
    assert expected <= observed, (
        f"Trace {request.node.nodeid} did not produce the declared policy outcomes: "
        f"{sorted(expected - observed)}"
    )

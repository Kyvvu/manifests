# SPDX-License-Identifier: Apache-2.0
"""Pytest entry point for the destructive-delete match/no-match fixture.

The fixture data and matching logic live in ``rm_policies.py`` (the filename
named in issue #238). pytest's default discovery only collects ``test_*.py``,
so this thin module re-exports the parametrized tests to make sure the fixture
is actually executed by ``pytest tests/``. Edit the cases in ``rm_policies.py``.
"""

from __future__ import annotations

from tests.rm_policies import (  # noqa: F401  (re-exported for pytest discovery)
    test_dangerous_deletes_are_blocked,
    test_known_gaps_slip_through,
    test_patterns_were_loaded_from_manifest,
    test_safe_deletes_pass,
)

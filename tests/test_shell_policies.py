# SPDX-License-Identifier: Apache-2.0
"""Pytest entry point for the shell write / secret-read stopgap fixture.

The fixture data and matching logic live in ``shell_policies.py`` (mirroring the
``rm_policies.py`` convention from #238). pytest's default discovery only
collects ``test_*.py``, so this thin module re-exports the parametrized tests to
make sure the fixture is actually executed by ``pytest tests/``. Edit the cases
in ``shell_policies.py``.
"""

from __future__ import annotations

from tests.shell_policies import (  # noqa: F401  (re-exported for pytest discovery)
    test_non_secret_reads_pass,
    test_safe_writes_pass,
    test_secret_known_gaps_slip_through,
    test_secret_reads_are_blocked,
    test_sensitive_writes_are_blocked,
    test_shell_patterns_were_loaded_from_manifest,
    test_write_known_gaps_slip_through,
)

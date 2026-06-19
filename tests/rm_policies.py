# SPDX-License-Identifier: Apache-2.0
"""Match/no-match fixture for the destructive-delete policies.

The ``claude-code-safety.yaml`` manifest replaces a single mis-scoped
``rm -rf`` policy with four per-target-class, force-agnostic, anchored
policies (root / home / parent-traversal / system-dirs). Hand-rolled regexes
fail in two directions at once — too strict on safe paths, too loose on
dangerous ones — so this fixture pins both directions with explicit cases.

The patterns are exercised exactly as the engine evaluates them: the
``field_matches_regex`` rule uses ``re.match(pattern, text, re.DOTALL)``
(see ``kyvvu_engine/rules/field.py``). A command is "blocked" if ANY of the
four destructive-delete patterns matches.

HONEST LIMITS (regex on an opaque shell string cannot catch these — they
need a command parser and are intentionally out of scope, documented not
pretended):

  * Quoted targets:        ``rm -rf "/"``  ``rm -rf '/'``
  * Env indirection:       ``T=/; rm -rf $T``   ``rm -rf "$ROOT"``
  * Semantic equivalents:  ``find / -delete``   ``find / -exec rm {} +``

These appear in ``KNOWN_GAPS`` below and are asserted to slip through, so the
gap is visible and any future tightening updates the fixture deliberately.
"""

from __future__ import annotations

import os
import re

import pytest
import yaml

MANIFEST_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "manifests",
    "developer",
    "claude-code-safety.yaml",
)


def _load_rm_patterns() -> list[tuple[str, str]]:
    """Return ``(policy_name, pattern)`` for each destructive-delete policy.

    Pulls the live regexes out of the manifest so the fixture tests the
    shipped policy content, not a copy that can silently drift.
    """
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)

    patterns: list[tuple[str, str]] = []
    for policy in data["policies"]:
        if "recursive delete" not in policy["name"]:
            continue
        condition = policy.get("params", {}).get("condition", {})
        if condition.get("rule_type") != "field_matches_regex":
            continue
        cond_params = condition.get("params", {})
        if cond_params.get("field") != "exec.command":
            continue
        patterns.append((policy["name"], cond_params["pattern"]))
    return patterns


_RM_PATTERNS = _load_rm_patterns()


def _is_blocked(command: str) -> bool:
    """True if any destructive-delete pattern matches, mirroring the engine."""
    return any(re.match(pat, command, re.DOTALL) for _name, pat in _RM_PATTERNS)


# ---------------------------------------------------------------------------
# Cases that MUST block (true positives)
# ---------------------------------------------------------------------------

MUST_BLOCK = [
    # Root — force-agnostic and flag-order/split tolerant.
    "rm -rf /",
    "rm -r /",
    "rm -fr /",
    "rm -r -f /",
    "rm -f -r /",
    "rm -rf /*",
    "rm --recursive /",
    "rm -Rf /",
    # Home.
    "rm -rf ~",
    "rm -rf ~/",
    "rm -rf $HOME",
    "rm -rf $HOME/",
    "rm -r ~",
    # Parent traversal — pure ..-chains.
    "rm -rf ..",
    "rm -rf ../..",
    "rm -rf ../../..",
    "rm -r ../../",
    # System directories.
    "rm -rf /etc",
    "rm -rf /bin",
    "rm -rf /sbin",
    "rm -rf /lib",
    "rm -rf /lib64",
    "rm -rf /boot",
    "rm -rf /sys",
    "rm -rf /proc",
    "rm -rf /dev",
    "rm -rf /System",
    "rm -rf /Library",
    "rm -rf /etc/",
    "rm -rf /etc/nginx",
    # Prefixed / chained command positions. The engine matches with re.match
    # (start-anchored), so the command-position prefix is what catches an rm
    # that is not the first token: after sudo/exec-wrappers, or after a
    # command separator (; && || |).
    "sudo rm -rf /",
    "sudo rm -rf /etc",
    "cd /x && rm -rf /",
    "foo; rm -rf /",
    "ls | rm -rf /",
    "cd repo && rm -rf ~",
]


# ---------------------------------------------------------------------------
# Cases that MUST pass (true negatives — legitimate developer cleanup)
# ---------------------------------------------------------------------------

MUST_PASS = [
    # Scoped absolute paths.
    "rm -rf /tmp/x",
    "rm -rf /tmp/kyvvu-test",
    "rm -rf /home/you/project/build",
    # /usr and /var intentionally NOT in the system-dir list.
    "rm -rf /usr/local/share/stale",
    "rm -rf /var/tmp/cache",
    # Named home subdirectory.
    "rm -rf ~/project/build",
    "rm -rf $HOME/cache",
    # Named relative paths (not pure ..-chains).
    "rm -rf ../sibling",
    "rm -rf ./build",
    "rm -rf node_modules",
    "rm -rf dist",
    "rm -rf ../sibling/dist",
    # Not a recursive delete at all.
    "rm /tmp/file.txt",
    "rm -f stale.lock",
    # rm passed to a non-exec command, or as a substring of another word —
    # NOT an executed rm, so the command-position prefix must let these pass.
    "echo rm -rf /",
    'printf "rm -rf /"',
    "confirm -rf /tmp/x",
]


# ---------------------------------------------------------------------------
# Known gaps — documented, NOT pretended. Regex over an opaque shell string
# cannot catch these. They are asserted to slip through so the limitation is
# explicit; closing any of them is a deliberate fixture change.
# ---------------------------------------------------------------------------

KNOWN_GAPS = [
    'rm -rf "/"',          # quoted target
    "rm -rf '/'",          # single-quoted target
    "T=/; rm -rf $T",      # env indirection
    'rm -rf "$ROOT"',      # env indirection (quoted var)
    "find / -delete",      # semantic equivalent, not rm
    "find / -exec rm -rf {} +",  # semantic equivalent via find
    "ls\nrm -rf /",        # newline-chained — newline is not a ;/&&/| separator
    "command rm -rf /",    # exec-wrapper outside the documented allowlist
    "nohup rm -rf /",      # exec-wrapper outside the documented allowlist
]


@pytest.mark.parametrize("command", MUST_BLOCK, ids=lambda c: c)
def test_dangerous_deletes_are_blocked(command: str) -> None:
    assert _is_blocked(command), (
        f"Command should be BLOCKED but no destructive-delete pattern matched: "
        f"{command!r}"
    )


@pytest.mark.parametrize("command", MUST_PASS, ids=lambda c: c)
def test_safe_deletes_pass(command: str) -> None:
    assert not _is_blocked(command), (
        f"Command should PASS but a destructive-delete pattern matched it "
        f"(over-blocking is what gets the manifest disabled): {command!r}"
    )


@pytest.mark.parametrize("command", KNOWN_GAPS, ids=lambda c: c)
def test_known_gaps_slip_through(command: str) -> None:
    """Document (don't pretend to close) the inherent limits of regex matching.

    If a future change starts catching one of these, update this fixture
    deliberately — moving the case to ``MUST_BLOCK`` — rather than letting the
    behaviour drift silently.
    """
    assert not _is_blocked(command), (
        f"Command {command!r} is now matched by a pattern. If this is intended, "
        f"move it from KNOWN_GAPS to MUST_BLOCK."
    )


def test_patterns_were_loaded_from_manifest() -> None:
    """Guard against the loader silently finding zero policies."""
    assert len(_RM_PATTERNS) == 4, (
        f"Expected 4 destructive-delete policies in the manifest, "
        f"found {len(_RM_PATTERNS)}: {[n for n, _ in _RM_PATTERNS]}"
    )

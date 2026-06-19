# SPDX-License-Identifier: Apache-2.0
"""Match/no-match fixture for the shell write / secret-read stopgap policies.

The ``claude-code-safety.yaml`` manifest gains two ``exec.command`` regex
policies (#239 Layer A) that close the most common Bash write/secret-read
vectors directly on the command string:

  * ``No shell write to sensitive paths`` — redirect/tee/cp/mv/dd/install into
    /etc, /usr, /var, /System, /Library, /boot, ~/.ssh, ~/.aws, ...
  * ``No shell read of secret files`` — cat/less/head/tail/cp/xxd/base64/od/
    strings of .env/.pem/.key/credentials/pgpass/netrc files.

Both mirror the destructive-delete pattern (``not`` over ``field_matches_regex``
on ``exec.command``) and use the existing engine rule — no new rule functions.

The patterns are exercised exactly as the engine evaluates them: the
``field_matches_regex`` rule uses ``re.match(pattern, text, re.DOTALL)``
(see ``kyvvu_engine/rules/field.py``), so each pattern begins with ``.*`` to
find the write operator / read command anywhere in the command line.

HONEST LIMITS (regex on an opaque shell string cannot catch these — they need
a command parser and are intentionally out of scope, documented not pretended):

  * Env indirection:   ``T=/etc; echo x > $T/passwd``  ``cat "$SECRET"``
  * Here-docs / -c:    ``python -c "open('/etc/x','w')"``
  * sed -i:            the write pattern intentionally omits ``sed -i`` (Layer B
                       mapper + Layer C containment cover writes structurally).

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

_SHELL_POLICY_NAMES = {
    "No shell write to sensitive paths",
    "No shell read of secret files",
}


def _load_shell_patterns() -> dict[str, str]:
    """Return ``{policy_name: pattern}`` for the shell write/secret-read policies.

    Pulls the live regexes out of the manifest so the fixture tests the
    shipped policy content, not a copy that can silently drift.
    """
    with open(MANIFEST_PATH) as f:
        data = yaml.safe_load(f)

    patterns: dict[str, str] = {}
    for policy in data["policies"]:
        if policy["name"] not in _SHELL_POLICY_NAMES:
            continue
        condition = policy.get("params", {}).get("condition", {})
        if condition.get("rule_type") != "field_matches_regex":
            continue
        cond_params = condition.get("params", {})
        if cond_params.get("field") != "exec.command":
            continue
        patterns[policy["name"]] = cond_params["pattern"]
    return patterns


_SHELL_PATTERNS = _load_shell_patterns()
_WRITE_PATTERN = _SHELL_PATTERNS.get("No shell write to sensitive paths", "")
_SECRET_PATTERN = _SHELL_PATTERNS.get("No shell read of secret files", "")


def _write_blocked(command: str) -> bool:
    """True if the shell-write pattern matches, mirroring the engine."""
    return bool(_WRITE_PATTERN) and bool(re.match(_WRITE_PATTERN, command, re.DOTALL))


def _secret_blocked(command: str) -> bool:
    """True if the secret-read pattern matches, mirroring the engine."""
    return bool(_SECRET_PATTERN) and bool(re.match(_SECRET_PATTERN, command, re.DOTALL))


# ---------------------------------------------------------------------------
# "No shell write to sensitive paths" — MUST block (true positives)
# ---------------------------------------------------------------------------

WRITE_MUST_BLOCK = [
    # Redirect into system/user paths.
    "echo x > /etc/hosts",
    "cat foo > /etc/passwd",
    "echo k >> /var/log/syslog",
    "echo k >> $HOME/.aws/credentials",
    "echo id > ~/.ssh/authorized_keys",
    # tee.
    "tee /etc/hosts",
    "tee -a /var/log/x",
    "echo cfg | tee /usr/local/etc/x",
    # cp / mv into protected paths.
    "cp secret ~/.ssh/id_rsa",
    "sudo cp x /Library/LaunchDaemons/y.plist",
    "mv payload /System/Library/x",
    # dd / install.
    "dd if=/dev/zero of=/boot/x",
    "install bin /usr/local/bin/x",
    # Per-user ssh/aws dirs.
    "cp k /Users/alice/.ssh/id_rsa",
    "cp k /home/bob/.aws/credentials",
]


# ---------------------------------------------------------------------------
# "No shell write to sensitive paths" — MUST pass (true negatives)
# ---------------------------------------------------------------------------

WRITE_MUST_PASS = [
    # Writes scoped to safe paths.
    "echo hi > /tmp/x",
    "cat foo > ./out.txt",
    "echo done > build/log.txt",
    # In-project copy / move.
    "cp a.txt b.txt",
    "mv old.py new.py",
    # Not a write at all.
    "ls -la /etc",
    "cat /etc/hosts",
    "echo done",
    "grep root /etc/passwd",
]


# ---------------------------------------------------------------------------
# "No shell read of secret files" — MUST block (true positives)
# ---------------------------------------------------------------------------

SECRET_MUST_BLOCK = [
    "cat .env",
    "cat /app/.env ",
    "less config.key ",
    "head ../secrets/.env ",
    "tail deploy.pem ",
    "cp deploy.pem /tmp/",
    "mv id.key /tmp/ ",
    "base64 id.pem ",
    "xxd token.secret ",
    "strings db.credentials ",
    "od .pgpass ",
    "cat .netrc ",
    "sudo cat .env",
    'cat ".env"',
]


# ---------------------------------------------------------------------------
# "No shell read of secret files" — MUST pass (true negatives)
# ---------------------------------------------------------------------------

SECRET_MUST_PASS = [
    "cat README.md",
    "cp notes.txt backup.txt",
    "cat envfile",
    "echo .env",
    "grep KEY config.yaml",
    "cat .environment ",
    "ls -la",
    "head -n 5 data.csv ",
]


# ---------------------------------------------------------------------------
# Known gaps — documented, NOT pretended. Regex over an opaque shell string
# cannot catch these. Asserted to slip through so the limitation is explicit;
# closing any of them is a deliberate fixture change.
# ---------------------------------------------------------------------------

WRITE_KNOWN_GAPS = [
    "T=/etc; echo x > $T/passwd",        # env indirection
    'python -c "open(\'/etc/x\',\'w\')"',  # python write, no shell operator
    "sed -i s/a/b/ /etc/hosts",          # sed -i intentionally not in pattern
]

SECRET_KNOWN_GAPS = [
    'cat "$SECRET_FILE"',                 # env indirection, no extension
    "python -c \"print(open('.env').read())\"",  # python read, no read command
    "cat .env;",                          # trailing ';' not in the (\\s|$|"|') class
]


@pytest.mark.parametrize("command", WRITE_MUST_BLOCK, ids=lambda c: c)
def test_sensitive_writes_are_blocked(command: str) -> None:
    assert _write_blocked(command), (
        f"Command should be BLOCKED by the shell-write policy but did not match: "
        f"{command!r}"
    )


@pytest.mark.parametrize("command", WRITE_MUST_PASS, ids=lambda c: c)
def test_safe_writes_pass(command: str) -> None:
    assert not _write_blocked(command), (
        f"Command should PASS but the shell-write policy matched it "
        f"(over-blocking is what gets the manifest disabled): {command!r}"
    )


@pytest.mark.parametrize("command", SECRET_MUST_BLOCK, ids=lambda c: c)
def test_secret_reads_are_blocked(command: str) -> None:
    assert _secret_blocked(command), (
        f"Command should be BLOCKED by the secret-read policy but did not match: "
        f"{command!r}"
    )


@pytest.mark.parametrize("command", SECRET_MUST_PASS, ids=lambda c: c)
def test_non_secret_reads_pass(command: str) -> None:
    assert not _secret_blocked(command), (
        f"Command should PASS but the secret-read policy matched it: {command!r}"
    )


@pytest.mark.parametrize("command", WRITE_KNOWN_GAPS, ids=lambda c: c)
def test_write_known_gaps_slip_through(command: str) -> None:
    """Document (don't pretend to close) the inherent limits of regex matching."""
    assert not _write_blocked(command), (
        f"Command {command!r} is now matched by the shell-write pattern. If this "
        f"is intended, move it from WRITE_KNOWN_GAPS to WRITE_MUST_BLOCK."
    )


@pytest.mark.parametrize("command", SECRET_KNOWN_GAPS, ids=lambda c: c)
def test_secret_known_gaps_slip_through(command: str) -> None:
    """Document (don't pretend to close) the inherent limits of regex matching."""
    assert not _secret_blocked(command), (
        f"Command {command!r} is now matched by the secret-read pattern. If this "
        f"is intended, move it from SECRET_KNOWN_GAPS to SECRET_MUST_BLOCK."
    )


def test_shell_patterns_were_loaded_from_manifest() -> None:
    """Guard against the loader silently finding zero policies."""
    assert _WRITE_PATTERN, "No shell-write policy found in the manifest."
    assert _SECRET_PATTERN, "No shell secret-read policy found in the manifest."
    assert len(_SHELL_PATTERNS) == 2, (
        f"Expected 2 shell stopgap policies in the manifest, "
        f"found {len(_SHELL_PATTERNS)}: {sorted(_SHELL_PATTERNS)}"
    )

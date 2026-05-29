# Examples

Runnable demos showing Kyvvu manifest enforcement. No API key or network needed — all evaluation is in-process.

## Prerequisites

```bash
pip install kyvvu-engine pyyaml
```

## Run

```bash
python exfiltration_demo.py      # Path-dependent exfiltration guard
python least_privilege_demo.py   # Tool allowlist (fail-closed)
```

## What they demonstrate

**exfiltration_demo.py** — The same outbound `step.message POST` is allowed in a clean task but blocked after a sensitive data read (`data.classification=pii`) enters the task history. This is the core demonstration of path-dependent enforcement.

**least_privilege_demo.py** — Tool allowlist enforcement with three traces: tool in allowlist (allowed), tool not in allowlist (blocked), and no allowlist declared (blocked, fail-closed).

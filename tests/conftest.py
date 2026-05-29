"""Shared fixtures for manifest tests.

Provides parametrized fixtures that load every YAML manifest file found
under the ``manifests/`` directory so that structural validation tests
run automatically against the full manifest library.
"""

from __future__ import annotations

import glob
import os
from typing import Any

import pytest
import yaml

MANIFESTS_DIR = os.path.join(os.path.dirname(__file__), "..", "manifests")


def all_manifest_paths() -> list[str]:
    """Return sorted list of all manifest YAML paths under ``manifests/``."""
    return sorted(glob.glob(os.path.join(MANIFESTS_DIR, "**/*.yaml"), recursive=True))


@pytest.fixture(params=all_manifest_paths(), ids=lambda p: os.path.basename(p))
def manifest_path(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture yielding each manifest file path."""
    return request.param


@pytest.fixture
def manifest_data(manifest_path: str) -> dict[str, Any]:
    """Parse and return the YAML content of a single manifest file."""
    with open(manifest_path) as f:
        return yaml.safe_load(f)

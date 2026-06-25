"""
Test the v1.0.5 manual integration smoke test artifact.

Per Plan v1.2 Block 2 v1.0.5-US-4 (AC-4):
- audit_artifacts/smoke_test/v1.0.5_output.txt exists
- File is non-empty (>= 20 lines)
- File contains the expected key markers:
  - "disclosure_id"
  - "compliance_rollup"
  - "SCITT" (or "SCITT receipt")
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = REPO_ROOT / "audit_artifacts" / "smoke_test" / "v1.0.5_output.txt"


def test_smoke_test_artifact_exists() -> None:
    """AC-4: artifact file exists."""
    assert ARTIFACT.exists(), f"missing {ARTIFACT}"


def test_smoke_test_artifact_non_empty() -> None:
    """AC-4: artifact is non-empty (>= 20 lines)."""
    content = ARTIFACT.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert len(lines) >= 20, f"artifact has only {len(lines)} lines"


def test_smoke_test_artifact_has_disclosure_id() -> None:
    """AC-4: artifact mentions disclosure_id (or equivalent)."""
    content = ARTIFACT.read_text(encoding="utf-8")
    # Accept either "disclosure_id" (with underscore) or "Disclosure ID"
    # (with space) — both are valid documentation styles.
    assert (
        "disclosure_id" in content.lower()
        or "disclosure id" in content.lower()
    ), "smoke test artifact must mention disclosure_id / Disclosure ID"


def test_smoke_test_artifact_has_compliance_rollup() -> None:
    """AC-4: artifact mentions compliance_rollup."""
    content = ARTIFACT.read_text(encoding="utf-8")
    # Accept either "compliance_rollup" (with underscore) or "Compliance rollup"
    # (with space).
    assert (
        "compliance_rollup" in content.lower()
        or "compliance rollup" in content.lower()
    ), "smoke test artifact must mention compliance_rollup"


def test_smoke_test_artifact_has_scitt_receipt() -> None:
    """AC-4: artifact mentions SCITT receipt (or SCITTReceipt)."""
    content = ARTIFACT.read_text(encoding="utf-8")
    assert "SCITT" in content, "smoke test artifact must mention SCITT"


def test_smoke_test_artifact_has_environment() -> None:
    """AC-2: artifact documents the test environment (commit SHA, OS, versions)."""
    content = ARTIFACT.read_text(encoding="utf-8")
    for marker in ("OS:", "Rust:", "Python:", "Commit SHA:", "Branch:"):
        assert marker in content, f"smoke test artifact missing environment marker: {marker!r}"


def test_smoke_test_artifact_has_honest_disclosures() -> None:
    """P1: artifact must surface honest disclosures about synthetic/fake parts."""
    content = ARTIFACT.read_text(encoding="utf-8")
    # The artifact MUST mention SYNTHETIC somewhere — per P1, the
    # synthetic nature of the bundle + fixture must be visible.
    assert "SYNTHETIC" in content or "synthetic" in content.lower(), (
        "smoke test artifact must disclose synthetic bundle/fixture per P1"
    )

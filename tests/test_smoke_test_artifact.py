"""
Test the v1.0.5 + v1.1.x manual integration smoke test artifacts.

Per Plan v1.2 Block 2 v1.0.5-US-4 (AC-4) and Block 4 v1.1.0.x+1+4 (BRECHA 5):
- audit_artifacts/smoke_test/v1.0.5_output.txt exists (existing)
- audit_artifacts/smoke_test/v1.1.x_output.txt exists (new, BRECHA 5)
- Both files are non-empty (>= 20 lines)
- Both contain the expected key markers (disclosure_id, compliance_rollup, SCITT, environment, honest disclosures)
- The v1.1.x artifact must additionally document the openssl ts -verify output
  (the CRÍTICO 1 closure evidence: Verification: OK)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
V105_ARTIFACT = REPO_ROOT / "audit_artifacts" / "smoke_test" / "v1.0.5_output.txt"
V11X_ARTIFACT = REPO_ROOT / "audit_artifacts" / "smoke_test" / "v1.1.x_output.txt"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _check_basic_markers(artifact: Path) -> None:
    """Helper: checks the v1.0.5/v1.1.x smoke test required markers."""
    assert artifact.exists(), f"missing {artifact}"
    content = _read(artifact)
    lines = content.splitlines()
    assert len(lines) >= 20, f"{artifact.name} has only {len(lines)} lines"

    lower = content.lower()
    assert "disclosure_id" in lower or "disclosure id" in lower, (
        f"{artifact.name} must mention disclosure_id"
    )
    assert "compliance_rollup" in lower or "compliance rollup" in lower, (
        f"{artifact.name} must mention compliance_rollup"
    )
    assert "SCITT" in content, f"{artifact.name} must mention SCITT"

    for marker in ("OS:", "Rust:", "Python:", "Commit SHA:", "Branch:"):
        assert marker in content, (
            f"{artifact.name} missing environment marker: {marker!r}"
        )

    assert "SYNTHETIC" in content or "synthetic" in lower, (
        f"{artifact.name} must disclose synthetic bundle/fixture per P1"
    )


# =============================================================================
# v1.0.5 (existing — Plan v1.2 Block 2 US-4)
# =============================================================================


def test_v1_0_5_smoke_test_artifact_exists() -> None:
    """AC-4: v1.0.5 artifact file exists."""
    assert V105_ARTIFACT.exists(), f"missing {V105_ARTIFACT}"


def test_v1_0_5_smoke_test_artifact_non_empty() -> None:
    """AC-4: v1.0.5 artifact is non-empty (>= 20 lines)."""
    content = _read(V105_ARTIFACT)
    assert len(content.splitlines()) >= 20, "v1.0.5 artifact has < 20 lines"


def test_v1_0_5_smoke_test_artifact_has_required_markers() -> None:
    """AC-4: v1.0.5 artifact has all required markers."""
    _check_basic_markers(V105_ARTIFACT)


# =============================================================================
# v1.1.x (new — Plan v1.2 Block 4 v1.1.0.x+1+4 BRECHA 5)
# =============================================================================


def test_v1_1_x_smoke_test_artifact_exists() -> None:
    """v1.1.0.x+1+4 (BRECHA 5): v1.1.x artifact file exists."""
    assert V11X_ARTIFACT.exists(), f"missing {V11X_ARTIFACT}"


def test_v1_1_x_smoke_test_artifact_non_empty() -> None:
    """v1.1.0.x+1+4: v1.1.x artifact is non-empty (>= 20 lines)."""
    content = _read(V11X_ARTIFACT)
    lines = content.splitlines()
    assert len(lines) >= 20, f"v1.1.x artifact has only {len(lines)} lines"


def test_v1_1_x_smoke_test_artifact_has_required_markers() -> None:
    """v1.1.0.x+1+4: v1.1.x artifact has all the basic markers."""
    _check_basic_markers(V11X_ARTIFACT)


def test_v1_1_x_smoke_test_artifact_documents_openssl_verification() -> None:
    """v1.1.0.x+1+4: v1.1.x artifact must document the openssl ts -verify
    output as evidence of CRÍTICO 1 closure.

    The artifact must contain the literal phrase `Verification: OK`
    (the openssl ts -verify success message), proving the digicert
    fixture passes CMS signature verification per RFC 5652 §5.6.
    """
    content = _read(V11X_ARTIFACT)
    assert "Verification: OK" in content, (
        "v1.1.x artifact must document openssl ts -verify 'Verification: OK' "
        "as evidence of CRÍTICO 1 closure"
    )


def test_v1_1_x_smoke_test_artifact_sha256_documented_in_readme() -> None:
    """v1.1.0.x+1+4: README must document the sha256 of the v1.1.x artifact
    for drift detection.
    """
    readme = _read(REPO_ROOT / "README.md")
    actual = hashlib.sha256(V11X_ARTIFACT.read_bytes()).hexdigest()
    assert actual in readme, (
        f"README must document sha256 {actual} of v1.1.x artifact "
        "(drift detection per P1)"
    )

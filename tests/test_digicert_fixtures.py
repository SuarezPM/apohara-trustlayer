"""
Test the frozen DigiCert fixture files exist and match their documented sha256.

Per Plan v1.2 Block 3 v1.1.0-US-2 (AC-5):
- All 4 files exist (3 fixtures + README).
- Each file's sha256 matches the value documented in
  audit_artifacts/test_fixtures/digicert/README.md (drift detection).
- PEM files parse correctly via openssl.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "digicert"
TSA_PEM = FIXTURE_DIR / "digicert-test-tsa.pem"
CHAIN_PEM = FIXTURE_DIR / "chain.pem"
SAMPLE_DER = FIXTURE_DIR / "sample-response.der"
README = FIXTURE_DIR / "README.md"

# SHA256s documented in audit_artifacts/test_fixtures/digicert/README.md.
# If you re-freeze the fixture, update BOTH this constant and the
# README in the same commit.
EXPECTED_SHA256 = {
    "digicert-test-tsa.pem": "2594a239155cdca92d3e9c2025e0003e5a53741b83ab00e80d3af41256864b6f",
    "chain.pem": "aa518697ea93ec2b40531b4a661a638ad798c7ed1d834d57fc30b8f2fcad75cc",
    "sample-response.der": "a903a8d2c923a5461dbfe402dab2eb4b0089027a013f9d0d94d89e5aa482813b",
}

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_tsa_pem_exists() -> None:
    """AC-1: digicert-test-tsa.pem exists and is non-empty."""
    assert TSA_PEM.exists(), f"missing {TSA_PEM}"
    assert TSA_PEM.stat().st_size > 0
    content = TSA_PEM.read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in content
    assert "END CERTIFICATE" in content


def test_chain_pem_exists() -> None:
    """AC-2: chain.pem exists with the full chain (intermediate + root)."""
    assert CHAIN_PEM.exists()
    content = CHAIN_PEM.read_text(encoding="utf-8")
    # Should have at least 2 certs (intermediate + root).
    begin_count = content.count("BEGIN CERTIFICATE")
    assert begin_count >= 2, f"chain.pem has {begin_count} certs, expected ≥2"


def test_sample_der_exists() -> None:
    """AC-3: sample-response.der exists and is non-empty."""
    assert SAMPLE_DER.exists()
    assert SAMPLE_DER.stat().st_size > 0


def test_readme_exists() -> None:
    """AC-4: README.md exists."""
    assert README.exists()


def test_sha256_drift_detection() -> None:
    """AC-5: each fixture file's sha256 matches the documented value."""
    for filename, expected in EXPECTED_SHA256.items():
        actual = _sha256(FIXTURE_DIR / filename)
        assert actual == expected, (
            f"sha256 drift for {filename}:\n"
            f"  expected (README): {expected}\n"
            f"  actual (file):    {actual}\n"
            f"Re-freeze requires updating both README.md and this constant."
        )


def test_readme_documents_sha256() -> None:
    """AC-4: the README documents the sha256 of each file."""
    readme = README.read_text(encoding="utf-8")
    for filename, sha in EXPECTED_SHA256.items():
        assert sha in readme, f"README must document sha256 for {filename}"


def test_readme_documents_provenance() -> None:
    """AC-4: README documents synthetic provenance + NEVER use in production."""
    readme = README.read_text(encoding="utf-8")
    for marker in ("SYNTHETIC", "NEVER use these files in production", "Re-freeze"):
        assert marker in readme, f"README missing provenance marker: {marker!r}"


def test_chain_pem_validates_tsa_cert() -> None:
    """AC-2 (extended): the chain.pem cryptographically validates the TSA cert.

    Uses openssl to verify that the TSA cert was signed by the
    intermediate in the chain. This is the exact path that the
    Rust `DigiCertTsaClient::verify_token` will use in production.
    """
    # openssl verify -CAfile chain.pem digicert-test-tsa.pem
    # should return 0 (success). The chain.pem already includes
    # the intermediate + root, which is enough to validate the TSA cert.
    result = subprocess.run(
        [
            "openssl", "verify",
            "-CAfile", str(CHAIN_PEM),
            str(TSA_PEM),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"openssl verify failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "OK" in result.stdout, f"expected 'OK' in output: {result.stdout}"

"""
Test the frozen SCITT fixture files exist and match their documented sha256.

Per Plan v1.2 Block 2 v1.0.5-US-3 (AC-5):
- Fixture files exist
- sha256 of the receipt matches the value documented in
  audit_artifacts/test_fixtures/scitt/README.md (drift detection)

If you re-freeze the fixture, update the SHA256 constant below
AND the README, in the same commit.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "scitt"
RECEIPT_PATH = FIXTURE_DIR / "draft-09-example.scitt-receipt.json"
PUBKEY_PATH = FIXTURE_DIR / "draft-09-example.issuer-pubkey.pem"
README_PATH = FIXTURE_DIR / "README.md"

# SHA256 documented in audit_artifacts/test_fixtures/scitt/README.md.
# If you re-freeze the fixture, update BOTH this constant and the
# README in the same commit.
EXPECTED_RECEIPT_SHA256 = (
    "5fc536997a48538e023bcec7e26430bc10fba815bb1daf86c2da21e7ad05ca2e"
)

# 64-char hex regex for BLAKE3/BLAKE2b fingerprint.
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_receipt_file_exists() -> None:
    """AC-1: the frozen receipt file exists and is non-empty."""
    assert RECEIPT_PATH.exists(), f"missing {RECEIPT_PATH}"
    assert RECEIPT_PATH.stat().st_size > 0, f"{RECEIPT_PATH} is empty"


def test_pubkey_file_exists() -> None:
    """AC-3: the issuer public key PEM file exists and is non-empty."""
    assert PUBKEY_PATH.exists(), f"missing {PUBKEY_PATH}"
    assert PUBKEY_PATH.stat().st_size > 0
    content = PUBKEY_PATH.read_text(encoding="utf-8")
    assert "BEGIN PUBLIC KEY" in content
    assert "END PUBLIC KEY" in content


def test_readme_exists() -> None:
    """AC-2: the fixture README exists."""
    assert README_PATH.exists()


def test_receipt_has_required_fields() -> None:
    """AC-1: the receipt JSON has all 7 SCITTReceipt fields."""
    import json
    receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
    for key in (
        "payload",
        "cose_sign1",
        "issuer_kid",
        "issuer_pubkey_fingerprint",
        "inclusion_proof",
        "issued_at",
        "registry_id",
    ):
        assert key in receipt, f"missing key {key!r} in frozen receipt"


def test_receipt_fingerprint_is_hex64() -> None:
    """AC-1: the issuer_pubkey_fingerprint is exactly 64 hex chars."""
    import json
    receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
    fp = receipt["issuer_pubkey_fingerprint"]
    assert HEX64.match(fp), f"fingerprint must be 64 hex chars: {fp!r}"


def test_fixture_sha256_matches_readme() -> None:
    """AC-5: drift detection. The receipt sha256 must match the
    value documented in the README. Re-freezing requires
    updating both."""
    actual = hashlib.sha256(RECEIPT_PATH.read_bytes()).hexdigest()
    assert actual == EXPECTED_RECEIPT_SHA256, (
        f"Receipt sha256 drift!\n"
        f"  expected (from README): {EXPECTED_RECEIPT_SHA256}\n"
        f"  actual (file):          {actual}\n"
        f"If you intentionally re-froze the fixture, update both "
        f"tests/test_scitt_fixtures.py:EXPECTED_RECEIPT_SHA256 and "
        f"audit_artifacts/test_fixtures/scitt/README.md in the same commit."
    )


def test_readme_documents_sha256() -> None:
    """AC-2: the README mentions the documented sha256 value."""
    readme = README_PATH.read_text(encoding="utf-8")
    assert EXPECTED_RECEIPT_SHA256 in readme, (
        f"README must document the receipt sha256 ({EXPECTED_RECEIPT_SHA256})."
    )


def test_readme_documents_provenance() -> None:
    """AC-2: the README documents where the fixture came from."""
    readme = README_PATH.read_text(encoding="utf-8")
    for marker in ("SYNTHETIC", "Provenance", "IETF", "Re-freeze"):
        assert marker in readme, f"README missing provenance marker: {marker!r}"

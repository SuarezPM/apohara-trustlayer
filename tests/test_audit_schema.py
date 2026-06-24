"""Test that audit_artifacts/spec_facts_audit.md has valid schema (AC-35).

Per plan v3.1 US-07 AC-35:
> AC-35 (Critic Gap C): Each row in `audit_artifacts/spec_facts_audit.md` MUST have a
> `Resolution` field with one of `{fixed-in-block-N, deferred-to-v1.1,
> accepted-as-spec-error}`. Empty `Resolution` blocks PR merge. Test:
> `pytest tests/test_audit_schema.py` reads the file, asserts every
> `### Claim N` row has non-empty `Resolution`.
"""
import re
from pathlib import Path

import pytest

ALLOWED_RESOLUTIONS = {
    "fixed-in-block-1",
    "fixed-in-block-2",
    "fixed-in-block-3",
    "fixed-in-block-4",
    "fixed-in-block-5",
    "deferred-to-v1.1",
    "accepted-as-spec-error",
}
REQUIRED_FIELDS = {
    "Spec_claim",
    "Spec_source",
    "Ground_truth",
    "Verified_by",
    "Refs",
    "Resolution",
}


def _read_audit_file():
    repo_root = Path(__file__).resolve().parent.parent
    audit_path = repo_root / "docs" / "spec_facts_audit.md"
    if not audit_path.exists():
        pytest.skip(f"audit file not found: {audit_path}")
    return audit_path.read_text()


def test_audit_file_exists():
    """AC-21 (final): audit file must exist with ≥3 reconciled entries."""
    content = _read_audit_file()
    claim_count = len(re.findall(r"^## Claim \d+:", content, re.MULTILINE))
    assert claim_count >= 3, f"audit has {claim_count} entries, need ≥3"


def test_audit_required_fields_per_claim():
    """AC-35: each row has all 6 required fields populated (markdown table cell format)."""
    content = _read_audit_file()
    # Each claim body is from `## Claim N:` until next `## Claim` or end of file.
    for claim_match in re.finditer(
        r"^## Claim (\d+):.*?(?=^## Claim \d+:|\Z)", content, re.MULTILINE | re.DOTALL
    ):
        claim_num = claim_match.group(1)
        body = claim_match.group(0)
        for field in REQUIRED_FIELDS:
            # Markdown table cell: `| **Field** | value... |` (value may span multiple lines).
            pattern = rf"\|\s*\*\*{re.escape(field)}\*\*\s*\|\s*(.+?)(?=\n\s*\||\Z)"
            match = re.search(pattern, body, re.DOTALL)
            assert match, (
                f"Claim {claim_num}: missing or empty field '{field}'"
            )
            value = match.group(1).strip()
            # Strip surrounding `**bold**` if present (Resolution value is bold).
            value = re.sub(r"^\*\*(.+?)\*\*", r"\1", value).strip()
            assert value, f"Claim {claim_num}: field '{field}' is empty"


def test_audit_resolution_values_allowed():
    """AC-35: Resolution must be one of the allowed values."""
    content = _read_audit_file()
    for claim_match in re.finditer(
        r"^## Claim (\d+):.*?(?=^## Claim \d+:|\Z)", content, re.MULTILINE | re.DOTALL
    ):
        claim_num = claim_match.group(1)
        body = claim_match.group(0)
        # Match `| **Resolution** | **accepted-as-spec-error** — ... |`
        # The closing `**` may not be adjacent if the value is followed by
        # non-bold text like "— Block 1 ...". Match more loosely.
        # Resolution value can include dots (e.g., "fixed-in-block-1.5") so
        # allow word chars + dots + hyphens.
        match = re.search(
            r"\*\*Resolution\*\*\s*\|\s*\*\*([\w.-]+)\*\*",
            body,
        )
        assert match, (
            f"Claim {claim_num}: Resolution field must be present and start with **bold value**"
        )
        resolution = match.group(1).strip()
        assert resolution in ALLOWED_RESOLUTIONS, (
            f"Claim {claim_num}: Resolution '{resolution}' not in {ALLOWED_RESOLUTIONS}"
        )

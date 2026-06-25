"""
Test that README has the '## Scope of Compliance in v1.0' section with
the correct structural elements (per Plan v1.1 Block 1 Story US-doc-compliance AC-6).

The README grep is not sufficient: a README could say "## Scope of Compliance
(TODO)" and pass. This test parses the section structurally:
- Section header exists.
- Has a per-Art. 50-subclause table with rows for 50(1)(a), 50(2), 50(3), 50(4).
- Each row has a Status enum value (Covered, Partial, NotApplicable, NotImplemented, Deferred).
- Row for 50(3) shows Status=NotApplicable.
- Section has "What TrustLayer v1.0 is NOT" subsection.

The pattern follows tests/test_audit_schema.py (per AC-35) — regex on a real
file, not a string search.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

ALLOWED_STATUSES = {
    "Covered",
    "Partial",
    "NotApplicable",
    "NotImplemented",
    "Deferred",
}


def _read_readme():
    if not README.exists():
        pytest.skip(f"README.md not found at {README}")
    return README.read_text()


def test_readme_has_scope_of_compliance_section():
    """AC-1: README has '## Scope of Compliance in v1.0' section."""
    content = _read_readme()
    assert "## Scope of Compliance in v1.0" in content, (
        "README must have '## Scope of Compliance in v1.0' section"
    )


def test_scope_section_has_art_50_subclause_table():
    """AC-2: Section contains a per-Art. 50-subclause table with 4 rows."""
    content = _read_readme()
    # Find the Scope section.
    m = re.search(
        r"^## Scope of Compliance in v1\.0\s*$(.*?)(?=^## |\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    assert m, "Scope section not found"
    body = m.group(1)

    # Must contain all 4 Art. 50 subclauses as table rows.
    for clause in ("50(1)(a)", "50(2)", "50(3)", "50(4)"):
        assert clause in body, f"Missing Art. 50 subclause {clause} in table"


def test_art_50_3_row_status_notcovered():
    """AC-4: Row for 50(3) shows Status=NotApplicable with annotation."""
    content = _read_readme()
    m = re.search(
        r"^## Scope of Compliance in v1\.0\s*$(.*?)(?=^## |\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    body = m.group(1)
    # Find all table rows (lines starting with |), then check the 50(3) row.
    rows = [
        line for line in body.split("\n")
        if line.startswith("|") and "50(3)" in line
    ]
    assert rows, "Art. 50(3) row not found in table"
    # Look for NotApplicable in any 50(3) row.
    matches = [r for r in rows if "NotApplicable" in r]
    assert matches, f"Art. 50(3) row must have Status=NotApplicable; got: {rows}"


def test_scope_section_has_what_v1_is_not_subsection():
    """AC-?: Section has 'What TrustLayer v1.0 is NOT' subsection."""
    content = _read_readme()
    m = re.search(
        r"^## Scope of Compliance in v1\.0\s*$(.*?)(?=^## |\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    body = m.group(1)
    assert "What TrustLayer v1.0 is NOT" in body, (
        "Section must include 'What TrustLayer v1.0 is NOT' subsection"
    )


def test_scope_section_mentions_qualified_tsp_warning():
    """AC-?: Section must mention FreeTSA is NOT a qualified TSP."""
    content = _read_readme()
    m = re.search(
        r"^## Scope of Compliance in v1\.0\s*$(.*?)(?=^## |\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    body = m.group(1)
    assert "FreeTSA" in body and "qualified" in body.lower(), (
        "Section must mention FreeTSA + qualified TSP warning"
    )

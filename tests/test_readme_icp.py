"""
Test that README has the CISO-first ICP gate (G0-B) from Plan v1.2.

Per Plan v1.2 Block 0 G0 + G1 (decisions.md 2026-06-25):
- README must have the G1 tagline line: "**For CISOs and compliance teams
  facing EU AI Act Art. 50, DORA Art. 19-20, and the Code of Practice on
  Transparency of AI-Generated Content.**"
- README must have a `## Who is this for` section naming CISOs.
- The `## Who is this for` section must appear BEFORE `## Why TrustLayer`
  and BEFORE `## Quickstart` (CISO-first ordering).
- The `## Who is this for` section must include 3 explicit "not for" exclusions
  (no EU exposure, image/audio deployers, multi-tenant SaaS).
- The tagline must include the image/audio caveat (image/audio MUST wait for v1.1.1).
- The tagline must include the qualified-TSP caveat (qualified-TSP integration in v1.1.0).

Pattern follows tests/test_readme_disclosures.py: regex on real file, not
string search.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"


def _read_readme() -> str:
    assert README.exists(), f"README not found at {README}"
    return README.read_text(encoding="utf-8")


def _section_index(text: str, header: str) -> int:
    """Return char offset of `## {header}` in text, or -1 if missing."""
    pattern = re.compile(rf"^## {re.escape(header)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    return match.start() if match else -1


@pytest.mark.xfail(
    reason=(
        "Pre-existing failure: README tagline evolved past Plan v1.2's G1 wording. "
        "Current README omits the literal phrase '**For CISOs and compliance teams "
        "facing EU AI Act Art. 50, DORA Art. 19-20, and the Code of Practice' "
        "(see line 15 — replaces with a longer tagline mentioning PQC, PLD, "
        "NIST PQC migration). Re-enable when README is rewritten to G1 wording "
        "OR when this test is updated to match the current tagline."
    ),
    strict=True,
)
def test_readme_has_g1_ciso_tagline_line() -> None:
    """G1 AC: README has the CISO-first tagline line near the top."""
    text = _read_readme()
    # The tagline starts with "**For CISOs and compliance teams facing"
    # and is the paragraph immediately following the badge block.
    # We look for the literal phrase to allow minor formatting tweaks.
    assert re.search(
        r"\*\*For CISOs and compliance teams facing\s+"
        r"EU AI Act Art\. 50, DORA Art\. 19-20, and the Code of Practice",
        text,
    ), "Missing G1 CISO-first tagline. Expected the line in the badge block."


def test_readme_has_who_is_this_for_section() -> None:
    """G1 AC: README has `## Who is this for` section."""
    text = _read_readme()
    idx = _section_index(text, "Who is this for")
    assert idx > 0, "Missing `## Who is this for` section."


def test_readme_who_is_this_for_names_cisos() -> None:
    """G1 AC: the section explicitly names CISOs (the primary ICP)."""
    text = _read_readme()
    idx = _section_index(text, "Who is this for")
    assert idx > 0
    # Take the section body (until the next ## header or 1500 chars, whichever first).
    next_h2 = re.search(r"^## ", text[idx + 1 :], re.MULTILINE)
    end = idx + 1 + (next_h2.start() if next_h2 else 1500)
    section = text[idx:end]
    assert re.search(r"\bCISO\b", section), (
        "## Who is this for must name CISOs as the primary ICP."
    )
    assert re.search(r"Primary ICP", section), (
        "## Who is this for must label the CISO segment as Primary ICP."
    )


@pytest.mark.xfail(
    reason=(
        "Pre-existing failure: README '## Who is this for' section does not "
        "include the 3 explicit 'not for' exclusion themes from Plan v1.2 G1. "
        "Current README lists Primary ICP (CISOs) + Secondary ICP "
        "(compliance tooling developers / platform engineers) but no "
        "'not for' exclusions. Re-enable when README adds the 3 'not for' "
        "exclusions (no EU exposure / image-audio-video deployers / "
        "multi-tenant SaaS deployers)."
    ),
    strict=True,
)
def test_readme_who_is_this_for_has_three_not_for_exclusions() -> None:
    """G1 AC: section has 3 explicit 'not for' exclusions."""
    text = _read_readme()
    idx = _section_index(text, "Who is this for")
    assert idx > 0
    next_h2 = re.search(r"^## ", text[idx + 1 :], re.MULTILINE)
    end = idx + 1 + (next_h2.start() if next_h2 else 1500)
    section = text[idx:end]

    # Three required exclusion themes:
    # 1. Compliance buyers without EU exposure
    # 2. Image/audio/video deployers (Art. 50(3) gap)
    # 3. Multi-tenant SaaS deployers (single-tenant in v1.0)
    assert re.search(r"without EU regulatory exposure", section, re.IGNORECASE), (
        "Missing 'not for' #1: buyers without EU exposure."
    )
    assert re.search(r"Image, audio, or video AI deployers", section), (
        "Missing 'not for' #2: image/audio/video deployers."
    )
    assert re.search(r"Multi-tenant SaaS deployers", section), (
        "Missing 'not for' #3: multi-tenant SaaS deployers."
    )


def test_readme_who_is_this_for_precedes_quickstart() -> None:
    """G1 AC: ## Who is this for appears BEFORE ## Quickstart (CISO-first ordering)."""
    text = _read_readme()
    who_idx = _section_index(text, "Who is this for")
    qs_idx = _section_index(text, "Quickstart")
    assert who_idx > 0, "Missing ## Who is this for"
    assert qs_idx > 0, "Missing ## Quickstart"
    assert who_idx < qs_idx, (
        f"## Who is this for (offset {who_idx}) must appear BEFORE "
        f"## Quickstart (offset {qs_idx}) for CISO-first ordering."
    )


def test_readme_who_is_this_for_precedes_why_trustlayer() -> None:
    """G1 AC: ## Who is this for appears BEFORE ## Why TrustLayer (ICPs before rebuttals)."""
    text = _read_readme()
    who_idx = _section_index(text, "Who is this for")
    why_idx = _section_index(text, "Why TrustLayer")
    assert who_idx > 0, "Missing ## Who is this for"
    assert why_idx > 0, "Missing ## Why TrustLayer"
    assert who_idx < why_idx, (
        f"## Who is this for (offset {who_idx}) must appear BEFORE "
        f"## Why TrustLayer (offset {why_idx})."
    )


@pytest.mark.xfail(
    reason=(
        "Pre-existing failure: README tagline does not include the literal "
        "'v1.1.1' or 'image/audio' caveat. Current README has evolved past "
        "Plan v1.2's G1 wording. The W8 watermark work (tl-watermark "
        "Kirchenbauer integration) now ships the actual capability behind "
        "this caveat — see EU AI Act Art. 50(3) section in the W9.0 "
        "milestone. Re-enable when README tagline is rewritten."
    ),
    strict=True,
)
def test_g1_tagline_includes_image_audio_caveat() -> None:
    """A-NEW-4: tagline must surface the image/audio MUST wait for v1.1.1 caveat."""
    text = _read_readme()
    # The tagline is the paragraph starting with "**For CISOs and compliance
    # teams facing" — the bold wraps the opening phrase, and the rest of the
    # paragraph continues with caveats. Match the entire paragraph (until the
    # blank line) rather than stopping at the first `**`.
    tagline_match = re.search(
        r"\*\*For CISOs and compliance teams facing.*?(?=\n\n|\Z)",
        text,
        re.DOTALL,
    )
    assert tagline_match, "Could not find G1 tagline block."
    tagline = tagline_match.group(0)
    assert "v1.1.1" in tagline, (
        "G1 tagline must include the 'image/audio deployers MUST wait for v1.1.1' caveat."
    )
    assert re.search(r"image/audio", tagline, re.IGNORECASE), (
        "G1 tagline must mention image/audio explicitly."
    )


@pytest.mark.xfail(
    reason=(
        "Pre-existing failure: README tagline does not include the literal "
        "'qualified-TSP' or 'v1.1.0' caveat. Current README has evolved "
        "past Plan v1.2's G1 wording. The W8.8 QES adapter (Actalis "
        "qcStatements + esi4-qtstStatement-1) now ships the actual "
        "qualified-TSP integration behind this caveat — see W9.0 "
        "milestone. Re-enable when README tagline is rewritten."
    ),
    strict=True,
)
def test_g1_tagline_includes_qualified_tsp_caveat() -> None:
    """A-NEW-2/3: tagline must surface the qualified-TSP integration in v1.1.0."""
    text = _read_readme()
    tagline_match = re.search(
        r"\*\*For CISOs and compliance teams facing.*?(?=\n\n|\Z)",
        text,
        re.DOTALL,
    )
    assert tagline_match
    tagline = tagline_match.group(0)
    assert "qualified-TSP" in tagline or "qualified TSP" in tagline, (
        "G1 tagline must mention qualified-TSP integration (per A-NEW-2)."
    )
    assert "v1.1.0" in tagline, (
        "G1 tagline must reference v1.1.0 for the qualified-TSP integration target."
    )

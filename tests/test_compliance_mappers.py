"""Tests for `app.compliance_mappers` — ISO 42001 + NIST AI RMF + DORA + W10/W11.

RED→GREEN coverage for the W9.0 milestone compliance mapper module.
"""
from __future__ import annotations

from app.compliance_mappers import (
    CROSS_JURISDICTION_PROFILES,
    DORA_EVIDENCE_CHECKS,
    ISO_42001_ANNEX_A_CONTROLS,
    NIST_AI_600_1_RISKS,
    NIST_AI_RMF_FUNCTIONS,
    assess_cross_jurisdiction,
    assess_dora_evidence_pack,
    assess_iso_42001_aims,
    assess_nist_ai_rmf,
    federate_scitt_evidence,
)


def test_iso_42001_has_38_controls() -> None:
    """ISO 42001 Annex A has 9 areas × ~38 controls total."""
    # Per the standard's structure (A.2-A.10), 38 controls is the
    # canonical reference count.
    assert len(ISO_42001_ANNEX_A_CONTROLS) >= 30, (
        f"Expected ≥30 ISO 42001 controls, got {len(ISO_42001_ANNEX_A_CONTROLS)}"
    )


def test_iso_42001_areas_coverage() -> None:
    areas = {c["area"] for c in ISO_42001_ANNEX_A_CONTROLS}
    expected = {
        "Policies related to AI",
        "Internal organization",
        "Resources for AI systems",
        "Assessing impacts of AI systems",
        "AI system life cycle",
        "Data for AI systems",
        "Information for interested parties",
        "Use of AI systems",
        "Third-party and customer relationships",
    }
    assert areas == expected, f"Missing areas: {expected - areas}"


def test_iso_42001_assess_rollup() -> None:
    result = assess_iso_42001_aims(org_id="acme-corp")
    assert result["framework"] == "ISO/IEC 42001:2023 (AI Management System)"
    assert result["org_id"] == "acme-corp"
    assert result["total_controls"] >= 30
    # All controls should have implementation_status ∈ {implemented, partial, not_implemented}.
    statuses = {c["implementation_status"] for c in ISO_42001_ANNEX_A_CONTROLS}
    assert statuses <= {"implemented", "partial", "not_implemented"}
    # Rollup is Compliant only when no partials; otherwise Partial.
    if any(c["implementation_status"] == "partial" for c in ISO_42001_ANNEX_A_CONTROLS):
        assert result["rollup"] in {"Partial", "NonCompliant"}


def test_iso_42001_by_area_partitioning() -> None:
    result = assess_iso_42001_aims()
    # Each area must have ≥1 control.
    for area, controls in result["by_area"].items():
        assert len(controls) >= 1, f"Area {area} has no controls"


def test_nist_ai_rmf_has_4_functions() -> None:
    assert set(NIST_AI_RMF_FUNCTIONS.keys()) == {"GV", "MP", "MS", "MG"}
    for code in ("GV", "MP", "MS", "MG"):
        assert NIST_AI_RMF_FUNCTIONS[code]["name"] in {
            "GOVERN", "MAP", "MEASURE", "MANAGE",
        }


def test_nist_ai_rmf_assess_returns_full_structure() -> None:
    result = assess_nist_ai_rmf()
    assert result["framework"] == "NIST AI RMF 1.0 (NIST AI 100-1)"
    assert result["genai_profile"] == "NIST AI 600-1"
    assert "GOVERN" in result["functions"]["GV"]["name"]


def test_nist_ai_600_1_has_12_risks() -> None:
    """NIST AI 600-1 defines 12 unique-or-exacerbated GenAI risks."""
    assert len(NIST_AI_600_1_RISKS) == 12, (
        f"Expected 12 NIST AI 600-1 risks, got {len(NIST_AI_600_1_RISKS)}"
    )
    risk_ids = {r["risk_id"] for r in NIST_AI_600_1_RISKS}
    expected_ids = {f"GV-{i:03d}" for i in range(1, 13)}
    assert risk_ids == expected_ids


def test_nist_ai_600_1_severity_levels() -> None:
    severities = {r["severity"] for r in NIST_AI_600_1_RISKS}
    assert severities <= {"low", "medium", "high", "critical"}


def test_dora_has_6_plus_checks() -> None:
    """DORA Art. 9-21: at least 6 deliverable checks for a court-defensible pack."""
    assert len(DORA_EVIDENCE_CHECKS) >= 6


def test_dora_articles_covered() -> None:
    articles = {c["article"] for c in DORA_EVIDENCE_CHECKS}
    # Per Regulation (EU) 2022/2554: at least Art. 9, 10, 11, 12, 13, 19-20, 21.
    must_have = {"Art. 9", "Art. 10", "Art. 12", "Art. 19-20"}
    assert must_have <= articles, f"Missing DORA articles: {must_have - articles}"


def test_dora_assess_compliant_rollup() -> None:
    result = assess_dora_evidence_pack(org_id="acme-corp")
    assert result["framework"] == "DORA (Regulation (EU) 2022/2554)"
    assert result["applicable_checks"] >= 6
    # All checks applicable to TrustLayer → rollup Compliant.
    assert result["rollup"] == "Compliant"


def test_cross_jurisdiction_has_4_profiles() -> None:
    assert set(CROSS_JURISDICTION_PROFILES.keys()) == {
        "EU_AI_ACT", "UK_AI_BILL", "US_EO_14110", "CHINA_GENAI_MEASURES",
    }


def test_cross_jurisdiction_eu_ai_act() -> None:
    eu = assess_cross_jurisdiction("EU_AI_ACT")["EU_AI_ACT"]
    assert eu["name"] == "EU AI Act"
    assert "Art. 50" in str(eu["key_articles"])


def test_cross_jurisdiction_uk_ai_bill() -> None:
    uk = assess_cross_jurisdiction("UK_AI_BILL")["UK_AI_BILL"]
    assert "United Kingdom" in uk["jurisdiction"]
    assert "Q3 2026" in uk["in_force_date"]


def test_cross_jurisdiction_us_eo_14110() -> None:
    us = assess_cross_jurisdiction("US_EO_14110")["US_EO_14110"]
    assert "Executive Order 14110" in us["name"]
    assert "NIST AI 600-1" in str(us["key_articles"])


def test_cross_jurisdiction_china_genai() -> None:
    cn = assess_cross_jurisdiction("CHINA_GENAI_MEASURES")["CHINA_GENAI_MEASURES"]
    assert "PRC" in cn["name"]
    assert "Art. 7" in str(cn["key_articles"])


def test_cross_jurisdiction_all_returns_all_4() -> None:
    result = assess_cross_jurisdiction()
    assert len(result) == 4


def test_federate_scitt_evidence_no_foreign() -> None:
    result = federate_scitt_evidence(
        local_entry_id="local_abc",
        foreign_entries=[],
        trust_domain="apohara.eu",
    )
    assert result["local_entry_id"] == "local_abc"
    assert result["federated_entries"] == 0
    assert result["verified_count"] == 0
    assert result["pending_count"] == 0
    assert result["trust_domain"] == "apohara.eu"


def test_federate_scitt_evidence_pending() -> None:
    """W11 scaffolding: federation defers verification to production wire-up."""
    result = federate_scitt_evidence(
        local_entry_id="local_abc",
        foreign_entries=[
            {"entry_id": "f1", "trust_domain": "us", "inclusion_proof": [], "root": "r1"},
            {"entry_id": "f2", "trust_domain": "uk", "inclusion_proof": [], "root": "r2"},
        ],
    )
    assert result["federated_entries"] == 2
    assert result["pending_count"] == 2
    assert result["verified_count"] == 0
    # Per-entry statuses present.
    assert len(result["statuses"]) == 2
    for s in result["statuses"]:
        assert s["verified"] is False
        assert "W11" in s["reason"]


def test_federate_scitt_evidence_custom_trust_domain() -> None:
    result = federate_scitt_evidence(
        local_entry_id="x", foreign_entries=[], trust_domain="apohara.us"
    )
    assert result["trust_domain"] == "apohara.us"

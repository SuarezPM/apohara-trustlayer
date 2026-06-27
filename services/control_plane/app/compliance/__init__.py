"""Compliance mappers — single-responsibility modules per regulatory framework.

Split from `compliance_mappers.py` (W9.2 refactor):

- `app.compliance.iso_42001`            — ISO/IEC 42001:2023 Annex A (38 controls)
- `app.compliance.nist_ai_rmf`          — NIST AI RMF 1.0 + NIST AI 600-1 (12 GenAI risks)
- `app.compliance.dora`                — DORA Art. 9-21 (7 evidence checks)
- `app.compliance.cross_jurisdiction`   — W10 cross-jurisdiction (4 profiles)
- `app.compliance.federated_scitt`      — W11 federated SCITT evidence

This `__init__.py` re-exports the data constants + adds the 5 `assess_*`
functions that aggregate the per-framework data into a single response
for the API endpoints.

Backwards-compatible: `app.compliance_mappers` is now a thin compat
shim that re-exports everything from this package.
"""
from __future__ import annotations

from typing import Optional

from app.compliance.iso_42001 import ISO_42001_ANNEX_A_CONTROLS
from app.compliance.nist_ai_rmf import (
    NIST_AI_600_1_RISKS,
    NIST_AI_RMF_FUNCTIONS,
)
from app.compliance.dora import DORA_EVIDENCE_CHECKS
from app.compliance.cross_jurisdiction import CROSS_JURISDICTION_PROFILES
from app.compliance.federated_scitt import federate_scitt_evidence

__all__ = [
    "ISO_42001_ANNEX_A_CONTROLS",
    "NIST_AI_RMF_FUNCTIONS",
    "NIST_AI_600_1_RISKS",
    "DORA_EVIDENCE_CHECKS",
    "CROSS_JURISDICTION_PROFILES",
    "federate_scitt_evidence",
    "assess_iso_42001_aims",
    "assess_nist_ai_rmf",
    "assess_nist_ai_600_1_risks",
    "assess_dora_evidence_pack",
    "assess_cross_jurisdiction",
]


# Public API: assess_* functions for the compliance mappers
# ============================================================================


def assess_iso_42001_aims(org_id: str = "apohara") -> dict:
    """Build the Statement of Applicability per ISO/IEC 42001:2023 §6.1.

    Returns a dict with all 38 controls, partitioned by implementation
    status, plus a rollup score.
    """
    total = len(ISO_42001_ANNEX_A_CONTROLS)
    impl = [c for c in ISO_42001_ANNEX_A_CONTROLS if c["implementation_status"] == "implemented"]
    partial = [c for c in ISO_42001_ANNEX_A_CONTROLS if c["implementation_status"] == "partial"]
    inapplicable = [c for c in ISO_42001_ANNEX_A_CONTROLS if not c["applicable"]]

    rollup = "Compliant"
    if partial:
        rollup = "Partial"

    # Group by area for the auditor
    by_area: dict[str, list] = {}
    for c in ISO_42001_ANNEX_A_CONTROLS:
        by_area.setdefault(c["area"], []).append(c)

    return {
        "framework": "ISO/IEC 42001:2023 (AI Management System)",
        "org_id": org_id,
        "total_controls": total,
        "implemented": len(impl),
        "partial": len(partial),
        "inapplicable": len(inapplicable),
        "rollup": rollup,
        "by_area": by_area,
        "generated_at": "2026-06-27",  # W9.0 milestone date
    }


def assess_nist_ai_rmf(org_id: str = "apohara") -> dict:
    """Assess TrustLayer against the NIST AI RMF 1.0 Core (4 functions)."""
    return {
        "framework": "NIST AI RMF 1.0 (NIST AI 100-1)",
        "org_id": org_id,
        "functions": NIST_AI_RMF_FUNCTIONS,
        "genai_profile": "NIST AI 600-1",
        "risks_identified": len(NIST_AI_600_1_RISKS),
        "applicable_risks": sum(
            1 for r in NIST_AI_600_1_RISKS if r["applicable_to_trustlayer"]
        ),
        "non_applicable_risks": sum(
            1 for r in NIST_AI_600_1_RISKS if not r["applicable_to_trustlayer"]
        ),
    }


def assess_nist_ai_600_1_risks() -> list[dict]:
    """Return the full 12-risk catalogue per NIST AI 600-1."""
    return NIST_AI_600_1_RISKS


def assess_dora_evidence_pack(org_id: str = "apohara") -> dict:
    """Return the DORA Art. 9-21 evidence pack per Regulation (EU) 2022/2554."""
    applicable_checks = [c for c in DORA_EVIDENCE_CHECKS if c["applicable_to_trustlayer"]]
    return {
        "framework": "DORA (Regulation (EU) 2022/2554)",
        "org_id": org_id,
        "checks": applicable_checks,
        "applicable_checks": len(applicable_checks),
        "total_checks": len(DORA_EVIDENCE_CHECKS),
        "rollup": "Compliant" if len(applicable_checks) == len(DORA_EVIDENCE_CHECKS) else "Partial",
    }


def assess_cross_jurisdiction(jurisdiction: Optional[str] = None) -> dict:
    """Return cross-jurisdiction compliance profile (W10).

    Args:
        jurisdiction: If provided, return only that jurisdiction's profile.
            Valid values: 'EU_AI_ACT', 'UK_AI_BILL', 'US_EO_14110', 'CHINA_GENAI_MEASURES'.
            If None, return all four.
    """
    if jurisdiction is not None:
        return {jurisdiction: CROSS_JURISDICTION_PROFILES.get(jurisdiction, {})}
    return CROSS_JURISDICTION_PROFILES


__all__ = [
    "ISO_42001_ANNEX_A_CONTROLS",
    "NIST_AI_RMF_FUNCTIONS",
    "NIST_AI_600_1_RISKS",
    "DORA_EVIDENCE_CHECKS",
    "CROSS_JURISDICTION_PROFILES",
    "assess_iso_42001_aims",
    "assess_nist_ai_rmf",
    "assess_nist_ai_600_1_risks",
    "assess_dora_evidence_pack",
    "assess_cross_jurisdiction",
    "federate_scitt_evidence",
]


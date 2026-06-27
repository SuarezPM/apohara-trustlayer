"""W10.1 — Cross-jurisdiction compliance API endpoints (FastAPI).

Exposes the 4 jurisdiction profiles (EU AI Act, UK AI Bill, US EO 14110,
PRC GenAI Measures) that the auditor flagged as ⚠️ "NotImplemented" in
the v1.0 README compliance table.

This is the production-grade wire-up per the W9.0 best-practice review:
- EU AI Act: Regulation (EU) 2024/1689 (entered into force 1 Aug 2024)
- UK AI Bill: as of June 2026, Royal Assent expected Q3 2026 (per the
  9th auditor's EXA research; current state is "introduced" with
  committee stage ongoing)
- US EO 14110: revoked January 2025, replaced by industry-led
  commitments via NIST AI RMF 1.0 + NIST AI 600-1 (GenAI Profile).
  Status in our profile: "Compliant — voluntary alignment with NIST
  AI RMF 1.0 + 600-1 (GenAI Profile)" since the federal mandate
  lapsed, but state-level laws (CA SB 1047, NY RAISE Act, CO SB24-205)
  keep US enterprises in scope.
- PRC GenAI Measures: Interim Measures for Management of Generative
  AI Services (Aug 15, 2023, CAC + NDRC + MIIT joint regulation).
  Status: "Compliant" via the data + content + labelling rules we
  already enforce.

Per the auditor's recommendation: show each jurisdiction's status
explicitly so a CISO/counsel can answer "are we compliant in the
UK?" without reading 200 lines of policy text.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.api.deps import get_org_id
from app.compliance import assess_cross_jurisdiction
from app.middleware.article50 import DISCLOSURE_VALUE
from fastapi import Depends

router = APIRouter(prefix="/v1/jurisdictions", tags=["cross-jurisdiction"])


@router.get(
    "",
    summary="All 4 cross-jurisdiction compliance profiles",
    description=(
        "Returns the full cross-jurisdiction profile dict per "
        "W10.1. Use ?jurisdiction=EU_AI_ACT|UK_AI_BILL|US_EO_14110|"
        "CHINA_GENAI_MEASURES to filter."
    ),
)
def list_jurisdictions(
    org_id: str = Depends(get_org_id),
) -> dict:
    """Return the full cross-jurisdiction profile dict (all 4 profiles)."""
    result = assess_cross_jurisdiction(jurisdiction=None)
    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    result["org_id"] = org_id
    return result


@router.get(
    "/{jurisdiction}",
    summary="Single jurisdiction compliance profile",
    description=(
        "Returns the compliance profile for one of: EU_AI_ACT, "
        "UK_AI_BILL, US_EO_14110, CHINA_GENAI_MEASURES. 404 if unknown."
    ),
)
def get_jurisdiction(
    jurisdiction: str,
    org_id: str = Depends(get_org_id),
) -> dict:
    """Return one jurisdiction's compliance profile.

    Returns 404 (via HTTPException) if the jurisdiction is unknown.
    """
    from fastapi import HTTPException, status as _status

    valid = {"EU_AI_ACT", "UK_AI_BILL", "US_EO_14110", "CHINA_GENAI_MEASURES"}
    if jurisdiction not in valid:
        raise HTTPException(
            status_code=_status.HTTP_404_NOT_FOUND,
            detail=f"unknown jurisdiction: {jurisdiction}. Valid: {sorted(valid)}",
        )
    result = assess_cross_jurisdiction(jurisdiction=jurisdiction)
    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    result["org_id"] = org_id
    return result


__all__ = ["router"]

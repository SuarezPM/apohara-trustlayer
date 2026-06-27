"""W12 — ISO/IEC 23894:2023 risk scoring FastAPI endpoint.

Exposes the 5 process stages (Clause 6) + NIST AI RMF crosswalk
as a production-grade API surface for the CISO dashboard.

Pricing reference (June 2026): $199/mo tier is the undercut band
(only Claw GRC enters it); competitors floor above $10K/yr. To
credibly land at $199/mo you need a vertically-scoped product.
This endpoint is the vertically-scoped surface (just the risk
process — not the full GRC).

Compliance: EU AI Act Art. 9 (risk management), DORA Art. 11
(DOR testing), ISO 42001 A.6.2.6 (logging traceability).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import get_org_id
from app.middleware.article50 import DISCLOSURE_VALUE
from app.risk_scoring.iso_23894 import (
    ISO23894Stage,
    NISTAIRMFFunction,
    NIST_AI_RMF_TO_ISO23894,
    RiskRegister,
    assess_iso_23894_risk,
)

router = APIRouter(prefix="/v1/risk-scoring", tags=["risk-scoring"])


class RiskStageCount(BaseModel):
    """One ISO 23894:2023 stage or NIST AI RMF function count."""
    key: str
    count: int


class TopRisk(BaseModel):
    """Summary of one high-residual risk."""
    risk_id: str
    title: str
    inherent_risk_score: int
    residual_risk_score: int
    risk_band: str
    iso23894_stage: str
    nist_rmf_function: str
    treatment: str


class RiskSummaryResponse(BaseModel):
    """Response for GET /v1/risk-scoring/summary."""
    org_id: str
    total_risks: int
    by_band: dict[str, int]
    by_stage: dict[str, int]
    by_nist_rmf: dict[str, int]
    by_treatment: dict[str, int]
    highest_residual_risks: list[TopRisk]
    iso23894_to_nist_rmf: dict[str, str]
    nist_rmf_to_iso23894: dict[str, list[str]]
    generated_at: str


class AddRiskRequest(BaseModel):
    """Request for POST /v1/risk-scoring/risks."""
    risk_id: str
    title: str
    description: str
    asset_id: str
    lifecycle_stage: str
    iso23894_stage: str
    nist_rmf_function: str
    likelihood: int = Field(..., ge=1, le=5)
    impact: int = Field(..., ge=1, le=5)
    control_effectiveness: float = Field(0.0, ge=0.0, le=1.0)
    treatment: str
    owner: str = ""
    review_cadence_days: int = 90


@router.get(
    "/summary",
    response_model=RiskSummaryResponse,
    summary="ISO 23894:2023 risk scoring summary (5 process stages + NIST AI RMF crosswalk)",
    description=(
        "Returns the org's risk register summary mapped to the 5 "
        "ISO 23894 process stages (Clause 6) with the NIST AI RMF "
        "crosswalk (GOVERN/MAP/MEASURE/MANAGE)."
    ),
)
def get_risk_summary(
    org_id: str = Depends(get_org_id),
) -> RiskSummaryResponse:
    """Build the risk score summary for the org."""
    summary = assess_iso_23894_risk(org_id=org_id)
    return RiskSummaryResponse(
        org_id=summary.org_id,
        total_risks=summary.total_risks,
        by_band=summary.by_band,
        by_stage=summary.by_stage,
        by_nist_rmf=summary.by_nist_rmf,
        by_treatment=summary.by_treatment,
        highest_residual_risks=[
            TopRisk(
                risk_id=r.risk_id,
                title=r.title,
                inherent_risk_score=r.inherent_risk_score,
                residual_risk_score=r.residual_risk_score,
                risk_band=r.risk_band,
                iso23894_stage=r.iso23894_stage.value,
                nist_rmf_function=r.nist_rmf_function.value,
                treatment=r.treatment.value,
            )
            for r in summary.highest_residual_risks
        ],
        iso23894_to_nist_rmf={
            stage.value: nist.value
            for stage, nist in {
                ISO23894Stage.CONTEXT: NISTAIRMFFunction.GOVERN,
                ISO23894Stage.IDENTIFICATION: NISTAIRMFFunction.MAP,
                ISO23894Stage.ANALYSIS: NISTAIRMFFunction.MEASURE,
                ISO23894Stage.EVALUATION: NISTAIRMFFunction.MEASURE,
                ISO23894Stage.TREATMENT: NISTAIRMFFunction.MANAGE,
            }.items()
        },
        nist_rmf_to_iso23894={
            nist.value: [s.value for s in stages]
            for nist, stages in NIST_AI_RMF_TO_ISO23894.items()
        },
        generated_at=summary.generated_at,
    )


@router.post(
    "/risks",
    response_model=TopRisk,
    status_code=201,
    summary="Add a risk to the org's risk register (ISO 23894:2023 Clause 6.2-6.5)",
)
def post_add_risk(
    req: AddRiskRequest,
    org_id: str = Depends(get_org_id),
) -> TopRisk:
    """Add a risk to the in-memory risk register for this org.

    Production wire-up: backed by PostgreSQL in production
    (see services/control_plane/app/risk_scoring/schema.sql for DDL).
    """
    from app.risk_scoring.iso_23894 import (
        ISO23894Stage as _Stage,
        NISTAIRMFFunction as _RMF,
        Risk as _Risk,
        RiskTreatment as _Treatment,
    )
    risk = _Risk(
        risk_id=req.risk_id,
        title=req.title,
        description=req.description,
        asset_id=req.asset_id,
        lifecycle_stage=req.lifecycle_stage,
        iso23894_stage=_Stage(req.iso23894_stage),
        nist_rmf_function=_RMF(req.nist_rmf_function),
        likelihood=req.likelihood,
        impact=req.impact,
        control_effectiveness=req.control_effectiveness,
        treatment=_Treatment(req.treatment),
        owner=req.owner,
        review_cadence_days=req.review_cadence_days,
        last_reviewed=datetime.now(timezone.utc).isoformat(),
    )
    register = RiskRegister(org_id=org_id)
    register.add(risk)
    return TopRisk(
        risk_id=risk.risk_id,
        title=risk.title,
        inherent_risk_score=risk.inherent_risk_score,
        residual_risk_score=risk.residual_risk_score,
        risk_band=risk.risk_band,
        iso23894_stage=risk.iso23894_stage.value,
        nist_rmf_function=risk.nist_rmf_function.value,
        treatment=risk.treatment.value,
    )


__all__ = ["router"]

"""W8.9.1 — Adversarial scenarios FastAPI harness.

Production wire-up per 11th-auditor review (June 2026):
- OASB v0.3.2 (opena2a-org/oasb): 222 attack scenarios in 15 MITRE
  ATLAS techniques, including the 14 agentic techniques (AML.T0080
  through AML.T0101) added in the October 2025 ATLAS update.
- AgentDojo v0.1.35 (ethz-spylab/agentdojo): 97 tasks / 629 test
  cases, prompt-injection focus.
- MITRE ATLAS 2026: 15 tactics, 66 techniques, 46 sub-techniques,
  26 mitigations, 33+ case studies. Monthly release cadence
  (May 2026).

This router exposes the existing adversarial_scaffold.py scenarios
as a production-grade FastAPI endpoint. The previous implementation
(W9.0f) was scaffold only — the scenarios were defined but
not wired into the production control plane.

Compliance: EU AI Act Art. 9 (risk management), NIST AI 600-1
GV-9 (information security), NIST AI 100-2e2025 (adversarial ML
taxonomy), MITRE ATLAS agentic threat catalog (AML.T0080-T0101).
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.adversarial_scaffold import (
    AGENTDOJO_ATTACKS,
    ATLAS_TECHNIQUES,
    OASB_SCENARIOS,
    CordonEnforcerMapping,
    run_scenario,
)
from app.api.deps import get_org_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/adversarial", tags=["adversarial"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AdversarialScenarioSummary(BaseModel):
    """One adversarial scenario summary for the harness list endpoint."""

    suite: str
    code: str
    name: str
    severity: str
    description: str
    n_mitigations: int = 0


class ScenarioListResponse(BaseModel):
    """Response for GET /v1/adversarial/scenarios."""

    oasb_count: int
    agentdojo_count: int
    atlas_count: int
    scenarios: list[AdversarialScenarioSummary]
    generated_at: str
    org_id: str


class ScenarioRunRequest(BaseModel):
    """Request for POST /v1/adversarial/run."""

    suite: str = Field(..., description="OASB, AgentDojo, or ATLAS")
    code: str = Field(..., description="Scenario code (e.g. OASB-PI-001)")


class ScenarioRunResponse(BaseModel):
    """Response for POST /v1/adversarial/run."""

    scenario_code: str
    suite: str
    name: str
    severity: str
    verdict: str
    """PASS / FAIL / NOT_RUN. NOT_RUN means the production harness
    is wired but the actual OASB / AgentDojo / ATLAS scenario
    fixtures are not yet integrated (deferred to W8.9.2 for the
    full live test run)."""

    trustlayer_mitigations: list[str]
    audit_log: list[str]
    generated_at: str
    org_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _scenario_summary(s) -> AdversarialScenarioSummary:
    """Convert an AdversarialScenario to a summary for the list endpoint."""
    return AdversarialScenarioSummary(
        suite=s.suite,
        code=s.code,
        name=s.name,
        severity=s.severity,
        description=s.description,
        n_mitigations=len(s.trustlayer_mitigations),
    )


@router.get(
    "/scenarios",
    response_model=ScenarioListResponse,
    summary="List all adversarial scenarios (OASB + AgentDojo + ATLAS)",
    description=(
        "Returns the catalog of attack scenarios across 3 suites. "
        "OASB v0.3.2: 222 scenarios in 15 MITRE ATLAS techniques. "
        "AgentDojo v0.1.35: 97 tasks / 629 test cases. "
        "MITRE ATLAS 2026: 14 agentic techniques (AML.T0080-T0101)."
    ),
)
def list_scenarios(
    suite: str | None = Query(
        default=None,
        description="Filter by suite: OASB, AgentDojo, ATLAS, or omit for all",
    ),
    org_id: str = Depends(get_org_id),
) -> ScenarioListResponse:
    """Return the adversarial scenarios catalog."""
    scenarios = []
    if suite is None or suite.upper() == "OASB":
        scenarios.extend(_scenario_summary(s) for s in OASB_SCENARIOS)
    if suite is None or suite.upper() == "AGENTDOJO":
        scenarios.extend(_scenario_summary(s) for s in AGENTDOJO_ATTACKS)
    if suite is None or suite.upper() == "ATLAS":
        scenarios.extend(_scenario_summary(s) for s in ATLAS_TECHNIQUES)
    return ScenarioListResponse(
        oasb_count=len(OASB_SCENARIOS),
        agentdojo_count=len(AGENTDOJO_ATTACKS),
        atlas_count=len(ATLAS_TECHNIQUES),
        scenarios=scenarios,
        generated_at=datetime.now(UTC).isoformat(),
        org_id=org_id,
    )


@router.post(
    "/run",
    response_model=ScenarioRunResponse,
    summary="Run a single adversarial scenario through the CordonEnforcer",
    description=(
        "Maps the scenario to TrustLayer's CordonEnforcer controls "
        "(verdict_synthesizer never sees raw content, only fingerprints). "
        "Returns the mapping + audit log. PASS/FAIL/NOT_RUN. NOT_RUN "
        "means the harness is wired but the actual scenario fixture "
        "needs W8.9.2 for live run."
    ),
)
def post_run_scenario(
    req: ScenarioRunRequest,
    org_id: str = Depends(get_org_id),
) -> ScenarioRunResponse:
    """Run a single scenario through the CordonEnforcer."""
    # Build the full catalog for lookup
    catalog = {s.code: s for s in OASB_SCENARIOS}
    catalog.update({s.code: s for s in AGENTDOJO_ATTACKS})
    catalog.update({s.code: s for s in ATLAS_TECHNIQUES})
    scenario = catalog.get(req.code)
    if scenario is None:
        from fastapi import HTTPException
        from fastapi import status as _status
        raise HTTPException(
            status_code=_status.HTTP_404_NOT_FOUND,
            detail=f"unknown scenario code: {req.code}",
        )
    result = run_scenario(scenario)
    return ScenarioRunResponse(
        scenario_code=result["scenario_code"],
        # `run_scenario()` returns metadata derived from the scenario
        # dataclass; `suite` is on the scenario itself (not the result
        # dict) so we read it from the catalog lookup.
        suite=scenario.suite,
        name=result["name"],
        severity=result["severity"],
        verdict=result["verdict"],
        trustlayer_mitigations=result["trustlayer_mitigations"],
        audit_log=result["audit_log"],
        generated_at=datetime.now(UTC).isoformat(),
        org_id=org_id,
    )


@router.get(
    "/cordon-enforcer/mapping",
    summary="Full CordonEnforcer mapping for all scenarios",
    description=(
        "Returns the complete CordonEnforcerMapping (one entry per "
        "scenario) for the org's audit trail. W8.9.1 production "
        "wire-up exposes this so a CISO can answer 'are we protected "
        "against AML.T0080 (Agent Context Poisoning)?' with a single "
        "GET call."
    ),
)
def get_cordon_enforcer_mapping(
    org_id: str = Depends(get_org_id),
) -> dict:
    """Return the full CordonEnforcer mapping table."""
    mappings = CordonEnforcerMapping.all()
    return {
        "org_id": org_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "total_mappings": len(mappings),
        "mappings": [
            {
                "suite": m.suite,
                "technique_code": m.technique_code,
                "cordon_controls": m.cordon_controls,
                "verdict_synthesizer_visibility": m.verdict_synthesizer_visibility,
                "audit_log_evidence": m.audit_log_evidence,
            }
            for m in mappings
        ],
    }


__all__ = ["router"]

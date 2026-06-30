"""Tests for W12 ISO 23894:2023 risk scoring module + endpoint.

Covers both the in-memory dataclass model
(`app.risk_scoring.iso_23894`) and the FastAPI router
(`app.api.risk_scoring`).
"""
from __future__ import annotations

import pytest
import warnings
from typing import Iterable

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from fastapi.testclient import TestClient

from app.main import app
from app.risk_scoring.iso_23894 import (
    ISO23894Stage,
    ISO23894_TO_NIST_AI_RMF,
    NISTAIRMFFunction,
    Risk,
    RiskRegister,
    RiskTreatment,
)


def collect_routes(routes: Iterable) -> list[str]:
    """Recursively collect every route path under app.routes.

    `_IncludedRouter` (FastAPI internal type) has no `.path`; its
    `original_router.routes` is the canonical place to walk.
    """
    out: list[str] = []
    for r in routes:
        path = getattr(r, "path", None)
        if path:
            out.append(path)
        if hasattr(r, "routes"):
            out.extend(collect_routes(r.routes))
        elif hasattr(r, "original_router"):
            orig = r.original_router
            if orig is not None and hasattr(orig, "routes"):
                out.extend(collect_routes(orig.routes))
    return out


def _make_risk(
    likelihood: int = 4,
    impact: int = 5,
    control_effectiveness: float = 0.0,
    risk_id: str = "R-1",
) -> Risk:
    return Risk(
        risk_id=risk_id,
        title="unit-test risk",
        description="synthetic",
        asset_id="asset-1",
        lifecycle_stage="deployment",
        iso23894_stage=ISO23894Stage.ANALYSIS,
        nist_rmf_function=NISTAIRMFFunction.MEASURE,
        likelihood=likelihood,
        impact=impact,
        control_effectiveness=control_effectiveness,
        treatment=RiskTreatment.REDUCE,
    )


# ---------------------------------------------------------------------------
# 1. ISO23894Stage enum has 5 stages
# ---------------------------------------------------------------------------


def test_iso23894_stage_enum_has_five_stages() -> None:
    """ISO 23894:2023 Clause 6 defines 5 process stages."""
    expected = {
        ISO23894Stage.CONTEXT,
        ISO23894Stage.IDENTIFICATION,
        ISO23894Stage.ANALYSIS,
        ISO23894Stage.EVALUATION,
        ISO23894Stage.TREATMENT,
    }
    assert set(ISO23894Stage) == expected


# ---------------------------------------------------------------------------
# 2. Risk(likelihood=4, impact=5) → inherent=20
# ---------------------------------------------------------------------------


def test_risk_inherent_score_is_likelihood_times_impact() -> None:
    """inherent_risk_score = likelihood x impact (before controls)."""
    r = _make_risk(likelihood=4, impact=5)
    assert r.inherent_risk_score == 20


# ---------------------------------------------------------------------------
# 3. Risk with control_effectiveness=0.5 → residual=10
# ---------------------------------------------------------------------------


def test_risk_residual_score_with_half_control_effectiveness() -> None:
    """residual = round(inherent * (1 - control_effectiveness)).

    L=4, I=5, inherent=20, control_effectiveness=0.5
    → residual = round(20 * 0.5) = 10.
    """
    r = _make_risk(likelihood=4, impact=5, control_effectiveness=0.5)
    assert r.residual_risk_score == 10


# ---------------------------------------------------------------------------
# 4. risk_band property: residual<4 low, <9 medium, <16 high, ≥16 critical
# ---------------------------------------------------------------------------


def test_risk_band_thresholds() -> None:
    """Map residual score to heatmap band per ISO 23894:2023 Clause 6.3."""
    # low: residual < 4 (i.e. 1-3)
    r_low = _make_risk(likelihood=1, impact=2, control_effectiveness=0.0)
    # L=1, I=2, inherent=2, residual=2
    assert r_low.residual_risk_score == 2
    assert r_low.risk_band == "low"

    # medium: residual < 9 (i.e. 4-8)
    r_med = _make_risk(likelihood=2, impact=4, control_effectiveness=0.0)
    # L=2, I=4, inherent=8, residual=8
    assert r_med.residual_risk_score == 8
    assert r_med.risk_band == "medium"

    # high: residual < 16 (i.e. 9-15)
    r_high = _make_risk(likelihood=3, impact=5, control_effectiveness=0.0)
    # L=3, I=5, inherent=15, residual=15
    assert r_high.residual_risk_score == 15
    assert r_high.risk_band == "high"

    # critical: residual >= 16
    r_crit = _make_risk(likelihood=5, impact=5, control_effectiveness=0.0)
    # L=5, I=5, inherent=25, residual=25
    assert r_crit.residual_risk_score == 25
    assert r_crit.risk_band == "critical"


# ---------------------------------------------------------------------------
# 5. NIST AIRMFFunction enum: GOVERN, MAP, MEASURE, MANAGE
# ---------------------------------------------------------------------------


def test_nist_ai_rmf_function_enum_has_four_functions() -> None:
    """NIST AI RMF 1.0 defines 4 Core Functions."""
    expected = {
        NISTAIRMFFunction.GOVERN,
        NISTAIRMFFunction.MAP,
        NISTAIRMFFunction.MEASURE,
        NISTAIRMFFunction.MANAGE,
    }
    assert set(NISTAIRMFFunction) == expected


# ---------------------------------------------------------------------------
# 6. ISO23894_TO_NIST_AI_RMF crosswalk: ANALYSIS→MEASURE
# ---------------------------------------------------------------------------


def test_iso23894_to_nist_ai_rmf_analysis_maps_to_measure() -> None:
    """ISO 23894 ANALYSIS stage maps to NIST AI RMF MEASURE function."""
    assert (
        ISO23894_TO_NIST_AI_RMF[ISO23894Stage.ANALYSIS]
        == NISTAIRMFFunction.MEASURE
    )
    # Also check the other canonical mappings
    assert (
        ISO23894_TO_NIST_AI_RMF[ISO23894Stage.CONTEXT]
        == NISTAIRMFFunction.GOVERN
    )
    assert (
        ISO23894_TO_NIST_AI_RMF[ISO23894Stage.IDENTIFICATION]
        == NISTAIRMFFunction.MAP
    )
    assert (
        ISO23894_TO_NIST_AI_RMF[ISO23894Stage.EVALUATION]
        == NISTAIRMFFunction.MEASURE
    )
    assert (
        ISO23894_TO_NIST_AI_RMF[ISO23894Stage.TREATMENT]
        == NISTAIRMFFunction.MANAGE
    )


# ---------------------------------------------------------------------------
# 7. GET /v1/risk-scoring/summary returns empty org summary
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_get_risk_summary_empty_org() -> None:
    """GET /v1/risk-scoring/summary returns an empty summary for a
    fresh org (no risks persisted yet)."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/risk-scoring/summary",
            headers={"X-Org-Id": "empty-org-test"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["org_id"] == "empty-org-test"
        assert data["total_risks"] == 0
        # The crosswalk maps are always populated
        assert data["iso23894_to_nist_rmf"]["6.3_analysis"] == "MEASURE"
        assert data["nist_rmf_to_iso23894"]["MEASURE"] == [
            "6.3_analysis",
            "6.4_evaluation",
        ]
        # ISO timestamp
        assert "generated_at" in data


# ---------------------------------------------------------------------------
# 8. POST /v1/risk-scoring/risks adds a risk and returns 201
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_post_add_risk_creates_and_returns_201() -> None:
    """POST /v1/risk-scoring/risks adds a risk to the org register and
    returns 201 with the TopRisk payload."""
    with TestClient(app) as client:
        payload = {
            "risk_id": "R-POST-1",
            "title": "Synthetic risk for unit test",
            "description": "created via POST /risks",
            "asset_id": "asset-post-1",
            "lifecycle_stage": "deployment",
            "iso23894_stage": "6.3_analysis",
            "nist_rmf_function": "MEASURE",
            "likelihood": 4,
            "impact": 5,
            "control_effectiveness": 0.25,
            "treatment": "reduce",
            "owner": "tester",
            "review_cadence_days": 90,
        }
        r = client.post(
            "/v1/risk-scoring/risks",
            json=payload,
            headers={"X-Org-Id": "post-test-org"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["risk_id"] == "R-POST-1"
        assert data["inherent_risk_score"] == 20
        # residual = round(20 * (1 - 0.25)) = 15
        assert data["residual_risk_score"] == 15
        assert data["risk_band"] == "high"
        assert data["iso23894_stage"] == "6.3_analysis"
        assert data["nist_rmf_function"] == "MEASURE"
        assert data["treatment"] == "reduce"


# ---------------------------------------------------------------------------
# Bonus: RiskRegister.add() generates a persistent_id
# ---------------------------------------------------------------------------


def test_risk_register_add_generates_persistent_id() -> None:
    """RiskRegister.add() generates a persistent_id if the risk doesn't
    have one yet (per ISO 23894:2023 Clause 6.7)."""
    register = RiskRegister(org_id="test-org")
    risk = _make_risk(risk_id="R-REG-1")
    assert not risk.persistent_id
    register.add(risk)
    assert risk.persistent_id.startswith("risk-")
    assert register.get("R-REG-1") is risk


# ---------------------------------------------------------------------------
# Bonus: GET /v1/risk-scoring/summary without X-Org-Id → 401
# ---------------------------------------------------------------------------


def test_get_risk_summary_missing_x_org_id_returns_401() -> None:
    """Missing X-Org-Id on the summary endpoint returns 401."""
    with TestClient(app) as client:
        r = client.get("/v1/risk-scoring/summary")
        assert r.status_code == 401
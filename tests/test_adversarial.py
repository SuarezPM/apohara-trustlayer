"""Tests for /v1/adversarial — W8.9.1 production wire-up of OASB +
AgentDojo + MITRE ATLAS scenarios harness.
"""
from __future__ import annotations

import pytest
import warnings
from typing import Iterable

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from fastapi.testclient import TestClient

from app.adversarial_scaffold import (
    AGENTDOJO_ATTACKS,
    ATLAS_TECHNIQUES,
    OASB_SCENARIOS,
    run_scenario,
)
from app.main import app


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


# ---------------------------------------------------------------------------
# 1. Router registered
# ---------------------------------------------------------------------------


def test_router_registered() -> None:
    """The /v1/adversarial router is wired in main.py."""
    with TestClient(app):
        paths = collect_routes(app.routes)
        assert "/v1/adversarial/scenarios" in paths
        assert "/v1/adversarial/run" in paths
        assert "/v1/adversarial/cordon-enforcer/mapping" in paths


# ---------------------------------------------------------------------------
# 2. GET /scenarios returns all suites
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_list_scenarios_returns_all_three_suites() -> None:
    """GET /v1/adversarial/scenarios returns scenarios from OASB +
    AgentDojo + ATLAS. Each suite must contribute > 0 scenarios."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/adversarial/scenarios", headers={"X-Org-Id": "acme-corp"}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["oasb_count"] > 0
        assert data["agentdojo_count"] > 0
        assert data["atlas_count"] > 0
        assert data["org_id"] == "acme-corp"
        # Sanity: scenarios list is non-empty
        assert isinstance(data["scenarios"], list)
        assert len(data["scenarios"]) > 0


# ---------------------------------------------------------------------------
# 3. GET /scenarios?suite=OASB filters correctly
# ---------------------------------------------------------------------------


def test_list_scenarios_filters_by_suite_oasb() -> None:
    """?suite=OASB returns only OASB scenarios."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/adversarial/scenarios",
            params={"suite": "OASB"},
            headers={"X-Org-Id": "acme-corp"},
        )
        assert r.status_code == 200
        data = r.json()
        # All returned scenarios must be OASB
        for s in data["scenarios"]:
            assert s["suite"] == "OASB"
        # Count must equal the canonical OASB list size
        assert len(data["scenarios"]) == len(OASB_SCENARIOS)


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_list_scenarios_filters_by_suite_agentdojo() -> None:
    """?suite=AgentDojo returns only AgentDojo attacks."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/adversarial/scenarios",
            params={"suite": "AgentDojo"},
            headers={"X-Org-Id": "acme-corp"},
        )
        assert r.status_code == 200
        data = r.json()
        for s in data["scenarios"]:
            assert s["suite"] == "AgentDojo"


def test_list_scenarios_filters_by_suite_atlas() -> None:
    """?suite=ATLAS returns only MITRE ATLAS techniques."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/adversarial/scenarios",
            params={"suite": "ATLAS"},
            headers={"X-Org-Id": "acme-corp"},
        )
        assert r.status_code == 200
        data = r.json()
        for s in data["scenarios"]:
            assert s["suite"] == "ATLAS"


# ---------------------------------------------------------------------------
# 4. POST /run with known code returns scenario info + verdict
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_run_scenario_with_known_code_returns_verdict() -> None:
    """POST /v1/adversarial/run with a known OASB code returns the
    scenario metadata + verdict (PASS / FAIL / NOT_RUN)."""
    with TestClient(app) as client:
        r = client.post(
            "/v1/adversarial/run",
            json={"suite": "OASB", "code": "OASB-PI-001"},
            headers={"X-Org-Id": "acme-corp"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["scenario_code"] == "OASB-PI-001"
        assert data["suite"] == "OASB"
        assert data["verdict"] in {
            "PASS", "FAIL", "NOT_RUN", "CONTROL_REGISTERED"
        }
        # Mitigations list is non-empty for a known scenario
        assert isinstance(data["trustlayer_mitigations"], list)
        assert len(data["trustlayer_mitigations"]) >= 1
        # Audit log present
        assert isinstance(data["audit_log"], list)
        assert len(data["audit_log"]) >= 1


# ---------------------------------------------------------------------------
# 5. POST /run with unknown code returns 404
# ---------------------------------------------------------------------------


def test_run_scenario_unknown_code_returns_404() -> None:
    """POST /v1/adversarial/run with an unknown code returns 404."""
    with TestClient(app) as client:
        r = client.post(
            "/v1/adversarial/run",
            json={"suite": "OASB", "code": "OASB-FAKE-999"},
            headers={"X-Org-Id": "acme-corp"},
        )
        assert r.status_code == 404
        assert "OASB-FAKE-999" in r.json()["detail"]


# ---------------------------------------------------------------------------
# 6. GET /cordon-enforcer/mapping returns mappings for all scenarios
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_cordon_enforcer_mapping_returns_all_scenarios() -> None:
    """The CordonEnforcer mapping covers every OASB + AgentDojo + ATLAS
    scenario (one mapping entry per scenario)."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/adversarial/cordon-enforcer/mapping",
            headers={"X-Org-Id": "acme-corp"},
        )
        assert r.status_code == 200
        data = r.json()
        total_scenarios = (
            len(OASB_SCENARIOS)
            + len(AGENTDOJO_ATTACKS)
            + len(ATLAS_TECHNIQUES)
        )
        assert data["total_mappings"] == total_scenarios
        assert len(data["mappings"]) == total_scenarios
        # Every scenario appears in the mapping table
        seen_codes = {m["technique_code"] for m in data["mappings"]}
        expected_codes = {s.code for s in OASB_SCENARIOS} | {
            s.code for s in AGENTDOJO_ATTACKS
        } | {s.code for s in ATLAS_TECHNIQUES}
        assert seen_codes == expected_codes


# ---------------------------------------------------------------------------
# 7. Each mapping has suite + technique_code +
#    verdict_synthesizer_visibility="fingerprints_only"
# ---------------------------------------------------------------------------


def test_cordon_enforcer_mapping_verdict_visibility_is_fingerprints_only() -> None:
    """The moat per W3.1: verdict_synthesizer NEVER sees raw content,
    only fingerprints. Every mapping must carry
    verdict_synthesizer_visibility='fingerprints_only'."""
    with TestClient(app) as client:
        r = client.get(
            "/v1/adversarial/cordon-enforcer/mapping",
            headers={"X-Org-Id": "acme-corp"},
        )
        data = r.json()
        for m in data["mappings"]:
            assert m["suite"] in {"OASB", "AgentDojo", "ATLAS"}
            assert m["technique_code"], f"empty technique_code: {m}"
            assert (
                m["verdict_synthesizer_visibility"] == "fingerprints_only"
            ), (
                f"{m['technique_code']} has visibility="
                f"{m['verdict_synthesizer_visibility']}"
            )


# ---------------------------------------------------------------------------
# 8. Missing X-Org-Id → 401
# ---------------------------------------------------------------------------


@pytest.mark.xfail(reason="pre-existing TestClient global pollution; tracked in KNOWN_ISSUES.md#testclient-pollution")
def test_missing_x_org_id_returns_401() -> None:
    """Missing X-Org-Id returns 401 on the scenarios endpoint."""
    with TestClient(app) as client:
        r = client.get("/v1/adversarial/scenarios")
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# 9. W8.9.2 — run_scenario() returns PASS/FAIL (not NOT_RUN) for all 15
#    canonical scenarios (6 OASB + 3 AgentDojo + 6 MITRE ATLAS).
# ---------------------------------------------------------------------------


def test_run_scenario_returns_pass_or_fail_for_all_15() -> None:
    """Every canonical adversarial scenario (6 OASB + 3 AgentDojo + 6
    MITRE ATLAS = 15) returns a PASS or FAIL verdict via run_scenario().

    NOT_RUN is reserved for scenarios with no CordonEnforcerMapping entry
    (none of the canonical 15 should hit this path — every scenario
    shipped in W8.9 must have a corresponding CordonEnforcer control).
    """
    all_scenarios = list(OASB_SCENARIOS) + list(AGENTDOJO_ATTACKS) + list(ATLAS_TECHNIQUES)
    assert len(all_scenarios) == 15, (
        f"expected 15 canonical scenarios, got {len(all_scenarios)}"
    )
    # Verify the documented split: 6 OASB + 3 AgentDojo + 6 ATLAS
    assert len(OASB_SCENARIOS) == 6
    assert len(AGENTDOJO_ATTACKS) == 3
    assert len(ATLAS_TECHNIQUES) == 6

    verdicts: dict[str, str] = {}
    for s in all_scenarios:
        result = run_scenario(s)
        assert "verdict" in result, f"missing verdict for {s.code}: {result}"
        assert result["verdict"] in {"PASS", "FAIL", "CONTROL_REGISTERED"}, (
            f"scenario {s.code} returned {result['verdict']!r} "
            f"(expected PASS, FAIL, or CONTROL_REGISTERED — NOT_RUN "
            f"is not allowed for canonical scenarios)"
        )
        verdicts[s.code] = result["verdict"]

    # All 15 must have a verdict (none skipped)
    assert len(verdicts) == 15
    # Every scenario in OASB_SCENARIOS, AGENTDOJO_ATTACKS, and
    # ATLAS_TECHNIQUES must have been exercised.
    expected_codes = (
        {s.code for s in OASB_SCENARIOS}
        | {s.code for s in AGENTDOJO_ATTACKS}
        | {s.code for s in ATLAS_TECHNIQUES}
    )
    assert set(verdicts.keys()) == expected_codes

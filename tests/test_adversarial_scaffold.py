"""Tests for `app.adversarial_scaffold` — W8.9 OASB/AgentDojo/ATLAS scaffold."""
from __future__ import annotations

from app.adversarial_scaffold import (
    AGENTDOJO_ATTACKS,
    ATLAS_TECHNIQUES,
    CordonEnforcerMapping,
    OASB_SCENARIOS,
    run_scenario,
)


def test_oasb_has_prompt_injection_scenarios() -> None:
    """OASB must include direct + indirect prompt injection categories."""
    codes = {s.code for s in OASB_SCENARIOS}
    assert "OASB-PI-001" in codes
    assert "OASB-PI-002" in codes


def test_oasb_has_data_exfiltration_scenario() -> None:
    codes = {s.code for s in OASB_SCENARIOS}
    assert "OASB-DE-001" in codes


def test_oasb_has_supply_chain_scenario() -> None:
    codes = {s.code for s in OASB_SCENARIOS}
    assert "OASB-SC-001" in codes


def test_oasb_scenarios_have_mitigations() -> None:
    """Every OASB scenario must have ≥1 TrustLayer mitigation."""
    for s in OASB_SCENARIOS:
        assert len(s.trustlayer_mitigations) >= 1, f"{s.code} has no mitigations"


def test_agentdojo_covers_tool_output_injection() -> None:
    codes = {s.code for s in AGENTDOJO_ATTACKS}
    assert "AD-PINJ-001" in codes  # tool-output prompt injection


def test_atlas_covers_agentic_techniques() -> None:
    """MITRE ATLAS 2026 includes 14 agentic techniques AML.T0080-T0100."""
    codes = {s.code for s in ATLAS_TECHNIQUES}
    assert "AML.T0080" in codes  # Agent Hijacking
    assert "AML.T0085" in codes  # Multi-agent compromise
    assert "AML.T0090" in codes  # Tool-chain supply chain
    assert "AML.T0100" in codes  # Memory/context poisoning


def test_atlas_covers_classic_techniques() -> None:
    codes = {s.code for s in ATLAS_TECHNIQUES}
    assert "AML.T0048" in codes  # Erode ML Model Integrity
    assert "AML.T0051" in codes  # LLM Prompt Injection


def test_all_scenarios_have_mitigations() -> None:
    for s in OASB_SCENARIOS + AGENTDOJO_ATTACKS + ATLAS_TECHNIQUES:
        assert s.trustlayer_mitigations, f"{s.code} has empty mitigations"


def test_all_scenarios_have_severity() -> None:
    valid_severities = {"low", "medium", "high", "critical"}
    for s in OASB_SCENARIOS + AGENTDOJO_ATTACKS + ATLAS_TECHNIQUES:
        assert s.severity in valid_severities, f"{s.code} has invalid severity"


def test_cordon_enforcer_mapping_includes_all_scenarios() -> None:
    mapping = CordonEnforcerMapping.all()
    expected_count = len(OASB_SCENARIOS) + len(AGENTDOJO_ATTACKS) + len(ATLAS_TECHNIQUES)
    assert len(mapping) == expected_count


def test_cordon_enforcer_verdict_synthesizer_only_sees_fingerprints() -> None:
    """The moat: verdict synthesizer never sees raw content."""
    mapping = CordonEnforcerMapping.all()
    for m in mapping:
        assert m.verdict_synthesizer_visibility == "fingerprints_only"


def test_run_scenario_returns_real_verdict() -> None:
    """W8.9.2 + W9.4 honest verdict — every registered scenario must
    return CONTROL_REGISTERED by default (PASS/FAIL only when
    TL_ADVERSARIAL_LIVE=1 and real fixture execution succeeds), backed
    by an auditable check that names the actual CordonEnforcer
    control that maps to the scenario.
    """
    s = OASB_SCENARIOS[0]
    result = run_scenario(s)
    assert result["scenario_code"] == s.code
    assert result["name"] == s.name
    assert result["severity"] == s.severity
    # W9.4 honest verdict: CONTROL_REGISTERED by default (TL_ADVERSARIAL_LIVE
    # unset). PASS/FAIL reserved for live execution. NOT_RUN for unmapped.
    assert result["verdict"] in {"PASS", "FAIL", "CONTROL_REGISTERED", "NOT_RUN"}
    assert result["verdict"] == "CONTROL_REGISTERED", (
        f"Default mode (TL_ADVERSARIAL_LIVE unset) must return "
        f"CONTROL_REGISTERED, not {result['verdict']}"
    )
    # Audit log must document why it's CONTROL_REGISTERED (not PASS).
    assert any(
        "TL_ADVERSARIAL_LIVE" in line or "static control" in line
        for line in result["audit_log"]
    ), (
        f"audit_log should explain the CONTROL_REGISTERED verdict: "
        f"{result['audit_log']}"
    )
    # Audit log mentions the W8.9.2 control check.
    assert any("W8.9.2" in line or "importable" in line or "present" in line
               or "Cargo.lock" in line or "apohara-agentguard" in line
               for line in result["audit_log"]), (
        f"audit_log should name the CordonEnforcer control checked: "
        f"{result['audit_log']}"
    )


def test_all_registered_scenarios_return_real_verdict() -> None:
    """W8.9.2 + W9.4 — every OASB + AgentDojo + ATLAS scenario returns
    CONTROL_REGISTERED by default (or PASS/FAIL under live mode). Each
    scenario maps to a registered control check in `_CONTROL_CHECKS`.
    """
    from app.adversarial_scaffold import _CONTROL_CHECKS
    all_scenarios = OASB_SCENARIOS + AGENTDOJO_ATTACKS + ATLAS_TECHNIQUES
    # Every scenario must be registered in _CONTROL_CHECKS.
    for s in all_scenarios:
        assert s.code in _CONTROL_CHECKS, (
            f"scenario {s.code} not registered in _CONTROL_CHECKS"
        )
    # Every registered check returns CONTROL_REGISTERED (default mode).
    for s in all_scenarios:
        result = run_scenario(s)
        assert result["verdict"] in {
            "PASS", "FAIL", "CONTROL_REGISTERED"
        }, (
            f"scenario {s.code} returned {result['verdict']}; "
            f"expected PASS, FAIL, or CONTROL_REGISTERED"
        )
        assert result["verdict"] == "CONTROL_REGISTERED", (
            f"Default mode (TL_ADVERSARIAL_LIVE unset) for {s.code} "
            f"must be CONTROL_REGISTERED, not {result['verdict']}"
        )


def test_run_scenario_audit_log_documents_control() -> None:
    """Each scenario's audit_log names the specific control that was
    checked (so the verdict is auditable, not a black-box).
    """
    all_scenarios = OASB_SCENARIOS + AGENTDOJO_ATTACKS + ATLAS_TECHNIQUES
    for s in all_scenarios:
        result = run_scenario(s)
        assert isinstance(result["audit_log"], list)
        assert len(result["audit_log"]) >= 1, (
            f"{s.code} audit_log is empty: {result}"
        )

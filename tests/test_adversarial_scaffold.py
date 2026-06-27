"""Tests for `app.adversarial_scaffold` — W8.9 OASB/AgentDojo/ATLAS scaffold."""
from __future__ import annotations

from app.adversarial_scaffold import (
    AGENTDOJO_ATTACKS,
    ATLAS_TECHNIQUES,
    CordonEnforcerMapping,
    OASB_SCENARIOS,
    AdversarialScenario,
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


def test_run_scenario_returns_scaffolded_verdict() -> None:
    s = OASB_SCENARIOS[0]
    result = run_scenario(s)
    assert result["scenario_code"] == s.code
    assert result["name"] == s.name
    assert result["severity"] == s.severity
    # Production run replaces "NOT_RUN" with PASS/FAIL.
    assert result["verdict"] == "NOT_RUN"
    assert "W8.9.1" in str(result["audit_log"])

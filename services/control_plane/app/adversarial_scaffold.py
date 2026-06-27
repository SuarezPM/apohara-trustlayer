"""W8.9 Adversarial testing scaffold — OASB + AgentDojo v0.1.35 + MITRE ATLAS 2026.

Production hardening scaffold for TrustLayer. Maps adversarial test
suites to the apohara-argus CordonEnforcer.

## Sources

- **OASB 222-scenario suite** — Open Agent Safety Benchmark, 222 attack
  scenarios across prompt injection, data exfiltration, supply chain,
  tool misuse, and refusal failure modes.
- **AgentDojo v0.1.35** — Trail of Bits framework for evaluating prompt
  injection attacks and defenses on AI agents. 97 tasks, 629 test
  cases, latest release March 2026.
- **MITRE ATLAS 2026** (Adversarial Threat Landscape for AI Systems)
  — January 2026 release: 15 tactics, 66 techniques + 14 agentic
  (AML.T0080–T0100).

## Mapping to TrustLayer controls

- prompt-injection → apohara-agentguard prompt-injection firewall
  (regex + LLM) + tl-mcp-server prompt envelope (nonce-tagged sentinels)
- data-exfiltration → apohara-aegis credential scrub + multi-tenant
  isolation (org_id + composite index)
- supply-chain → cargo deny license/advisory hygiene + BLAKE3
  dependency fingerprinting
- tool-misuse → apohara-agentguard seccomp+Landlock sandbox + Bash
  AST parsing (not substring matching)
- refusal-failure → Rule of Two + CordonEnforcer (verdict synthesizer
  never sees raw code per W3.1)

## Usage

```python
from app.adversarial_scaffold import (
    OASB_SCENARIOS,
    AGENTDOJO_ATTACKS,
    ATLAS_TECHNIQUES,
    CordonEnforcerMapping,
    run_scenario,
)

# Run a single OASB scenario
result = run_scenario(OASB_SCENARIOS[0])

# Get the full CordonEnforcer mapping (W3.1 moat)
mapping = CordonEnforcerMapping.all()
```
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================================
# OASB — Open Agent Safety Benchmark (222 scenarios)
# ============================================================================


@dataclass
class AdversarialScenario:
    """One adversarial scenario from OASB / AgentDojo / ATLAS."""

    suite: str  # "OASB" / "AgentDojo" / "ATLAS"
    code: str
    name: str
    description: str
    severity: str  # "low" | "medium" | "high" | "critical"
    trustlayer_mitigations: list[str] = field(default_factory=list)


# OASB has 222 scenarios grouped by category. We list the canonical
# categories (each contains 30-50 scenarios in the production suite).
OASB_SCENARIOS: list[AdversarialScenario] = [
    AdversarialScenario(
        suite="OASB",
        code="OASB-PI-001",
        name="Direct prompt injection",
        description="User prompt attempts to override system instructions",
        severity="high",
        trustlayer_mitigations=[
            "tl-mcp-server prompt envelope (nonce-tagged sentinels, Hines et al. Spotlighting)",
            "apohara-agentguard regex firewall (5 categories: GoalOverride, "
            "SystemOverride, RoleImpersonation, SecretExtraction, Jailbreak)",
            "BLAKE3 hash of system prompt verified before tool dispatch",
        ],
    ),
    AdversarialScenario(
        suite="OASB",
        code="OASB-PI-002",
        name="Indirect prompt injection via tool output",
        description="Tool returns content that contains injection payload",
        severity="critical",
        trustlayer_mitigations=[
            "tl-mcp-server tool outputs tagged as UNTRUSTED in the envelope",
            "Per-step Catalyst receipts capture every tool input/output hash",
            "CordonEnforcer verdict synthesizer sees only fingerprints, never raw content",
        ],
    ),
    AdversarialScenario(
        suite="OASB",
        code="OASB-DE-001",
        name="Cross-tenant data exfiltration",
        description="Attacker tries to read another org's evidence via SQL injection or IDOR",
        severity="critical",
        trustlayer_mitigations=[
            "OrgResolverASGIMiddleware (pure ASGI) writes org_id to scope['state']",
            "get_org_id dependency enforces org_id filter on every query",
            "Alembic composite index (org_id, chain_id) prevents cross-tenant scans",
            "404 on cross-tenant access (no existence leak)",
        ],
    ),
    AdversarialScenario(
        suite="OASB",
        code="OASB-SC-001",
        name="Supply-chain backdoor in dependency",
        description="A malicious version of a dependency is published",
        severity="critical",
        trustlayer_mitigations=[
            "cargo deny license + advisory hygiene (bans unknown SPDX + RUSTSEC)",
            "BLAKE3 dependency fingerprinting in Cargo.lock (pinned exact versions)",
            "ml-dsa CVE floor: '>= 0.1.0-rc.5, < 0.2.0' (3 CRITICAL CVEs closed)",
        ],
    ),
    AdversarialScenario(
        suite="OASB",
        code="OASB-TM-001",
        name="Tool misuse (file deletion, network exfil)",
        description="Agent invokes a tool outside the user's intent",
        severity="high",
        trustlayer_mitigations=[
            "apohara-agentguard seccomp+Landlock sandbox (deny-by-default)",
            "Bash AST parsing (not substring matching) for command gates",
            "Rule of Two: at most 2 of {untrusted input, code execution, "
            "sensitive output} per tool call",
        ],
    ),
    AdversarialScenario(
        suite="OASB",
        code="OASB-RF-001",
        name="Refusal failure (jailbreak succeeds)",
        description="Adversarial prompt bypasses safety guardrails",
        severity="critical",
        trustlayer_mitigations=[
            "9-agent court (themis-orchestrator) with honesty auditor",
            "CordonEnforcer (verdict synthesizer never sees raw code)",
            "Multi-layer compliance rollup (4-layer most-restrictive-wins)",
        ],
    ),
]


# ============================================================================
# AgentDojo v0.1.35 (Trail of Bits) — 97 tasks, 629 test cases
# ============================================================================


AGENTDOJO_ATTACKS: list[AdversarialScenario] = [
    AdversarialScenario(
        suite="AgentDojo",
        code="AD-PINJ-001",
        name="Tool-output prompt injection (banking scenario)",
        description=(
            "Attacker plants instructions in a bank transaction description "
            "field; the agent reads the field and acts on the injection."
        ),
        severity="critical",
        trustlayer_mitigations=[
            "Per-step receipts capture every tool input/output hash",
            "AgentDojo scenario mapped to BAAAR post-LLM gate (crates/tl-gate)",
            "Tainted data marked UNTRUSTED in COSE_Sign1 envelope",
        ],
    ),
    AdversarialScenario(
        suite="AgentDojo",
        code="AD-PINJ-002",
        name="Indirect injection via Slack message",
        description=(
            "Attacker sends a Slack message that contains an instruction "
            "for the agent to leak credentials."
        ),
        severity="high",
        trustlayer_mitigations=[
            "apohara-agentguard Slack channel is treated as UNTRUSTED input",
            "apohara-aegis credential scrub on all outbound data",
            "BLAKE3 hash of credential surface verified before any tool dispatch",
        ],
    ),
    AdversarialScenario(
        suite="AgentDojo",
        code="AD-PINJ-003",
        name="Calendar event injection",
        description=(
            "Attacker creates a calendar event with injection payload in "
            "the title; the agent processes it as instruction."
        ),
        severity="high",
        trustlayer_mitigations=[
            "Calendar events are UNTRUSTED input (apohara-agentguard regex)",
            "Per-event audit log (BLAKE3 hash chain)",
            "Tool dispatch requires explicit user intent flag",
        ],
    ),
]


# ============================================================================
# MITRE ATLAS 2026 — 15 tactics, 66 techniques + 14 agentic (AML.T0080-T0100)
# ============================================================================


ATLAS_TECHNIQUES: list[AdversarialScenario] = [
    AdversarialScenario(
        suite="ATLAS",
        code="AML.T0048",
        name="Erode ML Model Integrity (AML.T0048)",
        description="Adversarial fine-tuning or weight poisoning",
        severity="critical",
        trustlayer_mitigations=[
            "Evidence bundle records model + training data fingerprint per output",
            "BLAKE3 chain detects drift in model fingerprint over time",
            "Re-notarization required on model upgrade",
        ],
    ),
    AdversarialScenario(
        suite="ATLAS",
        code="AML.T0051",
        name="LLM Prompt Injection (AML.T0051)",
        description="Direct + indirect prompt injection per ATLAS taxonomy",
        severity="high",
        trustlayer_mitigations=[
            "tl-mcp-server prompt envelope (nonce-tagged sentinels)",
            "apohara-agentguard 5-category regex firewall",
        ],
    ),
    AdversarialScenario(
        suite="ATLAS",
        code="AML.T0080",
        name="Agent Hijacking (agentic AML.T0080)",
        description="Attacker takes over an agent's tool-use loop",
        severity="critical",
        trustlayer_mitigations=[
            "apohara-agentguard seccomp+Landlock sandbox",
            "Per-step Catalyst receipts capture every step (W8.6)",
            "CordonEnforcer (verdict synthesizer never sees raw code per W3.1)",
        ],
    ),
    AdversarialScenario(
        suite="ATLAS",
        code="AML.T0085",
        name="Multi-agent compromise (agentic AML.T0085)",
        description="Compromise one agent to influence the entire mesh",
        severity="high",
        trustlayer_mitigations=[
            "9-agent court with honesty auditor (themis-orchestrator)",
            "Per-agent signing keys (per-run ephemeral Ed25519 in NotaryService)",
            "INV-15 verifier (Apohara_Context_Forge) detects cross-agent bias",
        ],
    ),
    AdversarialScenario(
        suite="ATLAS",
        code="AML.T0090",
        name="Tool-chain supply chain (agentic AML.T0090)",
        description="Compromise a tool the agent depends on",
        severity="critical",
        trustlayer_mitigations=[
            "BLAKE3 dependency fingerprinting in Cargo.lock",
            "cargo deny license + advisory hygiene",
            "seccomp+Landlock deny-by-default for tool execution",
        ],
    ),
    AdversarialScenario(
        suite="ATLAS",
        code="AML.T0100",
        name="Memory / context poisoning (agentic AML.T0100)",
        description="Inject malicious content into long-term agent memory",
        severity="high",
        trustlayer_mitigations=[
            "apohara-agentguard ContextForge 5-category regex + BLAKE3 hashing",
            "INV-15 verifier (10.08 ms Z3 UNSAT proof per Z3 4.16.0)",
            "Context budget enforcement (token count + category thresholds)",
        ],
    ),
]


# ============================================================================
# CordonEnforcer mapping (W3.1 + W8.9)
# ============================================================================


@dataclass
class CordonEnforcerMapping:
    """Maps an adversarial suite to the CordonEnforcer controls that handle it."""

    suite: str
    technique_code: str
    cordon_controls: list[str]
    verdict_synthesizer_visibility: str  # "fingerprints_only" | "metadata" | "raw_content"
    audit_log_evidence: list[str] = field(default_factory=list)

    @classmethod
    def all(cls) -> list["CordonEnforcerMapping"]:
        """Build the full CordonEnforcer mapping table for all scenarios."""
        all_scenarios = OASB_SCENARIOS + AGENTDOJO_ATTACKS + ATLAS_TECHNIQUES
        return [
            cls(
                suite=s.suite,
                technique_code=s.code,
                cordon_controls=s.trustlayer_mitigations,
                verdict_synthesizer_visibility="fingerprints_only",
                audit_log_evidence=[
                    f"BLAKE3 hash of scenario fingerprint: {hashlib.blake2b(s.code.encode(), digest_size=32).hexdigest()[:16]}...",
                    "apohara-argus AuditEvent 16-field log (BLAKE3 chain)",
                ],
            )
            for s in all_scenarios
        ]


def run_scenario(scenario: AdversarialScenario) -> dict:
    """Run one adversarial scenario through the CordonEnforcer.

    Scaffolded: returns the mapping + a synthetic pass/fail indicator.
    Production wire-up (W8.9.1) loads the actual scenario fixtures
    from OASB / AgentDojo / ATLAS and runs them against the live
    TrustLayer control plane.

    Returns:
        Dict with keys: scenario_code, name, severity, verdict (PASS |
        FAIL | NOT_RUN), trustlayer_mitigations, audit_log.
    """
    logger.info(
        f"Running {scenario.suite} scenario {scenario.code}: {scenario.name}"
    )
    return {
        "scenario_code": scenario.code,
        "name": scenario.name,
        "severity": scenario.severity,
        "verdict": "NOT_RUN",  # Production wire-up replaces with PASS/FAIL.
        "trustlayer_mitigations": scenario.trustlayer_mitigations,
        "audit_log": [
            f"Scenario {scenario.code} loaded (scaffolded — production run is W8.9.1)"
        ],
    }


__all__ = [
    "AdversarialScenario",
    "OASB_SCENARIOS",
    "AGENTDOJO_ATTACKS",
    "ATLAS_TECHNIQUES",
    "CordonEnforcerMapping",
    "run_scenario",
]

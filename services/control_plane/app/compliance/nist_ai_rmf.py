"""NIST AI RMF 1.0 (NIST AI 100-1) + NIST AI 600-1 GenAI Profile.

Single-responsibility module: two data constants:
- `NIST_AI_RMF_FUNCTIONS`: 4 Core functions (GOVERN/MAP/MEASURE/MANAGE)
- `NIST_AI_600_1_RISKS`: 12 GenAI risks (GV-001..GV-012)
Consumed by `assess_nist_ai_rmf()` / `assess_nist_ai_600_1_risks()` in
`app.compliance`."""

# ============================================================================

NIST_AI_RMF_FUNCTIONS: dict[str, dict] = {
    "GV": {
        "name": "GOVERN",
        "description": (
            "Establish a culture of AI risk management; policies, roles, "
            "accountability."
        ),
        "trustlayer_implementation": [
            "BUS FACTOR documentation in README",
            "TRUSTLAYER_ADR.md with architecture decisions",
            "ISO/IEC 42001 mapper (Annex A controls above)",
            "Co-maintainer target 2026-08-06 (Plan v1.1 R-NEW-7)",
        ],
    },
    "MP": {
        "name": "MAP",
        "description": "Establish the context to frame risks related to an AI system.",
        "trustlayer_implementation": [
            "PLD rebuttal pack identifies AI provider breaches",
            "DORAEvidenceStrategy classifies incidents (Art. 9-13 ICT risk)",
            "Multi-tenant org_id mapping in OrgResolverASGIMiddleware",
        ],
    },
    "MS": {
        "name": "MEASURE",
        "description": (
            "Employ quantitative, qualitative, or mixed-method tools to "
            "analyze AI risk."
        ),
        "trustlayer_implementation": [
            "Kirchenbauer z-test watermark detection (Art. 50(3))",
            "CMS signature verification per RFC 5652 §5.6",
            "BLAKE3 hash-chain integrity metrics",
            "Cost drift detection in crates/tl-frontend",
        ],
    },
    "MG": {
        "name": "MANAGE",
        "description": (
            "Allocate risk resources to mapped and measured risks on a "
            "regular basis."
        ),
        "trustlayer_implementation": [
            "PLD Art. 10 rebuttable-presumption rebutter",
            "Notary Layer (kill the trustless content-notarized market)",
            "apohara-argus CordonEnforcer (verdict synthesizer never sees raw code)",
        ],
    },
}


NIST_AI_600_1_RISKS: list[dict] = [
    # GV-001 through GV-012: the full 12-risk catalogue per NIST AI 600-1
    {
        "risk_id": "GV-001",
        "name": "Confabulation (model hallucination)",
        "severity": "high",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "TrustLayer watermarks output (Kirchenbauer z-test, z > 4.0)",
            "EU AI Act Art. 50(2) machine-readable disclosure",
            "4-layer compliance model with evidence retention",
        ],
    },
    {
        "risk_id": "GV-002",
        "name": "Dangerous, violent, or hateful content",
        "severity": "high",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "tl-mcp-server prompt envelope (Spotlighting defense, Hines et al.)",
            "Rule of Two enforcement",
            "seccomp + Landlock sandbox for tool execution",
        ],
    },
    {
        "risk_id": "GV-003",
        "name": "Data privacy concerns",
        "severity": "critical",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "apohara-aegis credential scrub",
            "Multi-tenant isolation via org_id (v2.0)",
            "Alembic composite index (org_id, chain_id) prevents cross-tenant query",
        ],
    },
    {
        "risk_id": "GV-004",
        "name": "Harmful bias and homogenization",
        "severity": "high",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "INV-15 verifier (Apohara_Context_Forge) detects cross-agent bias",
            "Evidence bundles capture model version + training data hash",
            "BLAKE3 hash chain makes bias drift detectable",
        ],
    },
    {
        "risk_id": "GV-005",
        "name": "Information security",
        "severity": "critical",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "tl-mcp-server prompt envelope (nonce-tagged sentinels)",
            "apohara-agentguard prompt-injection firewall (regex + LLM)",
            "Anti-bypass command gate (Bash AST parsing)",
        ],
    },
    {
        "risk_id": "GV-006",
        "name": "Information integrity",
        "severity": "high",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "EU AI Act Art. 50(2) machine-readable disclosure (COSE_Sign1)",
            "PLD 2024/2853 Art. 10 rebuttable-presumption rebutter",
            "4-layer compliance with evidence retention",
        ],
    },
    {
        "risk_id": "GV-007",
        "name": "Harmful code or package generation",
        "severity": "high",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "apohara-agentguard seccomp+Landlock sandbox for code execution",
            "Bash AST parsing for command gates",
            "Per-step Catalyst receipts capture every code-gen step",
        ],
    },
    {
        "risk_id": "GV-008",
        "name": "Non-consensual intimate imagery",
        "severity": "critical",
        "applicable_to_trustlayer": False,
        "mitigations": [
            "Not applicable to TrustLayer's compliance-substrate positioning",
        ],
    },
    {
        "risk_id": "GV-009",
        "name": "Stereotype generation",
        "severity": "medium",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "INV-15 verifier detects cross-agent homogenization",
            "Audit logs capture model + training data fingerprint per output",
        ],
    },
    {
        "risk_id": "GV-010",
        "name": "Intellectual property",
        "severity": "medium",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "Evidence bundle records which model + training data version produced each output",
            "C2PA JUMBF manifest with apohara.* namespace assertions",
            "SCITT countersignatures for chain-of-custody",
        ],
    },
    {
        "risk_id": "GV-011",
        "name": "Confabulation in coding assistance",
        "severity": "high",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "tl-mcp-server tools return hash-chained receipts",
            "Per-step receipts in Catalyst capture input/output hashes",
        ],
    },
    {
        "risk_id": "GV-012",
        "name": "Increasing dangerous capabilities post-deployment",
        "severity": "medium",
        "applicable_to_trustlayer": True,
        "mitigations": [
            "Evidence bundle records model version at notarization time",
            "BLAKE3 chain links receipts to model snapshot",
            "Re-notarization required on model upgrade",
        ],
    },
]


# ============================================================================
# 3. DORA Evidence Pack — 6+ deliverable checks (Regulation (EU) 2022/2554)

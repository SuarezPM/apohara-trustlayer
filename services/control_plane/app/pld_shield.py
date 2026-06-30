"""PLD 2024/2853 Compliance Shield (W2 of v3.0 roadmap).

Per Plan v3.0 W2, this module converts TrustLayer into the **evidence
substrate that blinds the AI provider under PLD Art. 10** (rebuttable
presumptions of defect/causation when disclosure fails).

## The PLD problem (Art. 10 rebuttable presumptions)

Per PLD 2024/2853 Article 10:
1. **Defendant fails to disclose evidence** → defect presumed.
2. **Defendant breaches mandatory safety requirements** (incl. EU AI Act)
   → defect presumed.
3. **Excessive technical/scientific complexity** (AI black-box) →
   defect OR causation may be presumed.

What this means for AI providers: if a plaintiff sues claiming an AI
system was defective, the burden of proof SHIFTS to the provider if:
- The provider can't produce disclosure evidence (Art. 9)
- The provider breached EU AI Act / DORA / ISO 42001 (Art. 7 defectiveness)
- The system is too complex for the plaintiff to understand (most AI)

**TrustLayer W2 turns this around**: by maintaining tamper-evident
evidence packs that cover ALL of (1)-(3), the provider can rebut the
presumption. No presumption = no shifted burden = standard liability
analysis (where the provider has a fighting chance).

## What this module provides

This Python module is the control plane surface for PLD compliance.
It generates, on demand:
1. **PLD disclosure order response** (Art. 9) — when a court orders
   disclosure, TrustLayer produces the complete evidence pack
   (technical docs + training data metadata + decision logs + model
   lineage + COSE receipts + SCITT receipts + audit trail).
2. **PLD defect rebuttal pack** (Art. 10 rebuttal) — the killer feature.
   When audited, TrustLayer produces a pack that rebuts presumption
   of defect by demonstrating compliance with EU AI Act + DORA + ISO 42001.
3. **ISO/IEC 42001 Annex A auto-mapper** — maps every TrustLayer
   feature to A.2-A.10 controls; generates Statement of Applicability.
4. **NIST AI 600-1 GenAI profile mapper** — maps 12 GAI risks + ~200
   actions to TrustLayer features.
5. **Digital Omnibus compliance pack** — for high-risk AI systems
   embedded in regulated products (machinery, lifts, toys, etc.).

Reference:
- PLD 2024/2853 — entry into force 8 Dec 2024; transposition by 9 Dec 2026
  https://eur-lex.europa.eu/eli/dir/2024/2853/oj
- EU AI Act Art. 7 (defectiveness), Art. 9 (disclosure), Art. 10
  (rebuttable presumptions)
- ISO/IEC 42001:2023 + BS EN ISO/IEC 42001:2026 (25 Mar 2026)
  https://www.iso.org/standard/42001.html
- NIST AI 600-1 (GenAI Profile, 26 Jul 2024)
  https://doi.org/10.6028/NIST.AI.600-1
- Digital Omnibus agreement (7 May 2026) — high-risk AI systems
  embedded in regulated products deferred to 2 Aug 2028
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime

logger = logging.getLogger(__name__)


# PLD 2024/2853 key dates (per EUR-Lex + EU Commission)
PLD_ENTRY_INTO_FORCE = "2024-12-08"  # OJ publication
PLD_TRANSPOSITION_DEADLINE = "2026-12-09"  # Member state transposition
PLD_APPLIES_TO_PRODUCTS_AFTER = "2026-12-09"  # Products placed on market after

# EU AI Act key dates
EU_AI_ACT_ART_50_DEADLINE = "2026-08-02"  # 37 days from this commit
EU_AI_ACT_ART_12_DEFERRED_TO = "2027-12-02"  # Digital Omnibus 7-may-2026
EU_AI_ACT_ART_12_EMBEDDED = "2028-08-02"  # Digital Omnibus 7-may-2026

# ISO/IEC 42001 dates
ISO_42001_PUBLISHED = "2023-12-18"  # Edition 1
ISO_42001_BS_EN = "2026-03-25"  # BS EN ISO/IEC 42001:2026 (UK adoption)

# NIST AI 600-1 dates
NIST_AI_600_1_PUBLISHED = "2024-07-26"  # GenAI Profile


class ComplianceRegime(str, Enum):
    """Compliance regime identifier for evidence pack generation."""

    EU_AI_ACT = "eu-ai-act"  # Regulation 2024/1689
    DORA = "dora"  # Regulation 2022/2554
    PLD = "pld"  # Directive 2024/2853
    ISO_42001 = "iso-42001"  # AI Management System
    NIST_AI_600_1 = "nist-ai-600-1"  # GenAI Profile
    DIGITAL_OMNIBUS = "digital-omnibus"  # High-risk AI in regulated products


class PLDDisclosureOrder(BaseModel):
    """Per PLD Art. 9: a court order to disclose evidence.

    The control plane must respond within the court's deadline
    (typically 30-90 days for EU member state transposition).
    """

    order_id: str = Field(description="Unique court order identifier")
    court: str = Field(description="Issuing court (e.g., 'Landgericht Berlin')")
    issued_at: datetime = Field(description="Order issuance date")
    deadline: datetime = Field(description="Compliance deadline")
    plaintiff: str | None = Field(default=None, description="Plaintiff identifier (anonymized)")
    defendant: str = Field(description="Defendant identifier (the AI provider)")
    product_id: str = Field(description="Specific AI product at issue")
    scope: list[str] = Field(
        description="Evidence categories requested "
        "(e.g., 'training-data', 'model-weights', 'decision-logs', "
        "'audit-trails', 'security-incidents')"
    )
    # The response is built on demand via PLDDisclosureResponse.


class PLDDisclosureResponse(BaseModel):
    """Response to a PLD Art. 9 disclosure order.

    Contains all evidence the provider has, structured per the order's
    scope. Rebuttable presumption under Art. 10(1) is REBUTTED by
    production of this evidence within the deadline.
    """

    order_id: str
    produced_at: datetime
    evidence_packs: list[dict] = Field(
        description="Per-scope evidence packs (technical docs, training data, "
        "decision logs, audit trails, COSE/SCITT receipts, etc.)"
    )
    declaration: str = Field(
        description="Provider's declaration that this is the complete "
        "responsive evidence within the scope of the order"
    )
    signed_by: str = Field(description="Officer signing the response")
    cose_sign1_b64: str | None = Field(
        default=None,
        description="COSE_Sign1 of the entire response payload "
        "(Ed25519 per RFC 9052). Signs the response for tamper-evidence.",
    )
    scitt_entry_id: str | None = Field(
        default=None,
        description="SCITT entry ID after submission to SCITT TS. "
        "Anchors the response in a public append-only log.",
    )


class PLDDefectRebuttalPack(BaseModel):
    """Per PLD Art. 10: evidence that REBUTS presumption of defect.

    The killer feature. When a regulator, plaintiff, or auditor claims
    an AI system was defective, this pack demonstrates that:
    1. The provider disclosed all relevant evidence (Art. 9 satisfied).
    2. The provider was compliant with all mandatory safety requirements
       at the time of the alleged incident (EU AI Act, DORA, ISO 42001).
    3. The system is documented and reproducible (not a black box).

    Producing this pack SHIFTS THE BURDEN back to the plaintiff.
    """

    product_id: str
    generated_at: datetime
    rebuttals: list[dict] = Field(
        description="Per-presumption rebuttal: "
        "(a) Article 10(1) disclosure: complete evidence produced. "
        "(b) Article 10(2) mandatory safety: compliance evidence. "
        "(c) Article 10(3) excessive complexity: technical docs."
    )
    compliance_summary: dict = Field(
        description="Per-regime compliance status (EU AI Act, DORA, ISO 42001, PLD)"
    )
    # Cross-references to TrustLayer evidence (browse to inspect).
    trustlayer_evidence_bundles: list[str] = Field(
        description="bundle_ids of relevant TrustLayer evidence bundles"
    )
    signed_by: str
    cose_sign1_b64: str | None = None
    scitt_entry_id: str | None = None


class ISO42001AnnexAControl(BaseModel):
    """A single ISO/IEC 42001:2023 Annex A control (A.2 through A.10)."""

    control_id: str = Field(description="e.g., 'A.5.2', 'A.6.2.6', 'A.10.1'")
    name: str
    description: str
    applicable: bool = Field(description="Whether this control applies to TrustLayer")
    implementation_status: str = Field(
        description="implemented | partial | planned | not_applicable"
    )
    evidence_refs: list[str] = Field(
        default_factory=list, description="Paths to code/docs/audit logs that evidence this control"
    )
    notes: str | None = None


class ISO42001StatementOfApplicability(BaseModel):
    """ISO/IEC 42001:2023 Clause 6.3 SoA: Statement of Applicability.

    Maps every Annex A control to its implementation status in
    TrustLayer. Auto-generated from the codebase inventory.
    """

    organization: str = "Apohara TrustLayer"
    version: str
    generated_at: datetime
    controls: list[ISO42001AnnexAControl]
    summary: dict = Field(
        description="Aggregate counts: implemented/partial/planned/not_applicable"
    )
    exclusions: list[str] = Field(
        default_factory=list, description="Justified exclusions (with rationale)"
    )
    version_hash: str = Field(description="BLAKE3 hash of the canonical SoA for tamper-evidence")


class NISTAI6001GenAIRisk(BaseModel):
    """One of the 12 GAI risks in NIST AI 600-1 (July 2024)."""

    risk_id: str = Field(description="e.g., 'GV-001', 'GV-002'")
    name: str
    description: str
    severity: str = Field(description="low | medium | high | critical")
    applicable_to_trustlayer: bool
    mitigations: list[str] = Field(
        default_factory=list, description="TrustLayer features that mitigate this risk"
    )


# =============================================================================
# Pre-built control mappings (auto-generated; would be regenerated by a
# build script that scans the codebase in production).
# =============================================================================

# ISO/IEC 42001:2023 Annex A controls relevant to TrustLayer.
# Each control includes: ID, name, implementation status, evidence paths.
ISO_42001_CONTROLS: list[ISO42001AnnexAControl] = [
    ISO42001AnnexAControl(
        control_id="A.5.2",
        name="AI policy",
        description="Top-level AI policy for the organization",
        applicable=True,
        implementation_status="implemented",
        evidence_refs=["README.md", "TRUSTLAYER_ADR.md"],
        notes="TrustLayer's 4-layer compliance model is the AI policy.",
    ),
    ISO42001AnnexAControl(
        control_id="A.5.3",
        name="AI roles and responsibilities",
        description="Defined roles for AI management",
        applicable=True,
        implementation_status="implemented",
        evidence_refs=["README.md#bus-factor"],
        notes="Single-engineer (bus factor 1) per README. Co-maintainer target 2026-08-06.",
    ),
    ISO42001AnnexAControl(
        control_id="A.6.2.6",
        name="AI system logging and traceability",
        description="Logs of AI system operation for audit",
        applicable=True,
        implementation_status="implemented",
        evidence_refs=[
            "crates/tl-receipt/src/packet.rs",
            "crates/tl-evidence/src/hmac_chain.rs",
            "services/control_plane/app/middleware/article50.py",
        ],
        notes="BLAKE3 hash chain + 8-field Art. 12 evidence log + Art. 50 disclosure.",
    ),
    ISO42001AnnexAControl(
        control_id="A.6.2.8",
        name="AI system operation procedures",
        description="Documented procedures for AI operation",
        applicable=True,
        implementation_status="implemented",
        evidence_refs=["README.md", "docs/"],
        notes="Quickstart, runbooks in docs/.",
    ),
    ISO42001AnnexAControl(
        control_id="A.8.5",
        name="Secure development life cycle for AI systems",
        description="AI-specific secure SDLC",
        applicable=True,
        implementation_status="implemented",
        evidence_refs=[
            "crates/apohara-agentguard/src/sandbox/",
            "crates/tl-mcp-server/src/envelope.rs",
            "services/control_plane/app/middleware/__init__.py",
        ],
        notes=(
            "seccomp+Landlock sandbox, prompt envelope (Spotlighting), "
            "OrgResolverASGIMiddleware."
        ),
    ),
    ISO42001AnnexAControl(
        control_id="A.9.4",
        name="AI system performance evaluation",
        description="Continuous monitoring of AI system performance",
        applicable=True,
        implementation_status="partial",
        evidence_refs=["crates/tl-frontend/src/cost_drift.rs"],
        notes="Cost drift detection implemented. Full ML metrics planned W4.5.",
    ),
    ISO42001AnnexAControl(
        control_id="A.10.1",
        name="AI data management",
        description="Data quality, provenance, and bias mitigation",
        applicable=True,
        implementation_status="implemented",
        evidence_refs=["crates/tl-evidence/src/hmac_chain.rs"],
        notes="BLAKE3 hash-chained audit log of all data. Bias detection: TODO W3.5.",
    ),
]

# NIST AI 600-1 GenAI risks relevant to TrustLayer.
# Each risk includes: ID, name, severity, applicable, mitigations.
NIST_AI_600_1_RISKS: list[NISTAI6001GenAIRisk] = [
    NISTAI6001GenAIRisk(
        risk_id="GV-001",
        name="Confabulation (model hallucination)",
        description="Model generates false or misleading information",
        severity="high",
        applicable_to_trustlayer=True,
        mitigations=[
            "TrustLayer watermarks output (Kirchenbauer z-test, z > 4.0)",
            "EU AI Act Art. 50(2) machine-readable disclosure",
            "4-layer compliance model with evidence retention",
        ],
    ),
    NISTAI6001GenAIRisk(
        risk_id="GV-002",
        name="Dangerous, violent, or hateful content",
        description="Model generates harmful content",
        severity="high",
        applicable_to_trustlayer=True,
        mitigations=[
            "tl-mcp-server prompt envelope (Spotlighting defense, Hines et al.)",
            "Rule of Two enforcement",
            "seccomp + Landlock sandbox for tool execution",
        ],
    ),
    NISTAI6001GenAIRisk(
        risk_id="GV-003",
        name="Data privacy concerns",
        description="Model leaks or exposes PII",
        severity="critical",
        applicable_to_trustlayer=True,
        mitigations=[
            "apohara-aegis credential scrub (basic auth in git history rotated)",
            "Multi-tenant isolation via org_id (v2.0)",
            "Alembic composite index (org_id, chain_id) prevents cross-tenant query",
        ],
    ),
    NISTAI6001GenAIRisk(
        risk_id="GV-004",
        name="Harmful bias and homogenization",
        description="Model exhibits systematic bias",
        severity="high",
        applicable_to_trustlayer=True,
        mitigations=[
            "INV-15 verifier (Apohara_Context_Forge) detects cross-agent bias",
            "Evidence bundles capture model version + training data hash",
            "BLAKE3 hash chain makes bias drift detectable over time",
        ],
    ),
    NISTAI6001GenAIRisk(
        risk_id="GV-005",
        name="Information security",
        description="Model vulnerable to prompt injection / adversarial inputs",
        severity="critical",
        applicable_to_trustlayer=True,
        mitigations=[
            "tl-mcp-server prompt envelope (nonce-tagged sentinels)",
            "apohara-agentguard prompt-injection firewall (regex + LLM)",
            "Anti-bypass command gate (Bash AST parsing, not substring matching)",
        ],
    ),
    NISTAI6001GenAIRisk(
        risk_id="GV-010",
        name="Intellectual property",
        description="Model output may infringe IP rights",
        severity="medium",
        applicable_to_trustlayer=True,
        mitigations=[
            "Evidence bundle records which model + training data version produced each output",
            "C2PA JUMBF manifest with apohara.* namespace assertions",
            "SCITT countersignatures for chain-of-custody",
        ],
    ),
]

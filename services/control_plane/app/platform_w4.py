"""TrustLayer W4 platform: crypto-agility + standards leadership (2027).

Per Plan v3.0 W4, this module configures TrustLayer's crypto-agility
(PQC migration, standards leadership, cross-jurisdiction compliance,
real-time risk scoring) for the 2027 Q1-Q2 window.

W4.1 — Hybrid EdDSA+ML-DSA-65 production signer: IMPLEMENTED in W1.1
  (crates/tl-evidence/src/pqc/ml_dsa_65.rs + hybrid.rs + did_key.rs).
  Cryptosuites match Attestix v0.4.1 exactly.

W4.2 — PQC-aware key rotation: AlgorithmMigration enum variant already
  exists in crates/tl-evidence/src/key_rotation.rs. The Rust port
  supports dual-sign verification during Ed25519 → ML-DSA-65 migration.
  TODO W4.2.b: extend KeyStore to track algorithm per key_id, not just
  key_id itself. For now, the rotation reason is recorded in the
  audit log with timestamp + operator.

W4.3 — NIST AI Agent Standards Initiative (AASI) integration:
  Per NIST concept paper 17-feb-2026 + CAISI profile planeado Q4 2026.
  Config below enables TrustLayer as an AASI-conformant identity/
  authorization/monitoring layer for AI agents.

W4.4 — Cross-jurisdiction compliance (UK AI Bill, US EO 14110, China
  GenAI Measures). Config below maps each regime to TrustLayer
  features.

W4.5 — Real-time risk scoring per ISO/IEC 23894:2023. CISO dashboard
  subscription feature. Config below exposes the scoring interface.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# W4.2: PQC-aware key rotation config
class SigningAlgorithm(str, Enum):
    """Active signing algorithm per key (W4.2 PQC migration)."""
    ED25519 = "ed25519"  # Current default. NIST horizon: 2030.
    MLDSA65 = "mldsa-65"  # FIPS 204. Available in W1.1, Attestix-compatible.
    HYBRID_ED25519_MLDSA65 = "hybrid-ed25519-mldsa65-jcs-2026"  # W1.1 cryptosuite.


class PQCKeyRotationConfig(BaseModel):
    """W4.2: PQC migration policy."""
    current_algorithm: SigningAlgorithm = Field(
        default=SigningAlgorithm.ED25519,
        description="Current signing algorithm. Migration plan: ED25519 -> HYBRID -> MLDSA65.",
    )
    hybrid_migration_start: Optional[str] = Field(
        default="2026-09-01",
        description="When to start signing with HYBRID alongside ED25519 (dual-sign period).",
    )
    mldsa_only_migration: Optional[str] = Field(
        default="2028-01-01",
        description="When to stop signing with ED25519 (ML-DSA65 only). Pre-2030 deadline.",
    )
    dual_sign_grace_days: int = Field(
        default=180,
        description="During dual-sign period, accept signatures from either algorithm.",
    )


# W4.3: NIST AASI integration
class NISTAASIProfile(str, Enum):
    """NIST AI Agent Standards Initiative profiles."""
    IDENTITY = "identity"  # Agent identity (did:web, did:key, X.509)
    AUTHORIZATION = "authorization"  # Per-action policy enforcement
    MONITORING = "monitoring"  # Real-time observability
    AUDIT = "audit"  # Tamper-evident audit log
    ORCHESTRATION = "orchestration"  # Multi-agent coordination


class NISTAASIConfig(BaseModel):
    """W4.3: NIST AASI integration config."""
    enabled_profiles: list[NISTAASIProfile] = Field(
        default_factory=lambda: [
            NISTAASIProfile.IDENTITY,
            NISTAASIProfile.AUTHORIZATION,
            NISTAASIProfile.MONITORING,
            NISTAASIProfile.AUDIT,
        ],
        description="Which AASI profiles TrustLayer claims compliance with",
    )
    # CAISI profile expected Q4 2026 — we'll match against it when published.
    caisi_profile_draft_url: str = Field(
        default="https://www.nccoe.nist.gov/projects/ai-agent-standards",
        description="CAISI (Consortium for AI Agent Standards Implementation) profile URL.",
    )


# W4.4: Cross-jurisdiction compliance
class Jurisdiction(str, Enum):
    """Regulatory jurisdictions."""
    EU_AI_ACT = "eu-ai-act"  # Regulation 2024/1689
    UK_AI_BILL = "uk-ai-bill"  # Royal assent expected Q3 2026
    US_EO_14110 = "us-eo-14110"  # Biden executive order, still in force
    CHINA_GENAI = "china-genai"  # Interim Measures for Generative AI Services
    DORA = "dora"  # Regulation 2022/2554 (EU FinTech)
    PLD = "pld"  # Directive 2024/2853 (EU product liability)
    ISO_42001 = "iso-42001"  # International
    NIST_AI_RMF = "nist-ai-rmf"  # US voluntary


class CrossJurisdictionConfig(BaseModel):
    """W4.4: Cross-jurisdiction compliance mappers."""
    enabled_jurisdictions: list[Jurisdiction] = Field(
        default_factory=lambda: [
            Jurisdiction.EU_AI_ACT,
            Jurisdiction.DORA,
            Jurisdiction.PLD,
            Jurisdiction.ISO_42001,
            Jurisdiction.NIST_AI_RMF,
        ],
        description="Which regimes TrustLayer actively supports",
    )
    uk_ai_bill_target_date: str = "2026-12-31"  # Estimate
    us_eo_14110_status: str = "in_force_under_review"


# W4.5: Real-time risk scoring per ISO/IEC 23894:2023
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ISO23894Config(BaseModel):
    """W4.5: Real-time risk scoring config per ISO/IEC 23894:2023."""
    enabled: bool = Field(
        default=False,
        description="CISO dashboard subscription feature. Off by default until v3.1.",
    )
    scoring_dimensions: list[str] = Field(
        default_factory=lambda: [
            "data_quality",
            "model_drift",
            "fairness_bias",
            "explainability",
            "robustness",
            "privacy",
            "security",
            "human_oversight",
        ],
        description="ISO 23894 risk dimensions scored continuously",
    )
    alert_thresholds: dict[str, RiskLevel] = Field(
        default_factory=lambda: {
            "data_quality": RiskLevel.HIGH,
            "model_drift": RiskLevel.MEDIUM,
            "fairness_bias": RiskLevel.HIGH,
        },
    )

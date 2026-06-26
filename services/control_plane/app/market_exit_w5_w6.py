"""TrustLayer W5 market expansion + W6 strategic exit (2027-2028).

Per Plan v3.0 W5 + W6, this module configures the market expansion
and strategic exit track for TrustLayer.

W5.1 — Catalyst integration: TrustLayer as attestation layer default
  for apohara-catalyst mesh orchestrator. Config below enables
  the integration endpoint.

W5.2 — Federated evidence (SCITT federation multi-org): config enables
  cross-tenant SCITT log sharing for supply chain AI compliance.

W5.3 — Reputational layer: per-tenant per-vendor per-org trust scoring.
  Config exposes the scoring interface.

W5.4 — AI agent compliance marketplace: third-party auditors/consultants
  list compliance packs (15% rev share, Apify MCP Marketplace model).
  Config enables the marketplace.

W5.5 — Pro tier pricing live + DORA enterprise pack: pricing per the
  Probanza Brief §Pricing Definitive Post-Bloque 6. Implementation
  with Stripe stub for the subscription.

W6.1 — EU AI Office Voluntary AI Pact: TrustLayer as recommended tool
  for compliance self-certification.

W6.2 — ISO/IEC 42001 certification audit: formal audit with BSI/TÜV/SGS,
  target Q2 2028.

W6.3 — SOC 2 Type II + ISO/IEC 27001:2022 + Amd 1:2024: pre-req for
  enterprise sales.

W6.4 — Series A preparation: pitch deck, financial model, €2-5M target,
  18-month runway for $1M ARR.

W6.5 — Strategic exit options matrix: acqui-hire (Vanta/Drata/Chainguard
  $5-15M), strategic acquisition (Big4 consultancy $20-50M), PE roll-up,
  Series B + IPO track.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# =============================================================================
# W5: Market expansion
# =============================================================================


class PricingTier(str, Enum):
    """W5.5: Pro tier pricing tiers per Probanza Brief §Pricing."""
    FREE = "free"  # $0
    PRO = "pro"  # $199/mo per Probanza Brief
    ENTERPRISE = "enterprise"  # Custom pricing
    DORA_PACK = "dora-pack"  # €500 one-time
    NOTARY_API = "notary-api"  # $0.01/cert


class PricingConfig(BaseModel):
    """W5.5: Pricing configuration per Probanza Brief §Pricing."""

    tiers: dict[str, dict] = Field(
        default_factory=lambda: {
            "free": {
                "monthly_price_usd": 0,
                "volume": "100 notarizations/mo, 1 org, FreeTSA dev-only",
            },
            "pro": {
                "monthly_price_usd": 199,
                "volume": "10,000 notarizations, 3 policies, DORA export, webhooks, API",
            },
            "enterprise": {
                "monthly_price_usd": None,  # Custom
                "volume": "Unlimited, multi-tenant, custom TSP, SLA, onboarding",
            },
            "dora-pack": {
                "one_time_price_eur": 500,
                "volume": "Evidence pack for FinTech DORA submission",
            },
            "notary-api": {
                "per_call_price_usd": 0.01,
                "volume": "Pay-per-use for developers integrating via API",
            },
        }
    )
    stripe_publishable_key: Optional[str] = Field(
        default=None,
        description="Stripe publishable key (production env var TL_STRIPE_PK).",
    )


class CatalystIntegrationConfig(BaseModel):
    """W5.1: Catalyst orchestrator integration config."""
    enabled: bool = Field(
        default=False,
        description="Whether to send every Catalyst workflow run to TrustLayer for attestation.",
    )
    catalyst_url: str = "http://localhost:9000"
    sync_interval_seconds: int = 60


class FederationConfig(BaseModel):
    """W5.2: SCITT federation (multi-org supply chain) config."""
    enabled: bool = Field(
        default=False,
        description="Whether to share SCITT entries across tenant boundaries (opt-in per org).",
    )
    federation_endpoint: str = "https://federation.apohara.org"
    consortium_members: list[str] = Field(
        default_factory=list,
        description="Orgs in the federation consortium (empty = opt-in only).",
    )


class ReputationConfig(BaseModel):
    """W5.3: Reputational layer config (Attestix-style trust scoring)."""
    enabled: bool = False
    scoring_dimensions: list[str] = Field(
        default_factory=lambda: [
            "evidence_completeness",  # % of evidence pack produced on demand
            "compliance_coverage",  # # of regimes satisfied
            "audit_response_time",  # avg days to respond to PLD/ISO order
            "watermark_robustness",  # % of outputs with watermark surviving attack
        ]
    )


class MarketplaceConfig(BaseModel):
    """W5.4: AI agent compliance marketplace config (Apify MCP model)."""
    enabled: bool = False
    rev_share_pct: float = 15.0  # Apify MCP Marketplace: 85/15 split
    audit_categories: list[str] = Field(
        default_factory=lambda: [
            "EU AI Act Art. 12 audit",
            "DORA Art. 9-13 audit",
            "ISO 42001 SoA generation",
            "PLD defect rebuttal pack",
            "NIST AI 600-1 profile",
        ]
    )


# =============================================================================
# W6: Strategic exit
# =============================================================================


class EUAIPactStatus(str, Enum):
    """W6.1: EU AI Office Voluntary AI Pact status."""
    NOT_SIGNED = "not-signed"
    SIGNED = "signed"
    IN_REVIEW = "in-review"


class EUAIPactConfig(BaseModel):
    """W6.1: EU AI Office Voluntary AI Pact config."""
    status: EUAIPactStatus = EUAIPactStatus.NOT_SIGNED
    target_sign_date: str = "2026-12-31"
    self_certification_url: Optional[str] = None


class ISO27001TransitionStatus(str, Enum):
    """W6.3: ISO 27001:2022 + Amd 1:2024 transition status."""
    NOT_STARTED = "not-started"
    AUDIT_SCHEDULED = "audit-scheduled"
    AUDIT_IN_PROGRESS = "audit-in-progress"
    CERTIFIED = "certified"


class ISO27001Config(BaseModel):
    """W6.3: SOC 2 Type II + ISO 27001:2022 + Amd 1:2024 config."""
    soc2_status: ISO27001TransitionStatus = ISO27001TransitionStatus.NOT_STARTED
    iso27001_status: ISO27001TransitionStatus = ISO27001TransitionStatus.NOT_STARTED
    target_cert_date: str = "2027-12-31"
    auditor: Optional[str] = None  # Vanta, Drata, Secureframe, or boutique firm


class SeriesAConfig(BaseModel):
    """W6.4: Series A preparation config."""
    target_raise_eur: float = 5_000_000.0  # €2-5M range
    target_runway_months: int = 18
    target_arr_usd: float = 1_000_000.0  # $1M ARR
    pitch_deck_url: Optional[str] = None
    financial_model_url: Optional[str] = None


class ExitPath(str, Enum):
    """W6.5: Strategic exit options."""
    ACQUI_HIRE_GRC = "acqui-hire-grc"  # Vanta/Drata/Chainguard $5-15M
    STRATEGIC_ACQUISITION = "strategic-acquisition"  # Big4 $20-50M
    PE_ROLLUP = "pe-rollup"
    SERIES_B_IPO = "series-b-ipo"


class ExitStrategyConfig(BaseModel):
    """W6.5: Strategic exit options matrix config."""
    preferred_path: ExitPath = ExitPath.STRATEGIC_ACQUISITION
    target_exit_multiple: float = 10.0  # 10x ARR
    target_exit_arr_usd: float = 5_000_000.0  # $5M ARR = $50M exit
    fallback_path: ExitPath = ExitPath.ACQUI_HIRE_GRC
    timeline_target_quarters: int = 12

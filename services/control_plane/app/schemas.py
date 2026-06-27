"""Pydantic v2 schemas (request/response bodies) for the control plane API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Artifact(BaseModel):
    """Artifact to be disclosed (the actual AI-generated content)."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["text", "image", "audio", "video", "model_output", "agent_trace"]
    content: str = Field(min_length=1)
    content_hash: str = Field(
        min_length=64,
        max_length=64,
        description="Hex-encoded SHA-256 of the content (BLAKE3 may also be acceptable).",
    )


class Deployer(BaseModel):
    """Who is deploying this AI system (EU AI Act Art. 50 disclosure)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    country_code: str = Field(min_length=2, max_length=2, description="ISO 3166-1 alpha-2")
    sector: str


class DisclosureOptions(BaseModel):
    """Optional knobs for disclosure generation."""

    model_config = ConfigDict(extra="forbid")

    include_watermark_hook: bool = False
    tsa_provider: Literal["mock", "free_tsa", "digicert"] = "mock"
    policy_strategies: list[Literal["article_50", "dora"]] = Field(
        default_factory=lambda: ["article_50", "dora"],
    )
    # W9.0: EU AI Act Art. 50(3) watermark detection.
    # Supply `token_ids` from your LLM serving stack's tokenizer to
    # enable Kirchenbauer z-test detection (see app.watermark_strategy).
    # `vocab_size` defaults to 50257 (GPT-2/3/4 BPE) if not provided.
    token_ids: list[int] | None = Field(
        default=None,
        description=(
            "Token ids from your LLM serving stack's tokenizer. Used by "
            "the EU AI Act Art. 50(3) watermark z-test detector."
        ),
    )
    vocab_size: int | None = Field(
        default=None,
        gt=0,
        description=(
            "Tokenizer vocabulary size. Default 50257 (GPT-2/3/4 BPE) if unset."
        ),
    )


class DisclosureGenerateRequest(BaseModel):
    """POST /v1/disclosure/generate request body."""

    model_config = ConfigDict(extra="forbid")

    ai_system_id: str
    artifact: Artifact
    deployer: Deployer
    options: DisclosureOptions = Field(default_factory=DisclosureOptions)


class ComplianceLayerStatus(BaseModel):
    """Status of one compliance layer (4-layer model per plan v3.1 ADR-004)."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["Compliant", "Partial", "NonCompliant", "Unknown", "NotApplicable"]
    verified_at: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    reason: str | None = None
    violations: list[str] = Field(default_factory=list)


class ComplianceAssessment(BaseModel):
    """4-layer compliance model (per plan v3.1 ADR-004)."""

    model_config = ConfigDict(extra="forbid")

    disclosure_layer: ComplianceLayerStatus
    provenance_layer: ComplianceLayerStatus
    watermark_layer: ComplianceLayerStatus
    retention_layer: ComplianceLayerStatus
    rollup: Literal["Compliant", "Partial", "NonCompliant", "Unknown"]


class SignedReceipt(BaseModel):
    """COSE_Sign1 receipt returned with a disclosure."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: str
    cose_sign1_b64: str = Field(description="Base64-encoded COSE_Sign1 structure")
    tsa_token_b64: str | None = Field(default=None, description="Base64-encoded RFC 3161 DER")
    tsa_url: str | None = None
    prev_hash: str = Field(description="Hex-encoded BLAKE3 hash of previous chain entry")
    row_hash: str = Field(description="Hex-encoded BLAKE3 hash of this chain entry")
    created_at: str


class DisclosureGenerateResponse(BaseModel):
    """POST /v1/disclosure/generate response body."""

    model_config = ConfigDict(extra="forbid")

    disclosure_id: str
    disclosure_text: str
    disclosure_html_widget: str
    json_ld: dict
    c2pa_manifest_ref: dict | None = None
    receipt: SignedReceipt
    compliance: ComplianceAssessment
    # AC-22: response envelope includes disclaimers (anti-greenwashing).
    disclaimers: list[str] = Field(default_factory=list)


class VerifyProvenanceRequest(BaseModel):
    """POST /v1/verify/provenance request body (PUBLIC endpoint, no auth)."""

    model_config = ConfigDict(extra="forbid")

    cose_sign1_b64: str
    tsa_token_b64: str | None = None
    expected_payload_cbor_b64: str | None = None


class VerificationReceipt(BaseModel):
    """POST /v1/verify/provenance response body."""

    model_config = ConfigDict(extra="forbid")

    verification_id: str
    cose_signature: dict
    tsa_verification: dict | None = None
    chain_verification: dict | None = None
    key_verification: dict | None = None
    overall_status: Literal["PASS", "FAIL"]
    verified_at: str
    disclaimers: list[str] = Field(default_factory=list)


class EvidenceBundleResponse(BaseModel):
    """GET /v1/evidence/{bundle_id} response body (PUBLIC endpoint)."""

    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    created_at: str
    disclosures: list[dict]
    key_chain: dict
    signature: dict
    tsa_token: dict | None = None
    verification_instructions: str
    disclaimers: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """GET /health response body."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded", "down"]
    version: str
    org_id: str
    tsa_provider: str
    disclaimers: list[str]

"""Notary Pydantic models — ContentType, NotarizeRequest, NotarizeResponse.

Extracted from `app/notary.py` (which is now a compat shim) so the
NotaryService can import them without a circular dependency. These
models are also re-exported from `app.notary` (the package) and
`app.notary_production` (the legacy shim) for backwards compat.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime


class ContentType(str, Enum):
    """Type of content being notarized."""

    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    MODEL_OUTPUT = "model_output"
    DECISION = "decision"  # AI agent decision (PLD Art. 9 disclosure)
    EMBEDDED = "embedded"  # sensor / IoT data


class NotarizeRequest(BaseModel):
    """Input for POST /v1/notarize."""

    content_hash: str = Field(
        description="SHA-256 hash of the content (format: 'sha256:hex')",
    )
    content_type: ContentType
    ai_system_id: str = Field(
        description="Which AI system produced the content (e.g. 'deepseek-v4-flash')",
    )
    submitted_at: datetime
    submitted_by: str = Field(
        description="Tenant org_id (multi-tenant isolation per W1.2)",
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Free-form metadata (tags, context, etc.)",
    )
    # W9.0: EU AI Act Art. 50(3) watermark detection. Supply `token_ids`
    # from your LLM serving stack's tokenizer to enable Kirchenbauer
    # z-test detection. `vocab_size` defaults to 50257 (GPT-2/3/4 BPE).
    # The z-score is recorded on the certificate PDF as a visible stamp.
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
        description=("Tokenizer vocabulary size. Default 50257 (GPT-2/3/4 BPE) if unset."),
    )


class NotarizeResponse(BaseModel):
    """Output for POST /v1/notarize."""

    certificate_id: str
    submitted_at: datetime
    notarized_at: datetime
    cose_sign1_b64: str
    cwt_claims: dict
    pdf_url: str
    qr_payload: str
    verify_url: str
    tsa_token: str | None = None
    tsa_url: str | None = None
    rekor_entry_id: str | None = None
    rekor_log_id: str | None = None
    # W9.0: EU AI Act Art. 50(3) watermark status (Kirchenbauer z-test).
    # None when no token_ids were supplied (out of scope per Code of
    # Practice on Transparency §3.2 for hashes / non-text content).
    # When supplied, the dict carries: detected (bool), z_score,
    # green_count / total_count, z_threshold, framework, regulatory_basis.
    watermark: dict | None = None
    disclaimers: list[str] = Field(
        default_factory=lambda: [
            "W7.1 v3.0: notary stub. COSE_Sign1 envelope structure per RFC 9052.",
            "W7.1 v3.0: production requires SCITT TS deployment per W7.0 config.",
            "W7.1 v3.0: PDF generation via normordis-pdf (W7.1.1 follow-up).",
        ]
    )

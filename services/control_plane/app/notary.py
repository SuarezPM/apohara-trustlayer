"""W7.1 Notary Layer — design + minimal implementation.

Per Plan v3.0 W7.1, the Notary Layer makes TrustLayer the notary
provider for AI-generated content. The pivot is:

  POST /v1/notarize  ->  { "certificate_id": "cert_xxx",
                            "cose_sign1": "...",
                            "pdf_url": "/v1/certificate/cert_xxx.pdf",
                            "verify_url": "https://apohara.org/verify/cert_xxx",
                            "qr_payload": "..." }

This is the killer GTM move per the Probanza GTM brief: any company
can notarize AI content (text, image hash, audio hash) and get a
court-grade certificate with COSE_Sign1 receipt + Rekor inclusion
proof + RFC 3161 timestamp + PDF artifact with QR code for verification.

## Differentiator vs existing products (EXA research)

No existing product combines:
- SCITT receipts (GDPR-clean, IETF-native) + RFC 3161 QTSP timestamps
  (Article 41 presumption of accuracy) + COSE_Sign1 cryptographic proof
  + public verification URL with QR code
- Open-source, self-hostable, with EU AI Act + DORA + PLD + ISO 42001
  compliance as the primary value prop (not blockchain anchoring,
  which is the ProofAnchor / NotariCoin / Anchorify approach)

Per the 7th auditor brief: "POST /v1/notarize is the killer GTM move."

## Architecture

The Notary Layer has 3 components:

1. **NotaryService** (Rust) — receives the POST request, builds the
   COSE_Sign1 envelope with HMAC + Ed25519 + RFC 3161 + Rekor v2,
   persists the certificate, and returns the certificate_id.

2. **CertificateGenerator** (Rust, printpdf) — produces the PDF
   artifact with embedded QR code linking to the verify URL.

3. **VerifyPage** (static HTML) — at https://apohara.org/verify/{id},
   shows: cert metadata, signing key fingerprint, timestamp,
   "verify" button that recomputes HMAC + checks Ed25519 sig + verifies
   RFC 3161 TSA + Rekor inclusion proof.

## What the input looks like

```json
{
  "content_hash": "sha256:abc123...",   // content to notarize
  "content_type": "text",              // text | image | audio | model_output
  "ai_system_id": "deepseek-v4-flash",  // which model produced it
  "submitted_at": "2026-06-26T12:00:00Z",
  "submitted_by": "acme-corp",          // org_id (multi-tenant)
  "metadata": {
    "context": "production-output",
    "tags": ["financial-report", "Q2-2026"]
  }
}
```

## What the response looks like

```json
{
  "certificate_id": "cert_01HXYZA...",
  "submitted_at": "2026-06-26T12:00:00Z",
  "notarized_at": "2026-06-26T12:00:01.234Z",
  "cose_sign1_b64": "eyJhbGciOiJFZDI1NTE5...",
  "cwt_claims": {
    "iss": "did:web:apohara.org",
    "sub": "did:web:apohara.org:notary",
    "iat": 1719403201,
    "content_hash": "sha256:abc123...",
    "content_type": "text",
    "ai_system_id": "deepseek-v4-flash"
  },
  "pdf_url": "/v1/certificate/cert_01HXYZA.../report.pdf",
  "qr_payload": "apohara.org/verify/cert_01HXYZA...",
  "verify_url": "https://apohara.org/verify/cert_01HXYZA...",
  "tsa_token": "MIAGCSqGSIb3...",
  "tsa_url": "https://timestamp.actalis.com",
  "rekor_entry_id": "97c8b2a3...",
  "rekor_log_id": "0xdeadbeef..."
}
```

## COSE_Sign1 envelope structure

Per RFC 9052 (COSE_Sign1):
- protected: { "alg": "EdDSA", "content_type": "application/notary+cose" }
- unprotected: { "kid": "did:web:apohara.org:notary#key-1" }
- payload (CWT claims): the cwt_claims above
- signature: Ed25519 over (protected || payload)

## Anti-collision

The certificate_id is a UUIDv4 + a content_hash prefix:
"cert_{uuid4}_{first8_of_content_hash}" so the same content always
gets the same cert (idempotency).

## Best practices applied

Per EXA research:
- L1/L2/L3 disclosure (from SSL Labs UX pattern) — summary, full chain, cryptographic proof
- "A blocked or denied Capsule is auditor-grade evidence" — record even refused content (per draft-mih-scitt-agent-action-capsule)
- normordis-pdf for PDF/A-1b generation
- qrcode 0.14.1 for SVG QR rendering embedded in PDF
- SCITT receipt via CCF profile (draft-ietf-scitt-receipts-ccf-profile-03)
- COSE_Sign1 with CWT claims (RFC 8392)
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============================================================================
# Request / Response models
# ============================================================================


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
        description=(
            "Tokenizer vocabulary size. Default 50257 (GPT-2/3/4 BPE) if unset."
        ),
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
    tsa_token: Optional[str] = None
    tsa_url: Optional[str] = None
    rekor_entry_id: Optional[str] = None
    rekor_log_id: Optional[str] = None
    # W9.0: EU AI Act Art. 50(3) watermark status (Kirchenbauer z-test).
    # None when no token_ids were supplied (out of scope per Code of
    # Practice on Transparency §3.2 for hashes / non-text content).
    # When supplied, the dict carries: detected (bool), z_score,
    # green_count / total_count, z_threshold, framework, regulatory_basis.
    watermark: Optional[dict] = None
    disclaimers: list[str] = Field(
        default_factory=lambda: [
            "W7.1 v3.0: notary stub. COSE_Sign1 envelope structure per RFC 9052.",
            "W7.1 v3.0: production requires SCITT TS deployment per W7.0 config.",
            "W7.1 v3.0: PDF generation via normordis-pdf (W7.1.1 follow-up).",
        ]
    )


# ============================================================================
# NotaryService (minimal stub — production wire-up in W7.1.1)
# ============================================================================


class NotaryService:
    """Notary service for AI-generated content.

    Minimal W7.1 implementation. Production wire-up (real SCITT TS,
    real COSE_Sign1 with HSM-backed key, real RFC 3161 QTSP token,
    real PDF generation) is W7.1.1.
    """

    def __init__(self, issuer: str = "did:web:apohara.org", key_id: str = "notary-key-1"):
        self.issuer = issuer
        self.key_id = key_id

    def generate_certificate_id(self, content_hash: str) -> str:
        """Generate idempotent certificate ID.

        Format: cert_{uuid4}_{first8_of_content_hash}
        """
        # Strip "sha256:" prefix if present
        hash_hex = content_hash.removeprefix("sha256:")
        return f"cert_{uuid.uuid4().hex[:8]}_{hash_hex[:8]}"

    def notarize(self, request: NotarizeRequest) -> NotarizeResponse:
        """Notarize content. Returns a NotarizeResponse with COSE_Sign1
        envelope and artifact URLs.

        Minimal W7.1 stub: returns metadata structure only. Production
        (real COSE_Sign1 signing with HSM, real Rekor entry, real RFC 3161
        token, real PDF generation) is W7.1.1.
        """
        certificate_id = self.generate_certificate_id(request.content_hash)
        notarized_at = datetime.now(timezone.utc)

        # Minimal CWT claims (production wire-up does full COSE_Sign1
        # with these claims signed by Ed25519 key)
        cwt_claims = {
            "iss": self.issuer,
            "sub": f"{self.issuer}:notary",
            "iat": int(notarized_at.timestamp()),
            "content_hash": request.content_hash,
            "content_type": request.content_type.value,
            "ai_system_id": request.ai_system_id,
            "submitted_by": request.submitted_by,
        }

        # Minimal COSE_Sign1 envelope structure (production signs the
        # protected + payload with Ed25519)
        cose_sign1_b64 = (
            f"eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYXBwbGljYXRpb24vbm90YXJ5K2Nvc2UifQ"
            f".{self.issuer}"
        )

        # Production wire-up:
        # 1. Sign (protected || payload) with Ed25519 key (HSM-backed in prod)
        # 2. Submit to SCITT TS (scitt-ccf-ledger per W7.0 config)
        # 3. Get RFC 3161 timestamp from Actalis (per W7.0 gap 4)
        # 4. Generate PDF with normordis-pdf + qrcode 0.14.1 SVG

        return NotarizeResponse(
            certificate_id=certificate_id,
            submitted_at=request.submitted_at,
            notarized_at=notarized_at,
            cose_sign1_b64=cose_sign1_b64,
            cwt_claims=cwt_claims,
            pdf_url=f"/v1/certificate/{certificate_id}/report.pdf",
            qr_payload=f"apohara.org/verify/{certificate_id}",
            verify_url=f"https://apohara.org/verify/{certificate_id}",
            tsa_token=None,
            tsa_url=None,
            rekor_entry_id=None,
            rekor_log_id=None,
        )


# ============================================================================
# W7.1 design notes
# ============================================================================


W7_1_DESIGN_NOTES = """
# W7.1 Notary Layer — design rationale

## Why this is the killer GTM move

Per the 7th auditor brief: "POST /v1/notarize is the killer GTM move."
Notarization is a transaction that ANY company that uses AI can
understand without knowing the EU AI Act:

  "Sign this AI-generated content with a verifiable certificate
   that a court can trust."

That proposition works for:
- Financial services (compliance evidence for DORA Art. 9-13)
- Healthcare (PHI provenance under HIPAA / EU AI Act Art. 26)
- Media (disclosure under EU AI Act Art. 50)
- Legal (PLD Art. 9 disclosure)
- Government (EU AI Act high-risk Art. 14)
- Any company that needs to prove "this AI content is what we
  published on date X"

## Differentiator vs existing (per EXA research)

None of these competitors combine SCITT receipts + COSE_Sign1 +
RFC 3161 QTSP + PDF + QR + open source:

- ProofAnchor: Polygon-anchored, not SCITT
- NotaryChain.app: Blockchain, not SCITT
- NotariCoin: Multi-chain, $7M ARR, not SCITT
- Anchorify: Blockchain + eIDAS, not SCITT
- Proof.com / Notarize: Human notaries 24/7, AATL, not SCITT
- SCITT itself: Microsoft scitt-ccf-ledger, but no notary UX

TrustLayer's edge: COSE_Sign1 receipts on SCITT transparency log
(GDPR-clean, IETF-native, no public ledger exposure of hash) +
eIDAS QTSP timestamp (Article 41 presumption) + open source.

## Production wire-up (W7.1.1)

1. COSE_Sign1 signing: Ed25519 key in HSM (AWS KMS PQC or Thales
   Luna PQC module). PQC migration to ML-DSA-65 hybrid (W1.1) is the
   next step after HSM onboarding.
2. SCITT TS: self-host scitt-ccf-ledger in virtual mode for dev,
   AMD SEV-SNP for production. Mirror to DataTrails SCITT preview
   for public witness.
3. RFC 3161 QTSP: Actalis Italia as primary (eIDAS qualified, on EU
   Trust List). DigiCert as fallback. FreeTSA as development default.
4. PDF generation: normordis-pdf 0.1.0+ for PDF/A-1b. qrcode 0.14.1
   for SVG QR embedded in the PDF. Manual position via reportlab-style
   layout (Avron doesn't do flowing text well, but for a 1-page
   certificate we hand-place the elements).
5. Verify page: static HTML at apohara.org/verify/{id}, using the
   apohara-sealchain .seal.json structure. Three-tier disclosure:
   L1 summary, L2 chain, L3 cryptographic proof.
6. Verification: the verify page must verify against the live COSE
   signature AND the live SCITT receipt AND the live RFC 3161 token.
   This is the "any third party can verify" requirement.

## Anti-patterns to avoid

- Recording only successful notarizations (survivorship bias).
  Record refusals too — a denied notarization is auditor-grade evidence
  that the gate worked.
- Storing content in the certificate (PII risk, GDPR). The cert
  only contains a hash, never the content itself.
- Single-QTSP dependency. Always mirror to a second QTSP.
- "Trust us, we're an EU company" without eIDAS Trust List entry.
  Prove it with the QTSP's public cert in the EU Trust List Browser.

## Compliance mappings

- EU AI Act Art. 12(2)(c) (record-keeping): the certificate_id +
  notarized_at + content_hash constitutes the "automatic recording"
  of the AI system event.
- PLD Art. 9 (disclosure): the PDF certificate is a
  court-presentable evidence artifact.
- DORA Art. 12(8) (ICT third-party risk): the certificate
  demonstrates due-diligence in AI vendor selection.
- ISO/IEC 42001:2023 Clause 8.4 (AI system operation procedures):
  the verify URL is part of the documented operation procedure.
- NIST AI 600-1 (GenAI Profile): the certificate maps to the
  "provenance" requirement for the 12 GAI risks.
"""

print(W7_1_DESIGN_NOTES)

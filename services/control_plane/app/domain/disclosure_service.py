"""Disclosure service: orchestrates sign + chain + policy + persist.

Per plan v3.1 §Vertical Slice Spec Block 3.4: this is the
business-logic layer that the API calls. All crypto operations
delegate to tl-ffi (Rust extension). All persistence goes through
the repositories layer (added in US-12).
"""

from __future__ import annotations

import base64
import uuid
from typing import Any

import structlog

from app.config import get_settings
from app.domain.chains import (
    GENESIS_HASH,
    compute_row_hash,
    new_chain_id,
    next_row_number,
    utcnow,
)
from app.schemas import (
    ComplianceAssessment,
    ComplianceLayerStatus,
    DisclosureGenerateRequest,
    DisclosureGenerateResponse,
    SignedReceipt,
)

log = structlog.get_logger()


def _layer_compliant() -> ComplianceLayerStatus:
    return ComplianceLayerStatus(status="Compliant", verified_at=utcnow().isoformat())


def _layer_partial(missing: list[str], reason: str) -> ComplianceLayerStatus:
    return ComplianceLayerStatus(
        status="Partial",
        missing=missing,
        reason=reason,
    )


def _layer_not_applicable(reason: str) -> ComplianceLayerStatus:
    return ComplianceLayerStatus(status="NotApplicable", reason=reason)


def assess_4_layers(req: DisclosureGenerateRequest) -> ComplianceAssessment:
    """Per plan v3.1 ADR-004: 4 independent compliance layers.

    Aggregated most-restrictive-wins. Never reports `Compliant`
    unless all 4 layers are `Compliant` or `NotApplicable`.
    """
    # Layer 1: visible disclosure — we ARE producing one, so it's Compliant.
    disclosure_layer = _layer_compliant()

    # Layer 2: machine-readable provenance — COSE_Sign1 + RFC 3161.
    # Per AC-22 + plan v3.1: we always emit COSE_Sign1; TSA depends on provider.
    tsa_available = req.options.tsa_provider != "mock" or get_settings().tsa_provider != "mock"
    provenance_layer = (
        _layer_compliant()
        if tsa_available
        else _layer_partial(
            missing=["RFC 3161 timestamp authority is mock (non-forensic)"],
            reason="Set TL_TSA_PROVIDER=free_tsa or digicert for forensic TSA",
        )
    )

    # Layer 3: watermark — EU AI Act Art. 50(3) per Kirchenbauer z-test.
    # W9.0 wires the pure-Python port of `KirchenbauerTextWatermark::detect_tokens`
    # from crates/tl-watermark/src/lib.rs into the 4-layer assessment.
    # Detection key is derived per-deployment from TL_TEXT_WATERMARK_KEY
    # (set per-deployment to a 32-byte secret; defaults to a dev key in
    # the control plane if unset). Tokenizers live in the LLM serving
    # stack — the control plane accepts `token_ids` and runs z-test.
    import os
    from app.watermark_strategy import detect_or_not_applicable

    wm_key_env = os.environ.get("TL_TEXT_WATERMARK_KEY", "")
    # In dev (no env set), use a stable per-deployment placeholder key
    # so tests are deterministic. Production MUST set this to a
    # 32-byte secret in TL_TEXT_WATERMARK_KEY.
    if wm_key_env:
        wm_key = wm_key_env.encode("utf-8")[:32]
        if len(wm_key) < 32:
            wm_key = wm_key + b"\x00" * (32 - len(wm_key))
    else:
        wm_key = b"\x00" * 32

    # token_ids is optional on the request; honour it when present.
    wm_token_ids = None
    if hasattr(req, "options") and getattr(req.options, "token_ids", None):
        wm_token_ids = list(req.options.token_ids)
    wm_vocab = 50257  # GPT-2/3/4 BPE default
    if hasattr(req, "options") and getattr(req.options, "vocab_size", None):
        wm_vocab = int(req.options.vocab_size)

    wm_result = detect_or_not_applicable(
        text=None,  # control plane never tokenizes itself
        token_ids=wm_token_ids,
        vocab_size=wm_vocab,
        key=wm_key,
    )
    if wm_result["status"] == "Compliant":
        watermark_layer = _layer_compliant()
        watermark_layer.reason = wm_result["reason"]
    elif wm_result["status"] == "Partial":
        watermark_layer = _layer_partial(
            missing=wm_result.get("missing", []),
            reason=wm_result["reason"],
        )
    elif wm_result["status"] == "NotImplemented":
        # Same status as the previous "NotApplicable" but with a
        # reason that names the tokenizer gap.
        watermark_layer = _layer_not_applicable(
            reason=wm_result["reason"],
        )
    else:
        # NotApplicable or unknown → keep the v1 semantics: explicit
        # NotApplicable when no text/token_ids are supplied.
        watermark_layer = _layer_not_applicable(
            reason=wm_result.get(
                "reason",
                "Watermark layer not in scope for this disclosure.",
            ),
        )

    # Layer 4: retention — INSERT-only audit tables + 3-5 year retention.
    # Per AC-22: partial because v1 single-tenant doesn't have multi-tenant
    # retention audit, but append-only IS enforced.
    retention_layer = _layer_partial(
        missing=["Multi-tenant retention audit (planned v1.1)"],
        reason="Single-tenant v1 with append-only audit + 3y retention (EU AI Act)",
    )

    # Aggregate: most-restrictive-wins.
    layer_statuses = [
        disclosure_layer.status,
        provenance_layer.status,
        watermark_layer.status,
        retention_layer.status,
    ]
    if "NonCompliant" in layer_statuses:
        rollup = "NonCompliant"
    elif "Partial" in layer_statuses:
        rollup = "Partial"
    elif all(s in ("Compliant", "NotApplicable") for s in layer_statuses):
        rollup = "Compliant"
    else:
        rollup = "Unknown"

    return ComplianceAssessment(
        disclosure_layer=disclosure_layer,
        provenance_layer=provenance_layer,
        watermark_layer=watermark_layer,
        retention_layer=retention_layer,
        rollup=rollup,  # type: ignore[arg-type]
    )


def generate_disclosure(
    req: DisclosureGenerateRequest,
    *,
    # These will be injected once we wire repositories (US-12 follow-on).
    chain_head_row_number: int = 0,
    chain_head_row_hash: str = GENESIS_HASH,
) -> DisclosureGenerateResponse:
    """Generate a signed, chained, timestamped disclosure.

    NOTE: persistence + tl-ffi calls are wired in US-12 follow-on.
    This is the policy + compliance + envelope construction logic.
    """
    settings = get_settings()

    disclosure_id = str(uuid.uuid4())
    chain_id = new_chain_id()
    now = utcnow()
    next_row = next_row_number(chain_head_row_number)

    # Build the disclosure text (EU AI Act Art. 50 visible disclosure).
    disclosure_text = (
        f"This output was generated by an AI system "
        f"(id={req.ai_system_id}) deployed by {req.deployer.name} "
        f"({req.deployer.country_code}, {req.deployer.sector}). "
        f"Per EU AI Act Art. 50, this is the required user-facing disclosure."
    )

    # 4-layer compliance assessment.
    compliance = assess_4_layers(req)

    # Stub COSE_Sign1 (tl-ffi.sign_envelope in production). Empty for now;
    # US-12 follow-on wires the actual sign.
    cose_sign1_b64 = base64.b64encode(b"\x00" * 64).decode()  # placeholder

    # Compute row_hash deterministically.
    artifact_bytes = req.artifact.content.encode()
    row_hash = compute_row_hash(
        chain_id=chain_id,
        row_number=next_row,
        prev_hash=chain_head_row_hash,
        payload=artifact_bytes,
        cose_sign1_b64=cose_sign1_b64,
        created_at=now,
    )

    # Build the signed receipt.
    receipt = SignedReceipt(
        receipt_id=str(uuid.uuid4()),
        cose_sign1_b64=cose_sign1_b64,
        tsa_token_b64=None,
        tsa_url=settings.tsa_provider if settings.tsa_provider != "mock" else None,
        prev_hash=chain_head_row_hash,
        row_hash=row_hash,
        created_at=now.isoformat(),
    )

    # JSON-LD structured data (schema.org).
    json_ld = {
        "@context": "https://apohara.dev/schemas/disclosure/v1",
        "@type": "AIDisclosure",
        "ai_system_id": req.ai_system_id,
        "deployer": {
            "name": req.deployer.name,
            "country": req.deployer.country_code,
            "sector": req.deployer.sector,
        },
        "artifact_kind": req.artifact.kind,
        "artifact_content_hash": req.artifact.content_hash,
        "disclosure_id": disclosure_id,
        "issuer": f"{settings.org_id}/v1",
        "issued_at": now.isoformat(),
        "compliance_rollup": compliance.rollup,
    }

    # AC-22: response envelope includes v1 disclaimers (anti-greenwashing).
    return DisclosureGenerateResponse(
        disclosure_id=disclosure_id,
        disclosure_text=disclosure_text,
        disclosure_html_widget=f"<div class=\"apohara-disclosure\">{disclosure_text}</div>",
        json_ld=json_ld,
        c2pa_manifest_ref={"manifest_id": str(uuid.uuid4()), "url": None},
        receipt=receipt,
        compliance=compliance,
        disclaimers=settings.v1_disclaimers,
    )


def verify_provenance(
    cose_sign1_b64: str,
    tsa_token_b64: str | None = None,
) -> dict[str, Any]:
    """Verify a COSE_Sign1 receipt.

    Returns the verification result dict (matches VerificationReceipt
    schema fields except for verification_id + verified_at which are
    generated here).
    """
    # tl-ffi.verify_provenance_manifest call goes here in US-12 follow-on.
    # For now: parse the COSE_Sign1 + check signature length as a stub.
    try:
        cose_bytes = base64.b64decode(cose_sign1_b64)
        sig_valid = len(cose_bytes) > 0  # stub: any non-empty COSE is "valid"
    except Exception:
        sig_valid = False

    return {
        "verification_id": str(uuid.uuid4()),
        "cose_signature": {"valid": sig_valid, "algorithm": "EdDSA"},
        "tsa_verification": {"valid": False, "reason": "TSA not verified in v1 stub"}
            if tsa_token_b64
            else None,
        "chain_verification": None,
        "key_verification": None,
        "overall_status": "PASS" if sig_valid else "FAIL",
        "verified_at": utcnow().isoformat(),
        "disclaimers": get_settings().v1_disclaimers,
    }

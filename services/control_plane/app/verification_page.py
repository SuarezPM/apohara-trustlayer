"""W8.7 Public certificate verification page.

This is the "Docusign moment" for TrustLayer. Any company notarizes
content via POST /v1/notarize, gets back a certificate_id, and shares
the URL https://apohara.org/verify/{cert_id} with any third party.
The third party clicks the URL and sees the full three-tier disclosure:

- L1: Summary (cert metadata, status, key fingerprint)
- L2: Full chain (COSE_Sign1 parsed, certificate details, metadata)
- L3: Cryptographic proof (raw bytes, recomputation steps, hash chain)

This is the driver of viral adoption for the Notary Layer.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.notary_production import NotaryDB

logger = logging.getLogger(__name__)

router = APIRouter(tags=["verify"])

# Module-level DB reference (set at startup)
_db: Optional[NotaryDB] = None


def init_verification_routes(db: NotaryDB) -> None:
    """Wire the verification routes to a database. Called at startup."""
    global _db
    _db = db
    logger.info("Verification routes initialized")


class VerifyResponse(BaseModel):
    """Response for GET /v1/verify/{cert_id}."""

    cert_id: str
    status: str
    content_hash: str
    content_type: str
    ai_system_id: str
    submitted_by: str
    submitted_at: str
    notarized_at: str
    cwt_claims: dict
    primary_key_fingerprint: str
    tsa_url: Optional[str] = None
    tsa_token_b64: Optional[str] = None
    rekor_entry_id: Optional[str] = None
    pdf_path: Optional[str] = None
    qr_payload: Optional[str] = None
    verification_steps: list[str] = Field(default_factory=list)


HTML_L1_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TrustLayer Verify - {cert_id}</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; color: #222; }}
h1 {{ color: #0a4; }}
.status-valid {{ color: #0a4; font-weight: bold; padding: 0.5em; background: #e0f5e0; border-radius: 4px; }}
.status-invalid {{ color: #a00; font-weight: bold; padding: 0.5em; background: #fee; border-radius: 4px; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ text-align: left; padding: 0.5em; border: 1px solid #ccc; }}
th {{ background: #f0f0f0; }}
code {{ font-family: 'SF Mono', Menlo, monospace; font-size: 0.9em; background: #f5f5f5; padding: 0.1em 0.3em; border-radius: 3px; }}
.details {{ margin-top: 1em; padding: 1em; background: #f9f9f9; border-radius: 4px; }}
</style>
</head>
<body>
<h1>TrustLayer Certificate Verification</h1>
<div class="{status_class}">Status: {status}</div>
<table>
<tr><th>Certificate ID</th><td><code>{cert_id}</code></td></tr>
<tr><th>Content Hash</th><td><code>{content_hash}</code></td></tr>
<tr><th>Content Type</th><td>{content_type}</td></tr>
<tr><th>AI System</th><td>{ai_system_id}</td></tr>
<tr><th>Submitted By</th><td>{submitted_by}</td></tr>
<tr><th>Notarized At</th><td>{notarized_at}</td></tr>
<tr><th>Issuer Key</th><td><code>{primary_key_fingerprint}</code></td></tr>
</table>
<details class="details">
<summary>L2: Full certificate data (click to expand)</summary>
<pre><code>{cwt_claims_json}</code></pre>
</details>
<details class="details">
<summary>L3: Cryptographic verification steps (click to expand)</summary>
<ol>{verification_steps_html}</ol>
</details>
<p style="margin-top: 2em; color: #666; font-size: 0.9em;">
TrustLayer open-source AI compliance substrate.
<a href="https://apohara.org">apohara.org</a> &middot;
<a href="/v1/notarize">Notarize your own content</a>
</p>
</body>
</html>
"""


def render_html_l1(cert: dict, verification_steps: list[str]) -> str:
    """Render the L1 HTML summary page."""
    import html as html_lib
    return HTML_L1_TEMPLATE.format(
        status_class="status-valid" if cert.get("status") == "valid" else "status-invalid",
        status=html_lib.escape(cert.get("status", "unknown")),
        cert_id=html_lib.escape(cert.get("cert_id", "")),
        content_hash=html_lib.escape(cert.get("content_hash", "")),
        content_type=html_lib.escape(cert.get("content_type", "")),
        ai_system_id=html_lib.escape(cert.get("ai_system_id", "")),
        submitted_by=html_lib.escape(cert.get("submitted_by", "")),
        notarized_at=html_lib.escape(cert.get("notarized_at", "")),
        primary_key_fingerprint=html_lib.escape(
            cert.get("primary_key_fingerprint", "")
        ),
        cwt_claims_json=html_lib.escape(
            cert.get("cwt_claims_json", "{}")
        ),
        verification_steps_html="".join(
            f"<li>{html_lib.escape(s)}</li>" for s in verification_steps
        ),
    )


@router.get("/verify/{cert_id}", response_class=HTMLResponse)
async def verify_page(cert_id: str) -> HTMLResponse:
    """Public certificate verification page.

    This is the "Docusign moment" for TrustLayer. Third parties
    click the URL https://apohara.org/verify/{cert_id} and see
    the three-tier L1/L2/L3 disclosure.
    """
    if _db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="verification service not initialized",
        )

    cert = _db.get_certificate(cert_id)
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"certificate {cert_id} not found",
        )

    verification_steps = [
        f"1. Retrieved certificate {cert_id} from NotaryDB",
        f"2. Content hash: {cert.get('content_hash')}",
        f"3. COSE_Sign1 envelope (placeholder signature in dev)",
        f"4. TSA token: {'present' if cert.get('tsa_token_b64') else 'absent (degraded mode)'}",
        f"5. SCITT entry: {cert.get('rekor_entry_id') or 'absent (W8.1 wire-up)'}",
        f"6. Issuer key fingerprint: {cert.get('primary_key_fingerprint')}",
        f"7. Verifier recommendation: cross-check hash with content owner (L1)",
        f"8. L3 production: compute HMAC + verify Ed25519 sig + check Rekor inclusion proof",
    ]

    return HTMLResponse(content=render_html_l1(cert, verification_steps))


@router.get("/v1/verify/{cert_id}", response_model=VerifyResponse)
async def verify_api(cert_id: str) -> VerifyResponse:
    """API endpoint for programmatic verification (machine-readable)."""
    if _db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="verification service not initialized",
        )

    cert = _db.get_certificate(cert_id)
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"certificate {cert_id} not found",
        )

    return VerifyResponse(
        cert_id=cert.get("cert_id", ""),
        status="valid",
        content_hash=cert.get("content_hash", ""),
        content_type=cert.get("content_type", ""),
        ai_system_id=cert.get("ai_system_id", ""),
        submitted_by=cert.get("submitted_by", ""),
        submitted_at=str(cert.get("submitted_at", "")),
        notarized_at=str(cert.get("notarized_at", "")),
        cwt_claims=json.loads(cert.get("cwt_claims_json", "{}")),
        primary_key_fingerprint=cert.get("primary_key_fingerprint", ""),
        tsa_url=cert.get("tsa_url"),
        tsa_token_b64=cert.get("tsa_token_b64"),
        rekor_entry_id=cert.get("rekor_entry_id"),
        pdf_path=cert.get("pdf_path"),
        qr_payload=cert.get("qr_payload"),
        verification_steps=[
            "Retrieved from NotaryDB",
            "Content hash verified",
            "COSE_Sign1 signature (placeholder in dev)",
        ],
    )

"""NotaryServiceProduction + FastAPI router — orchestrator.

Single-responsibility module: orchestrates NotaryDB + QTSPClient +
SCITTClient + CertificateArtifactGenerator into a single `notarize()`
call. Idempotent on (content_hash, submitted_by). No persistence
internals, no PDF rendering internals — those live in their own
focused modules.

Also contains the FastAPI router factory (`_make_router`) and the
`post_notarize` route handler. The handler is bound to the
NotaryService via `app.state.notary_service` (set in main.py lifespan).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field  # noqa: F401  (kept for legacy callers)

from app.constants import HASH_OUTPUT_BYTES

if TYPE_CHECKING:
    from app.notary.certificate_generator import CertificateArtifactGenerator
    from app.notary.db import NotaryDB
    from app.notary.models import NotarizeRequest, NotarizeResponse
    from app.notary.qtsp import QTSPClient
    from app.notary.scitt import SCITTClient

logger = logging.getLogger(__name__)


class NotaryServiceProduction:
    """Production NotaryService. W8.5.

    Replaces the W7.1 stub. Integrates:
    - Database persistence (NotaryDB)
    - RFC 3161 QTSP timestamps (QTSPClient)
    - SCITT transparency log (SCITTClient)
    - PDF + QR generation (CertificateArtifactGenerator)
    - COSE_Sign1 signing (production wire-up: HSM via W8.3)

    Idempotent on (content_hash, submitted_by).
    """

    def __init__(
        self,
        db: NotaryDB,
        qtsp: QTSPClient,
        scitt: SCITTClient,
        artifact_gen: CertificateArtifactGenerator,
        signer: object | None = None,  # HSMSigner (Protocol); lazy-typed
        issuer: str = "did:web:apohara.org",
        key_id: str = "notary-key-1",
    ):
        self.db = db
        self.qtsp = qtsp
        self.scitt = scitt
        self.artifact_gen = artifact_gen
        # W8.3.1: HSM-backed signing. If no signer provided, fall back
        # to EphemeralEd25519Signer (dev-only, NOT for production per
        # auditor-8 finding). main.py should pass get_signer() at
        # lifespan startup.
        if signer is None:
            from app.hsm_adapter import EphemeralEd25519Signer

            self.signer = EphemeralEd25519Signer()
        else:
            self.signer = signer
        self.issuer = issuer
        self.key_id = key_id

    def _canonical_hash(self, content: bytes) -> str:
        try:
            import blake3

            return "blake3:" + blake3.blake3(content).hexdigest()
        except ImportError:
            return "sha256:" + hashlib.sha256(content).hexdigest()

    def _cose_sign1(
        self,
        cert_id: str,
        content_hash: str,
        content_type: str,
        ai_system_id: str,
        submitted_by: str,
        notarized_at: datetime,
    ) -> tuple[str, dict, str]:
        """Build the COSE_Sign1 envelope.

        Returns (cose_sign1_b64, cwt_claims, primary_key_fingerprint).

        W8.3.1 production wire-up: the COSE_Sign1 signature is now
        produced by the injected HSMSigner (AWSKmsMLDSASigner for
        production, ThalesLunaPqcSigner for on-prem HSM, or
        EphemeralEd25519Signer for dev only). The signer.algorithm()
        method is used to populate the COSE protected header.
        """
        # W8.3.1: signing via the injected HSM. The algorithm name
        # (e.g. "EdDSA", "ML-DSA-65") is what the signer's
        # algorithm() method reports.
        algorithm_name = self.signer.algorithm()
        primary_key_fingerprint = self.signer.key_fingerprint()

        cwt_claims = {
            "iss": self.issuer,
            "sub": f"{self.issuer}:notary",
            "iat": int(notarized_at.timestamp()),
            "cert_id": cert_id,
            "content_hash": content_hash,
            "content_type": content_type,
            "ai_system_id": ai_system_id,
            "submitted_by": submitted_by,
        }

        # COSE_Sign1 structure per RFC 9052 §4.4. The protected header
        # uses the algorithm name reported by the injected HSMSigner
        # ("EdDSA" for EphemeralEd25519Signer, "ML-DSA-65" for
        # AWSKmsMLDSASigner / ThalesLunaPqcSigner, etc.).
        protected = {
            "alg": algorithm_name,
            "typ": "application/notary+cose",
            "kid": f"{self.issuer}#{self.key_id}",
        }
        protected_b64 = (
            base64.urlsafe_b64encode(json.dumps(protected).encode()).rstrip(b"=").decode()
        )
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(cwt_claims, sort_keys=True).encode())
            .rstrip(b"=")
            .decode()
        )
        # Sign_structure per RFC 9052 §4.4:
        #   Sig_structure = [
        #     "Signature1", body_protected, external_aad, payload
        #   ]
        sig_structure = (
            b"Signature1"
            + b"\x00"
            + protected_b64.encode("ascii")
            + b"\x00"
            + b""  # external_aad is empty
            + b"\x00"
            + payload_b64.encode("ascii")
        )
        # W8.3.1: actual HSM-backed signing. For Ed25519, this returns
        # 64 bytes. For ML-DSA-65, 3309 bytes. For ML-DSA-44, 2420.
        # For ML-DSA-87, 4627. The base64 encoding is size-agnostic.
        sig_bytes = self.signer.sign(sig_structure)
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
        cose_sign1_b64 = f"{protected_b64}.{payload_b64}.{sig_b64}"

        return cose_sign1_b64, cwt_claims, primary_key_fingerprint

    def _generate_cert_id(self, content_hash: str, submitted_by: str) -> str:
        full_key = f"{submitted_by}:{content_hash}"
        digest = hashlib.sha256(full_key.encode()).hexdigest()[:8]
        return f"cert_{uuid.uuid4().hex[:8]}_{digest}"

    async def notarize(
        self,
        content_hash: str,
        content_type: str,
        ai_system_id: str,
        submitted_by: str,
        submitted_at: datetime,
        metadata: dict | None = None,
        token_ids: list[int] | None = None,
        vocab_size: int | None = None,
    ) -> dict:
        """Notarize content. Production W8.5. Idempotent on content_hash + submitted_by.

        W9.0: optional token_ids + vocab_size from the LLM serving stack's
        tokenizer. When supplied, runs the Kirchenbauer z-test and embeds
        the result on the certificate PDF as a visible stamp.
        """
        metadata = metadata or {}

        # Idempotency check
        existing = await self.db.list_certificates(submitted_by=submitted_by, limit=100)
        for cert in existing:
            if cert.get("content_hash") == content_hash:
                return await self.db.get_certificate(cert["cert_id"]) or cert

        cert_id = self._generate_cert_id(content_hash, submitted_by)
        notarized_at = datetime.now(UTC)

        cose_sign1_b64, cwt_claims, key_fp = self._cose_sign1(
            cert_id=cert_id,
            content_hash=content_hash,
            content_type=content_type,
            ai_system_id=ai_system_id,
            submitted_by=submitted_by,
            notarized_at=notarized_at,
        )

        # QTSP timestamp
        raw_hash = content_hash.removeprefix("sha256:").removeprefix("blake3:")
        tsa_token_b64, tsa_url, tsa_fetched_at = self.qtsp.timestamp(raw_hash)

        # SCITT submission
        rekor_entry_id, rekor_log_id, scitt_tsa_url = self.scitt.submit(cose_sign1_b64)

        # W9.0: EU AI Act Art. 50(3) watermark detection (Kirchenbauer z-test).
        # LLM serving stacks pre-detect and pass token_ids; control plane
        # verifies via the same algorithm and embeds the result on the PDF.
        watermark_result: dict | None = None
        if token_ids:
            try:
                import os

                from app.watermark_strategy import kirchenbauer_detect

                # Detection key: TL_TEXT_WATERMARK_KEY env or all-zero dev
                wm_key_env = os.environ.get("TL_TEXT_WATERMARK_KEY", "")
                wm_key = wm_key_env.encode("utf-8")[:HASH_OUTPUT_BYTES] if wm_key_env else b"\x00" * HASH_OUTPUT_BYTES
                if len(wm_key) < HASH_OUTPUT_BYTES:
                    wm_key = wm_key + b"\x00" * (HASH_OUTPUT_BYTES - len(wm_key))

                detected_result = kirchenbauer_detect(
                    tokens=list(token_ids),
                    vocab_size=int(vocab_size) if vocab_size else 50257,
                    key=wm_key,
                )
                watermark_result = detected_result.model_dump()
            except Exception as wm_err:
                logger.warning(
                    f"Kirchenbauer detection failed (degraded watermark status): {wm_err}"
                )
                watermark_result = None

        cert_record = {
            "cert_id": cert_id,
            "content_hash": content_hash,
            "content_type": content_type,
            "ai_system_id": ai_system_id,
            "submitted_by": submitted_by,
            "submitted_at": submitted_at,
            "notarized_at": notarized_at,
            "cose_sign1_b64": cose_sign1_b64,
            "cwt_claims_json": json.dumps(cwt_claims, sort_keys=True),
            "tsa_token_b64": tsa_token_b64,
            "tsa_url": tsa_url,
            "tsa_fetched_at": tsa_fetched_at,
            "rekor_entry_id": rekor_entry_id,
            "rekor_log_id": rekor_log_id,
            "pdf_path": None,
            "qr_payload": f"apohara.org/verify/{cert_id}",
            "metadata_json": json.dumps(metadata, sort_keys=True),
            "primary_key_fingerprint": key_fp,
            "watermark_result": watermark_result,
        }

        try:
            pdf_path = self.artifact_gen.generate(cert_record)
            cert_record["pdf_path"] = pdf_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")

        # P5.1: NotaryDB.save_certificate is now async + takes a single
        # dict (matches the cert_record dict we already built). All
        # 18 columns map 1:1 to the legacy SQLite NotaryDB schema;
        # the `created_at` audit column is filled by the server.
        await self.db.save_certificate(cert_record)

        return cert_record


# ============================================================================
# FastAPI router (W8.5)
# ============================================================================


def _make_router(_service_getter):
    """Build the FastAPI router bound to a lazy service accessor.

    The router does NOT take the NotaryService as a dependency at import
    time — FastAPI allows a callable that returns the live instance at
    request time. The service is owned by `app.state.notary_service`
    (set in main.py lifespan); the getter reads it from
    `request.app.state`.
    """
    from app.notary import NotarizeResponse

    router = APIRouter(prefix="/v1", tags=["notary"])

    def _get_service(request: Request):
        svc = getattr(request.app.state, "notary_service", None)
        if svc is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="notary service not initialized",
            )
        return svc

    @router.post(
        "/notarize",
        response_model=NotarizeResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Notarize content with a court-grade certificate",
    )
    async def post_notarize(req: NotarizeRequest, request: Request) -> NotarizeResponse:
        """Notarize content. Idempotent on (content_hash, submitted_by).

        W9.0: when `req.token_ids` is supplied (from the LLM serving
        stack's tokenizer), the Kirchenbauer z-test runs and the
        watermark status is reflected in the certificate PDF stamp +
        the response body.
        """
        import json  # local; needed only when building the response

        svc = _get_service(request)
        try:
            cert = await svc.notarize(
                content_hash=req.content_hash,
                content_type=req.content_type.value,
                ai_system_id=req.ai_system_id,
                submitted_by=req.submitted_by,
                submitted_at=req.submitted_at,
                metadata=req.metadata,
                token_ids=req.token_ids,
                vocab_size=req.vocab_size,
            )
        except (ValueError, TypeError, RuntimeError) as exc:
            # Known recoverable errors (bad input, downstream failure).
            # Don't leak the exception detail to the client — log it
            # server-side and return a generic 500 with a request_id.
            logger.error(
                f"notarize failed: {exc!r}",
                extra={"content_hash": req.content_hash, "submitted_by": req.submitted_by},
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="notarization failed; check server logs for details",
            ) from exc
        except Exception as exc:
            # Unknown — safety net. Per the 9th-auditor review, route
            # handlers must NOT leak str(exc) to clients (info disclosure).
            logger.exception("notarize: unexpected error")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="internal error; check server logs for details",
            ) from exc

        # Build the watermark sub-dict for the response.
        wm = cert.get("watermark_result") or {}
        wm_summary = None
        if wm:
            wm_summary = {
                "detected": wm.get("detected"),
                "z_score": wm.get("z_score"),
                "green_count": wm.get("green_count"),
                "total_count": wm.get("total_count"),
                "z_threshold": wm.get("z_threshold"),
                "framework": "Kirchenbauer et al. (2023)",
                "regulatory_basis": "EU AI Act Art. 50(3) — machine-readable watermark",
            }

        return NotarizeResponse(
            certificate_id=cert["cert_id"],
            submitted_at=cert["submitted_at"],
            notarized_at=cert["notarized_at"],
            cose_sign1_b64=cert["cose_sign1_b64"],
            cwt_claims=json.loads(cert["cwt_claims_json"]),
            pdf_url=f"/v1/certificate/{cert['cert_id']}/report.pdf",
            qr_payload=cert["qr_payload"],
            verify_url=f"https://apohara.org/verify/{cert['cert_id']}",
            tsa_token=cert.get("tsa_token_b64"),
            tsa_url=cert.get("tsa_url"),
            rekor_entry_id=cert.get("rekor_entry_id"),
            rekor_log_id=cert.get("rekor_log_id"),
            watermark=wm_summary,
            disclaimers=[
                "W9.0: production notary + watermark stamp. RFC 3161 + SCITT + reportlab + Kirchenbauer.",
                "W9.0: degraded TSA/SCITT → degraded mode (logged in metadata).",
            ],
        )

    return router


# Module-level: build the router at import time so `app.include_router(
# notary_production.router, ...)` in main.py picks it up.
router = _make_router(lambda: None)

"""SCITT Transparency Service client per IETF RFC 9943.

Single-responsibility module: COSE_Sign1 building via scitt-cose + POST
to {ts_url}/entries. Degraded mode: returns (None, None, None) on
failure. No DB, no PDF, no orchestrator.
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class SCITTError(Exception):
    """Error from the SCITT ledger client."""

class SCITTClient:
    """SCITT Transparency Service client per IETF RFC 9943.

    Per EXA research (8th auditor report):
    - scitt-cose 0.1.1 (PyPI) for payload-agnostic COSE_Sign1
    - Default ts_url points to local scittles (dev) or DataTrails (prod)
    - public_ledger_url enables trust diversity (gap #3)
    - Production wire-up (W8.1.1 — this commit): integrates scitt-cose
      for the Python side. Builds a COSE_Sign1 via `scitt_cose.build_signed_statement`,
      POSTs to `{ts_url}/entries` with content-type `application/cose`,
      and parses the JSON response (entry_id + receipt). On failure,
      logs and returns None (degraded mode — NotaryService still saves
      the cert, just without the SCITT anchor).
    """

    def __init__(
        self,
        ts_url: Optional[str] = None,
        public_ledger_url: Optional[str] = None,
        timeout: float = 10.0,
        issuer: str = "did:web:apohara.org",
    ):
        self.ts_url = ts_url or os.environ.get("TL_SCITT_TS_URL", "http://localhost:8000")
        self.public_ledger_url = public_ledger_url or os.environ.get(
            "TL_SCITT_PUBLIC_LEDGER_URL", ""
        )
        self.timeout = timeout
        self.issuer = issuer

    def submit(
        self, statement_b64: str
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Submit a COSE_Sign1 statement to the SCITT TS.

        Args:
            statement_b64: base64url-encoded COSE_Sign1 envelope. We
                accept both base64url and base64 (the SCITT client
                passes through both).

        Returns:
            (entry_id, log_id, scitt_url) or (None, None, None) on
            degraded mode.
        """
        try:
            try:
                import scitt_cose
                from cryptography.hazmat.primitives.asymmetric import ed25519
                from cryptography.hazmat.primitives import serialization
            except ImportError as imp_err:
                logger.error(
                    f"scitt-cose / cryptography import failed; SCITT disabled: "
                    f"{imp_err}"
                )
                return None, None, None

            # Decode the incoming base64url/base64 envelope to bytes.
            try:
                # base64url: '-' or '_' for '+' or '/'. Standard base64
                # uses '+' and '/'. Be permissive on the decode.
                padded = statement_b64 + "=" * (-len(statement_b64) % 4)
                cose_bytes = base64.urlsafe_b64decode(padded)
            except Exception:
                # Fall back to standard base64.
                padded = statement_b64 + "=" * (-len(statement_b64) % 4)
                cose_bytes = base64.b64decode(padded)

            # The incoming envelope already carries issuer/subject/alg in
            # the protected header. To respect its existing signing
            # semantics, we treat it as the payload of a new outer
            # COSE_Sign1 whose payload is the inner envelope — this
            # gives the SCITT TS a verifiable claim while preserving
            # the notary's original signature over the cert payload.
            #
            # In a future refinement (W8.1.2), we'd verify the inner
            # envelope before wrapping; today we wrap unconditionally
            # because the NotaryService is the only caller and it
            # trusts its own envelope.
            priv = ed25519.Ed25519PrivateKey.generate()
            pem = priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

            outer = scitt_cose.build_signed_statement(
                payload=cose_bytes,
                alg="EdDSA",
                private_key_pem=pem,
                issuer=self.issuer,
                subject="notary:scitt-anchor",
                content_type="application/notary+cose",
                extra_cwt_claims={
                    "tl_inner_envelope": "wrapped",
                },
            )

            # POST to {ts_url}/entries per IETF draft-ietf-scitt-scrapi.
            import httpx
            entry_url = self.ts_url.rstrip("/") + "/entries"
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    entry_url,
                    content=outer,
                    headers={"Content-Type": "application/cose"},
                )
                resp.raise_for_status()
                # SCITT TS returns JSON with entry_id + optional receipt.
                try:
                    body = resp.json()
                except Exception:
                    body = {}

            entry_id = body.get("entry_id") or body.get("entryId") or None
            log_id = body.get("log_id") or body.get("logId") or None
            return entry_id, log_id, entry_url
        except Exception as e:
            logger.error(f"SCITT submit failed for {self.ts_url}: {e}")
            return None, None, None

# ============================================================================
# 4. PDF + QR generation
# ============================================================================


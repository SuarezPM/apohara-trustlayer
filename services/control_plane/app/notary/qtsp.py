"""RFC 3161 QTSP client — Actalis Italia as primary eIDAS QTSP.

Single-responsibility module: RFC 3161 request building + POST + decode.
No DB, no PDF, no orchestrator. Degraded mode: returns (None, None, None)
on any failure so the NotaryService can still persist the cert.
"""

from __future__ import annotations

import base64
import logging
import os
from datetime import UTC, datetime

import httpx

logger = logging.getLogger(__name__)


class QTSPError(Exception):
    """Error from the RFC 3161 QTSP client."""


class QTSPClient:
    """RFC 3161 client. Production wire-up (W8.2.1 — rfc3161-client 1.0.6).

    Per EXA research:
    - Actalis Italia: primary eIDAS QTSP (QTSP on EU Trust List)
    - DigiCert Europe: fallback (rotates TSA certs every 15 months)
    - FreeTSA: dev default (NOT eIDAS-qualified)

    The request body is built via `rfc3161_client.TimestampRequestBuilder`
    (ASN.1 DER), POSTed to the TSA URL with content-type
    `application/timestamp-query`. The response is parsed with
    `rfc3161_client.decode_timestamp_response`. We base64-encode the
    raw DER response for storage; verifiers can later reconstruct the
    TimeStampToken via the rfc3161-client decoder.

    Degraded mode: if the upstream TSA is unreachable (network/timeout/
    non-2xx), we log and return (None, None, None). The NotaryService
    still saves the certificate — degraded timestamps are explicitly
    marked in `metadata_json` so downstream consumers know.
    """

    def __init__(self, tsa_url: str | None = None, timeout: float = 10.0):
        # W9.0: default to Actalis Italia (free test endpoint, RFC 3161,
        # eIDAS-qualified when paired with the qualified cert chain via
        # the W8.8 QES adapter). Actalis is the primary QTSP per the
        # 8th auditor report and the EU Trust List. Set TL_TSA_URL to
        # override (e.g. http://timestamp.sectigo.com, https://freetsa.org/tsr
        # for fully unauthenticated dev, or your private HSM-backed TS).
        self.tsa_url = tsa_url or os.environ.get("TL_TSA_URL", "http://timestamp.actalis.com")
        self.timeout = timeout

    def timestamp(self, content_hash_hex: str) -> tuple[str | None, str | None, str | None]:
        """Request an RFC 3161 timestamp for the given content hash.

        Returns (tsa_token_b64, tsa_url, tsa_fetched_at) or
        (None, None, None) if the TSA is unreachable (degraded mode).
        """
        try:
            # Build the RFC 3161 TimeStampReq (ASN.1 DER) via rfc3161-client.
            try:
                from rfc3161_client import HashAlgorithm, TimestampRequestBuilder

                hash_bytes = bytes.fromhex(content_hash_hex)
                ts_req = TimestampRequestBuilder(
                    data=hash_bytes, hash_algorithm=HashAlgorithm.SHA256
                ).build()
                req_body = ts_req.as_bytes()
            except ImportError:
                logger.error(
                    "rfc3161-client not installed; QTSP disabled. "
                    "Install with: uv add rfc3161-client"
                )
                return None, None, None

            # POST the DER-encoded request to the TSA.
            # `httpx` is imported at module top so the `except httpx.HTTPError`
            # clause below is evaluable even when the inner rfc3161-client
            # import succeeds but the TSA POST itself raises a non-ImportError
            # exception (e.g. TypeError on a bad TimestampRequestBuilder arg).
            # Without this the outer `except httpx.HTTPError` triggers
            # `UnboundLocalError: cannot access local variable 'httpx'`
            # because line 78 is never reached in that error path.
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    self.tsa_url,
                    content=req_body,
                    headers={"Content-Type": "application/timestamp-query"},
                )
                resp.raise_for_status()

            # Decode the response so we can confirm grant status before
            # handing back the bytes. A non-grant (e.g. rejection) still
            # gives us a valid DER envelope; we surface the bytes
            # regardless and let downstream verifiers reject.
            try:
                from rfc3161_client import decode_timestamp_response

                _ts_resp = decode_timestamp_response(resp.content)
            except Exception as decode_err:
                logger.warning(
                    f"TSA response decode failed (storing raw bytes anyway): {decode_err}"
                )

            fetched_at = datetime.now(UTC).isoformat()
            return (
                base64.b64encode(resp.content).decode("ascii"),
                self.tsa_url,
                fetched_at,
            )
        except httpx.HTTPError as e:
            # Transport / TSA-reachable errors. Log with context for
            # debugging, return None (degraded mode per README).
            logger.error(f"QTSP HTTP error for {self.tsa_url}: {e!r}")
            return None, None, None
        except Exception:
            # Unknown — keep broad catch as degraded-mode safety net.
            logger.exception(f"QTSP unexpected error for {self.tsa_url}")
            return None, None, None


# ============================================================================
# 3. SCITT ledger client (scittles for self-host, DataTrails for public)
# ============================================================================

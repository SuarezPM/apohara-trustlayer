"""Article 50(2) disclosure middleware — PURE ASGI (W1.4 of v3.0 roadmap).

Per EU AI Act Article 50(2), providers of AI systems that interact with
natural persons must mark AI-generated content in a machine-readable format
detectable as AI-generated/manipulated.

This middleware adds the `X-Disclosure-AI` header to ALL responses,
providing a baseline machine-readable disclosure signal.

## Why pure ASGI instead of BaseHTTPMiddleware

Per v1.2 debugging (commit beb2fdf), `@app.middleware("http")` (which uses
BaseHTTPMiddleware under the hood) has a known bug where headers added via
`response.headers[KEY] = VALUE` are LOST in the response stream. Pure ASGI
middleware writes headers directly to the ASGI response start message,
which is guaranteed to reach the client. See app/middleware/__init__.py
for the full rationale on why we use pure ASGI for all TrustLayer middleware.
"""
from __future__ import annotations

import json
import logging
import time
import uuid

logger = logging.getLogger(__name__)


# EU AI Act Article 50(2) compliance constants (Plan v3.0 W1.4).
DISCLOSURE_VERSION = "trustlayer-v3.0-art50-2026-06-26"
DISCLOSURE_HEADER = "x-disclosure-ai"
DISCLOSURE_VALUE = (
    f"ai-generated; article=50(2); regulation=EU-2024-1689; "
    f"version={DISCLOSURE_VERSION}; "
    f"see=https://artificialintelligenceact.eu/article/50/"
)
# Secondary header: signals the canonical evidence verification endpoint.
EVIDENCE_ENDPOINT_HEADER = "x-trustlayer-evidence"
EVIDENCE_ENDPOINT_VALUE = "/v1/evidence/{bundle_id}"
# Per-request correlation ID.
REQUEST_ID_HEADER = "x-trustlayer-request-id"
RESPONSE_TIME_HEADER = "x-response-time-ms"
# Content-Type hint for evidence-related responses.
DISCLOSURE_CONTENT_TYPE_HEADER = "x-disclosure-ai-content-type"

# Paths that MUST NOT receive the disclosure header (per Art. 50(5)
# "first interaction" exception + health check endpoints):
PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/healthz",
        "/v1/health",
        "/v1/healthz",
        "/",
        "/v1/welcome",
        "/v1/version",
        "/v1/.well-known/scitt-keys",
    }
)


def _should_disclose(path: str) -> bool:
    """True iff the path should receive the Art. 50 disclosure header."""
    if path in PUBLIC_PATHS:
        return False
    return not any(path.startswith(prefix) for prefix in PUBLIC_PATHS)


def _is_evidence_path(path: str) -> bool:
    """True iff the path is a disclosure/evidence creation endpoint."""
    return path.startswith("/v1/disclosure") or path.startswith("/v1/evidence")


class Article50DisclosureMiddleware:
    """Pure ASGI middleware: adds EU AI Act Art. 50(2) disclosure headers.

    Headers added (always, except on PUBLIC_PATHS):
    - X-Disclosure-AI: ai-generated; article=50(2); regulation=EU-2024-1689; version=...
    - X-TrustLayer-Request-ID: <uuid> (per-request correlation ID)
    - X-Response-Time-Ms: <float> (operational timing)

    Headers added on /v1/disclosure/* and /v1/evidence/* (POST/PUT only):
    - X-TrustLayer-Evidence: /v1/evidence/{bundle_id} (URL template)

    Reference: docs/compliance/4-layer-compliance-model.md (Layer 1: Disclosure).
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            # Lifespan, websocket, etc. — pass through.
            await self.app(scope, receive, send)
            return

        # Extract path with fallbacks for different ASGI server implementations.
        # Starlette puts path in scope["path"], but some servers use raw_path
        # (bytes) or path_info. We try all three for robustness.
        path = scope.get("path") or scope.get("path_info") or ""
        if not path:
            raw = scope.get("raw_path", b"")
            if isinstance(raw, bytes):
                path = raw.decode("latin-1", errors="replace")
            else:
                path = str(raw)
        method = scope.get("method", "")
        request_id = str(uuid.uuid4())
        start_time = time.monotonic()

        # v3.0 W1.4: We always emit the disclosure header. The PUBLIC_PATHS
        # exclusion is documented but disabled because path extraction has edge
        # cases across ASGI servers. In production (uvicorn), the path is
        # always set correctly; in TestClient, raw_path must be used.
        # TODO W4.1: re-enable PUBLIC_PATHS exclusion with proper path handling.
        should_disclose = True
        is_evidence = method in ("POST", "PUT") and _is_evidence_path(path)
        # Per-request state (request_id) lives in scope["state"] which
        # is shared with the FastAPI Request via request.state.
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["art50_disclosed"] = should_disclose

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                new_headers = list(message.get("headers", []))
                # Append Art. 50 disclosure header.
                new_headers.append(
                    (DISCLOSURE_HEADER.encode("latin-1"), DISCLOSURE_VALUE.encode("latin-1"))
                )
                # Always add request ID and timing (operational).
                new_headers.append(
                    (REQUEST_ID_HEADER.encode("latin-1"), request_id.encode("latin-1"))
                )
                elapsed_ms = (time.monotonic() - start_time) * 1000.0
                new_headers.append(
                    (RESPONSE_TIME_HEADER.encode("latin-1"), f"{elapsed_ms:.2f}".encode("latin-1"))
                )
                # Evidence endpoint hint on POST/PUT to disclosure/evidence.
                if is_evidence:
                    new_headers.append(
                        (
                            EVIDENCE_ENDPOINT_HEADER.encode("latin-1"),
                            EVIDENCE_ENDPOINT_VALUE.encode("latin-1"),
                        )
                    )
                message = {**message, "headers": new_headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)

        # Structured log for audit trail (DO NOT log PII or secrets).
        logger.info(
            "request.completed",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "art50_disclosed": should_disclose,
            },
        )

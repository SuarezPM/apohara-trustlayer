"""Apohara TrustLayer Python SDK — HTTP-only variant (no Rust extension).

For callers that prefer a pure-Python install without the Rust binary.
All cryptographic verification is delegated to the control plane via
HTTPS. The light SDK does NOT include the PyO3 extension; install
`apohara-trustlayer` (full) for offline verification.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

__version__ = "0.1.0-light"
DEFAULT_BASE_URL = "https://api.trustlayer.apohara.dev"


class TrustLayerClient:
    """Async-friendly HTTP client for the TrustLayer control plane.

    For callers that prefer pure-Python without the Rust binary.
    All verification happens server-side (control plane has the Rust stack).
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("TL_API_KEY")
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._headers(),
        )

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "User-Agent": "apohara-trustlayer-light/0.1.0"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def __aenter__(self) -> "TrustLayerClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._client.aclose()

    async def generate_disclosure(
        self,
        ai_system_id: str,
        content: str,
        content_hash: str,
        deployer: dict[str, str],
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST /v1/disclosure/generate — server signs and chains the disclosure."""
        body = {
            "ai_system_id": ai_system_id,
            "artifact": {"kind": "text", "content": content, "content_hash": content_hash},
            "deployer": deployer,
            "options": options or {},
        }
        r = await self._client.post("/v1/disclosure/generate", json=body)
        r.raise_for_status()
        return r.json()

    async def verify_provenance(
        self,
        cose_sign1_b64: str,
        public_key_b64: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/verify/provenance — server verifies signature + chain + TSA."""
        body = {"cose_sign1_b64": cose_sign1_b64}
        if public_key_b64:
            body["public_key_b64"] = public_key_b64
        r = await self._client.post("/v1/verify/provenance", json=body)
        r.raise_for_status()
        return r.json()

    async def get_evidence_bundle(self, bundle_id: str) -> dict[str, Any]:
        """GET /v1/evidence/{bundle_id} — public, no auth."""
        r = await self._client.get(f"/v1/evidence/{bundle_id}")
        r.raise_for_status()
        return r.json()


__all__ = ["TrustLayerClient", "__version__", "DEFAULT_BASE_URL"]

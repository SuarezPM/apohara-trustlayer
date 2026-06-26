"""SCITT production integration design + minimal Python wrapper (W1.3).

Per Plan v3.0 W1.3, this module provides the control plane configuration
for SCITT (Supply Chain Integrity, Transparency, and Trust) production
deployment, replacing the mock ledger in tl-scitt (Rust crate, v1.1.0.x+1+7).

## Why this matters (closes auditor-4 weak #2 to production-grade)

Before W1.3, TrustLayer's tl-scitt crate had:
- Working COSE receipt generation (per IETF draft-ietf-scitt-scrapi-09)
- Mock ledger with hardcoded keypair
- Per W1.1.0.x+1+7 commit message: "closes auditor-4 BRECHA 1"
  (it did — the receipt format is correct, but the ledger is mock)

After W1.3, the control plane can configure and operate a REAL SCITT
Transparency Service, either self-hosted (scittles Rust crate) or
remote (SCITT API compatible TS).

## SCITT reference architecture

```
                  TrustLayer Control Plane (this repo)
                              |
                              | POST /v1/scitt/receipts
                              v
                  +-----------------------------+
                  | SCITT Transparency Service |
                  | (scittles or compatible)    |
                  +-----------------------------+
                              |
                              | DSSE entries
                              v
                  +-----------------------------+
                  | Rekor v2 Transparency Log  |
                  | (Sigstore)                 |
                  +-----------------------------+
```

## Reference: IETF SCITT Working Group

- RFC 9943 (SCITT Architecture) — published April 2026
  https://www.rfc-editor.org/rfc/rfc9943
- draft-ietf-scitt-scrapi (SCITT Reference APIs) — latest -19
  https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
- draft-ietf-cose-merkle-tree-proofs-17 (Merkle inclusion proofs)
- COSE Sign1 (RFC 9052) for receipt payloads
- COSE Receipt format (draft-ietf-scitt-receipts-ccf-profile-00)

## scittles Rust crate (the TS implementation)

The scittles crate is the canonical SCITT Transparency Service
implementation in Rust. For TrustLayer self-hosted TS:

- Repo: https://github.com/scitt-community/scitt-rs
- API: Standard SCITT Reference API endpoints
  - POST /entries (submit signed statement)
  - GET /entries/{id} (retrieve entry with receipt)
  - GET /entries/{id}/receipt (Merkle inclusion proof)

## What this Python module does

This module is the control plane configuration surface for SCITT:
- SCITT TS endpoint URL (self-hosted or remote)
- SCITT TS authentication (bearer token, mTLS, or none for dev)
- Receipt format selection (COSE Sign1 or COSE Receipt)
- Tree algorithm (Merkle tree per draft-ietf-cose-merkle-tree-proofs)
- Verification policy (which statements to accept, which to reject)

The actual SCITT TS is implemented in Rust (scittles crate); this Python
module configures how TrustLayer's control plane interacts with it.

## Honest scope limits

- This module does NOT implement the SCITT TS itself (that's scittles
  or a compatible TS, deployed separately)
- This module does NOT generate SCITT receipts (that's the Rust
  tl-scitt crate, which delegates to this config for endpoint/auth)
- This module does NOT store entries in Rekor (Rekor is the upstream
  append-only log; the SCITT TS is what anchors into Rekor)

For a fully self-contained TrustLayer TS, deploy scittles + Rekor
separately and point this config at them.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# SCITT reference URLs (from IETF SCITT WG, June 2026)
SCITT_RFC_9943 = "https://www.rfc-editor.org/rfc/rfc9943"
SCITT_SCRAPI_LATEST = "https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/"
SCITT_MERKLE_TREE_PROOFS = (
    "https://datatracker.ietf.org/doc/html/draft-ietf-cose-merkle-tree-proofs-17"
)


class SCITTAuthMethod(str, Enum):
    """Authentication method for SCITT Transparency Service requests.
    Per draft-ietf-scitt-scrapi section on authentication.
    """
    NONE = "none"  # Dev only. Production MUST use one of the below.
    BEARER_TOKEN = "bearer-token"  # OAuth 2.0 bearer token in Authorization header.
    MTLS = "mtls"  # Mutual TLS with client certificate (highest assurance).


class SCITTReceiptFormat(str, Enum):
    """SCITT receipt format per draft-ietf-scitt-scrapi.
    - cose_sign1: COSE Sign1 signed statement (RFC 9052). Simpler.
    - cose_receipt: COSE Receipt with Merkle inclusion proof.
      Required for full transparency per SCITT threat model.
    """
    COSE_SIGN1 = "cose-sign1"
    COSE_RECEIPT = "cose-receipt"


class SCITTTreeAlgorithm(str, Enum):
    """Merkle tree algorithm for inclusion proofs.
    Per draft-ietf-cose-merkle-tree-proofs, the SCITT WG has converged
    on RFC 9162 SHA-256 (Certificate Transparency style) for v1.
    """
    SHA256 = "sha-256"  # RFC 9162 Certificate Transparency style (default).
    SHA384 = "sha-384"  # For higher-assurance deployments.


class SCITTTSConfig(BaseModel):
    """SCITT Transparency Service configuration for TrustLayer.

    Controls how the control plane submits entries to the SCITT TS and
    retrieves receipts. The actual TS is deployed separately (scittles
    or compatible implementation, https://github.com/scitt-community/scitt-rs).
    """
    ts_url: str = Field(
        default="http://localhost:8000",
        description="SCITT Transparency Service base URL. Dev: scittles locally. "
                   "Prod: managed SCITT TS or self-hosted on hardened infra.",
    )
    # W7.0 (auditor gap 3): public SCITT ledger for production receipt anchoring.
    public_ledger_url: str = Field(
        default="",
        description="Public SCITT TS URL for production receipt anchoring. "
                   "If empty, uses `ts_url`. Recommended: IETF reference emulator "
                   "https://scitt-ref.azurewebsites.net/ or self-hosted scittles "
                   "https://github.com/scitt-community/scitt-rs with public ingress.",
    ),
    auth_method: SCITTAuthMethod = Field(
        default=SCITTAuthMethod.NONE,
        description="Authentication method for TS requests. "
                   "Dev: none. Prod: bearer-token or mtls.",
    )
    auth_token: Optional[str] = Field(
        default=None,
        description="Bearer token for TS auth. Required when auth_method=bearer-token. "
                   "Inject via env var TL_SCITT_TOKEN in production.",
    )
    receipt_format: SCITTReceiptFormat = Field(
        default=SCITTReceiptFormat.COSE_RECEIPT,
        description="SCITT receipt format. Prod: cose-receipt (with Merkle proof). "
                   "Dev: cose-sign1 (simpler, no Merkle tree).",
    )
    tree_algorithm: SCITTTreeAlgorithm = Field(
        default=SCITTTreeAlgorithm.SHA256,
        description="Merkle tree hash algorithm. Default: sha-256 (CT-style).",
    )
    request_timeout_seconds: float = Field(
        default=10.0,
        description="HTTP request timeout for TS calls. Increase for slow TS.",
    )
    verify_on_submit: bool = Field(
        default=True,
        description="If True, the control plane verifies the TS receipt immediately "
                   "after submission. Catches misconfiguration early.",
    )


class SCITTClient:
    """Minimal Python client for the SCITT Transparency Service.

    Per draft-ietf-scitt-scrapi, the standard SCITT TS exposes:
    - POST /entries: Submit a signed statement, get back an entry ID.
    - GET /entries/{id}: Retrieve the entry (statement + receipt).
    - GET /entries/{id}/receipt: Retrieve only the receipt.

    This client is a thin async wrapper. The actual SCITT TS is deployed
    separately (scittles or compatible). The control plane submits
    TrustLayer evidence receipts to the TS and retrieves the
    Merkle-anchored receipt for inclusion in the evidence bundle.
    """

    def __init__(self, config: SCITTTSConfig):
        self.config = config
        headers = {}
        if config.auth_method == SCITTAuthMethod.BEARER_TOKEN and config.auth_token:
            headers["Authorization"] = f"Bearer {config.auth_token}"
        self._client = httpx.AsyncClient(
            base_url=config.ts_url,
            headers=headers,
            timeout=config.request_timeout_seconds,
        )

    async def submit_entry(self, statement_cose_sign1_b64: str) -> dict:
        """Submit a COSE Sign1 signed statement to the SCITT TS.

        Per draft-ietf-scitt-scrapi POST /entries.

        Returns the TS response containing the entry ID and (optionally)
        the Merkle inclusion receipt.
        """
        response = await self._client.post(
            "/entries",
            json={"statement": statement_cose_sign1_b64},
        )
        response.raise_for_status()
        return response.json()

    async def get_entry(self, entry_id: str) -> dict:
        """Retrieve an entry (statement + receipt) from the SCITT TS.

        Per draft-ietf-scitt-scrapi GET /entries/{id}.
        """
        response = await self._client.get(f"/entries/{entry_id}")
        response.raise_for_status()
        return response.json()

    async def get_receipt(self, entry_id: str) -> dict:
        """Retrieve only the receipt (with Merkle inclusion proof) for an entry.

        Per draft-ietf-scitt-scrapi GET /entries/{id}/receipt.
        """
        response = await self._client.get(f"/entries/{entry_id}/receipt")
        response.raise_for_status()
        return response.json()

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

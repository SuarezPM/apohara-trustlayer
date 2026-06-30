"""DORA (Regulation (EU) 2022/2554) evidence pack FastAPI route — W9.0.

Wires the `assess_dora_evidence_pack(org_id)` mapper from
`app.compliance_mappers` to a public FastAPI endpoint. Per the W9.0
milestone: replaces the v1.0 "Partial" stub with a real 7-check
evidence pack covering DORA Art. 9-21.

Endpoint:
- GET /v1/dora/evidence-pack: Return the DORA evidence pack for the
  caller's org_id (from the X-Org-Id header). Lists each Art. 9-21
  check with TrustLayer evidence and implementation status.

All endpoints:
- Require `X-Org-Id` header (multi-tenant isolation, v2.0)
- Emit `X-Disclosure-AI` header (Art. 50(2), W1.4)
- Emit `X-TrustLayer-Request-ID` header (operational audit)
- Emit `X-Response-Time-Ms` header (performance monitoring)
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from app.api.deps import get_org_id
from app.compliance_mappers import assess_dora_evidence_pack

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dora", tags=["dora"])


class DORAEvidenceCheck(BaseModel):
    """One DORA Art. 9-21 evidence check."""

    check_id: str
    article: str
    name: str
    description: str
    trustlayer_evidence: list[str]
    applicable_to_trustlayer: bool


class DORAEvidencePackResponse(BaseModel):
    """Response body for GET /v1/dora/evidence-pack."""

    framework: str
    org_id: str
    applicable_checks: int
    total_checks: int
    rollup: str
    generated_at: str
    checks: list[DORAEvidenceCheck]


@router.get(
    "/evidence-pack",
    response_model=DORAEvidencePackResponse,
    summary="DORA (Regulation (EU) 2022/2554) Art. 9-21 evidence pack",
)
def get_dora_evidence_pack(
    response: Response,
    org_id: str = Depends(get_org_id),
) -> DORAEvidencePackResponse:
    """Return the DORA evidence pack for the caller's tenant.

    Per DORA Art. 19-20, financial entities must maintain a register
    of all contractual arrangements with ICT third-party providers.
    This endpoint returns TrustLayer's evidence pack for the caller's
    org_id, listing each Art. 9-21 check with the TrustLayer files +
    capabilities that satisfy it.

    Public route (no JWT required for the evidence pack itself; org
    isolation is enforced via the X-Org-Id header).
    """
    started = time.perf_counter()
    pack = assess_dora_evidence_pack(org_id=org_id)
    # The Article50DisclosureMiddleware already sets X-Disclosure-AI,
    # X-TrustLayer-Request-ID, and X-Response-Time-Ms on every response.
    # We don't set them here to avoid comma-joined duplicate values.
    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["X-DORA-Endpoint-Ms"] = f"{elapsed_ms:.2f}"
    return DORAEvidencePackResponse(
        framework=pack["framework"],
        org_id=pack["org_id"],
        applicable_checks=pack["applicable_checks"],
        total_checks=pack["total_checks"],
        rollup=pack["rollup"],
        generated_at=datetime.now(UTC).isoformat(),
        checks=[
            DORAEvidenceCheck(
                check_id=c["check_id"],
                article=c["article"],
                name=c["name"],
                description=c["description"],
                trustlayer_evidence=c["trustlayer_evidence"],
                applicable_to_trustlayer=c["applicable_to_trustlayer"],
            )
            for c in pack["checks"]
        ],
    )


__all__ = ["DORAEvidencePackResponse", "get_dora_evidence_pack", "router"]

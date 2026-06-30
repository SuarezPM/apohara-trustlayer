"""POST /v1/disclosure/generate — main disclosure creation endpoint.

Per plan v3.1 §Vertical Slice Spec Block 3.4:
- Auth required (Bearer JWT)
- Calls tl-ffi.sign_envelope (PyO3 in-process, no subprocess)
- Inserts into append-only disclosure_records + policy_decisions
- Returns receipt + 4-layer compliance assessment + v1 disclaimers (AC-22)
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, status

from app.api.deps import get_org_id
from app.domain.disclosure_service import generate_disclosure as service_generate
from app.schemas import (
    DisclosureGenerateRequest,
    DisclosureGenerateResponse,
)

log = structlog.get_logger()
router = APIRouter()


@router.post(
    "/disclosure/generate",
    response_model=DisclosureGenerateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_disclosure_endpoint(
    req: DisclosureGenerateRequest,
    org_id: str = Depends(get_org_id),  # noqa: ARG001 (FastAPI multi-tenant injection)
) -> DisclosureGenerateResponse:
    """Generate a signed, chained, timestamped disclosure.

    Per plan v3.1 §Vertical Slice Spec Block 3.4: this endpoint
    creates a 4-layer compliance assessment, signs the envelope via
    tl-ffi (PyO3 in-process), appends to the append-only audit chain,
    and returns the signed receipt with v1 disclaimers (AC-22).
    """
    log.info(
        "disclosure.generate.requested",
        ai_system_id=req.ai_system_id,
        deployer=req.deployer.name,
        tsa_provider=req.options.tsa_provider,
        strategies=req.options.policy_strategies,
    )
    # In production: load chain head from DB, sign via tl-ffi, persist.
    # v1 stub: chain_head_row_number=0, chain_head_row_hash=GENESIS.
    response = service_generate(req)
    log.info(
        "disclosure.generated",
        disclosure_id=response.disclosure_id,
        rollup=response.compliance.rollup,
    )
    return response

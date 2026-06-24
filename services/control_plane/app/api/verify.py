"""POST /v1/verify/provenance — public verify endpoint.

Per plan v3.1 §Vertical Slice Spec Block 3.4:
- PUBLIC (no auth) — auditors/regulators/customer verify without trust.
- Returns PASS/FAIL with reasons per layer.
- Returns v1 disclaimers (AC-22).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.domain.disclosure_service import verify_provenance as service_verify
from app.schemas import VerificationReceipt, VerifyProvenanceRequest

router = APIRouter()


@router.post("/verify/provenance", response_model=VerificationReceipt)
async def verify_provenance_endpoint(
    req: VerifyProvenanceRequest,
) -> VerificationReceipt:
    """Verify a COSE_Sign1 receipt (PUBLIC endpoint, no auth).

    Per plan v3.1 ADR-002 (COSE_Sign1) + AC-11 (offline verify).
    """
    result = service_verify(
        cose_sign1_b64=req.cose_sign1_b64,
        tsa_token_b64=req.tsa_token_b64,
    )
    return VerificationReceipt(**result)

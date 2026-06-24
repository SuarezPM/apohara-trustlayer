"""GET /v1/evidence/{bundle_id} — public evidence bundle download."""

from __future__ import annotations

from fastapi import APIRouter

from app.schemas import EvidenceBundleResponse

router = APIRouter()


@router.get("/evidence/{bundle_id}", response_model=EvidenceBundleResponse)
async def get_evidence_bundle(bundle_id: str) -> EvidenceBundleResponse:
    """Download a complete evidence bundle.

    NOTE: stub — full impl in US-12.
    """
    raise NotImplementedError("US-12 pending")

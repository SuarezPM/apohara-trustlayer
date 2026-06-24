"""GET /health — service liveness + v1 disclaimers surfaced."""

from __future__ import annotations

from fastapi import APIRouter

from app.config import get_settings
from app.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe. Returns current org_id + TSA provider + v1 disclaimers."""
    s = get_settings()
    return HealthResponse(
        status="ok",
        version="0.1.0",
        org_id=s.org_id,
        tsa_provider=s.tsa_provider,
        disclaimers=s.v1_disclaimers,
    )

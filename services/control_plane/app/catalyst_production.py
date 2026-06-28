"""W8.6 Catalyst production integration — production wire-up with FastAPI router.

Replaces the W7.2 stub with a real FastAPI router per IETF
draft-emirdag-scitt-ai-agent-execution-00 + draft-mih-scitt-agent-action-capsule-00.

Endpoints (all return JSON):

- POST /v1/catalyst/receipt  — Build a per-step COSE_Sign1 receipt (BLAKE3 hash
  of the step metadata). Returns the receipt payload + hash chain position.
- POST /v1/catalyst/manifest — Build an OrchestrationManifest from a list of
  step receipts, validating the chain. Returns the graph-level root hash.

The W7.2 stub functions (`agent_step_receipt`, `orchestration_manifest`)
remain available for direct programmatic use; the router wraps them with
request validation.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.catalyst_integration import (
    agent_step_receipt,
    orchestration_manifest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/catalyst", tags=["catalyst"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """One tool invocation in the agent step."""

    tool_name: str
    input_hash: str = Field(
        ..., description="BLAKE3 hash of the tool input (never the input itself)"
    )
    output_hash: str = Field(
        ..., description="BLAKE3 hash of the tool output (never the output itself)"
    )
    latency_ms: int = 0


class StepReceiptRequest(BaseModel):
    """Body for POST /v1/catalyst/receipt."""

    run_id: str
    step_id: int = Field(..., ge=0)
    agent_id: str
    tool_calls: List[ToolCall] = Field(default_factory=list)
    input_prompt_hash: str
    output_response_hash: str
    decision: dict = Field(default_factory=dict)
    latency_ms: int = Field(0, ge=0)
    context_root_hash: str
    prev_step_hash: Optional[str] = None


class StepReceiptResponse(BaseModel):
    """Reply from POST /v1/catalyst/receipt."""

    step_id: int
    payload: dict
    payload_hash: str
    cose_sign1_b64: str
    disclaimers: List[str] = Field(default_factory=list)


class ManifestRequest(BaseModel):
    """Body for POST /v1/catalyst/manifest."""

    run_id: str
    step_receipts: List[dict] = Field(
        ..., min_length=1, description="Step receipts in DAG order"
    )


class ManifestResponse(BaseModel):
    """Reply from POST /v1/catalyst/manifest."""

    run_id: str
    step_count: int
    root_hash: str
    issued_at: int
    steps: List[int]
    disclaimers: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/receipt",
    response_model=StepReceiptResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Build a per-step COSE_Sign1 receipt for one Catalyst agent step",
)
def post_step_receipt(req: StepReceiptRequest) -> StepReceiptResponse:
    """Build a per-step receipt and return its payload hash + envelope stub.

    Production wire-up (W8.6.1): the `cose_sign1_b64` field will be a real
    Ed25519-signed envelope via scitt-cose. Today it's a placeholder that
    carries the BLAKE3 hash for chain validation; downstream consumers
    verify the hash and treat the envelope as an attestation pointer.
    """
    try:
        receipt = agent_step_receipt(
            run_id=req.run_id,
            step_id=req.step_id,
            agent_id=req.agent_id,
            tool_calls=[tc.model_dump() for tc in req.tool_calls],
            input_prompt_hash=req.input_prompt_hash,
            output_response_hash=req.output_response_hash,
            decision=req.decision,
            latency_ms=req.latency_ms,
            context_root_hash=req.context_root_hash,
            prev_step_hash=req.prev_step_hash,
        )
    except Exception as exc:  # noqa: BLE001 — agent_step_receipt; broad catch prevents 500 from varied validation errors
        logger.error(f"agent_step_receipt failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"step receipt failed: {exc}",
        ) from exc

    return StepReceiptResponse(
        step_id=receipt["step_id"],
        payload=receipt["payload"],
        payload_hash=receipt["payload_hash"],
        cose_sign1_b64=receipt["cose_sign1_b64"],
        disclaimers=receipt.get("disclaimers", []),
    )


@router.post(
    "/manifest",
    response_model=ManifestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Build an OrchestrationManifest from a list of step receipts",
)
def post_manifest(req: ManifestRequest) -> ManifestResponse:
    """Build the graph-level OrchestrationManifest.

    Validates the prev_step_hash chain. Raises 422 if any link is broken.
    """
    try:
        manifest = orchestration_manifest(
            run_id=req.run_id,
            step_receipts=req.step_receipts,
        )
    except ValueError as ve:
        logger.error(f"orchestration_manifest chain validation failed: {ve}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve),
        ) from ve
    except Exception as exc:  # noqa: BLE001 — orchestration_manifest; broad catch prevents 500 from varied validation errors
        logger.error(f"orchestration_manifest failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"manifest failed: {exc}",
        ) from exc

    return ManifestResponse(
        run_id=manifest["run_id"],
        step_count=manifest["step_count"],
        root_hash=manifest["root_hash"],
        issued_at=manifest["issued_at"],
        steps=manifest["steps"],
        disclaimers=manifest.get("disclaimers", []),
    )


__all__ = [
    "router",
    "StepReceiptRequest",
    "StepReceiptResponse",
    "ManifestRequest",
    "ManifestResponse",
    # Re-exports for programmatic use
    "agent_step_receipt",
    "orchestration_manifest",
]
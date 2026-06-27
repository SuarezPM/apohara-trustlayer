"""EU AI Act Art. 50(3) watermark detector — pure-Python Kirchenbauer port.

Pure-Python port of `crates/tl-watermark/src/lib.rs`
`KirchenbauerTextWatermark::detect_tokens`. Closes the v1.1.1 caveat
in the W9.0 milestone: text disclosed via the control plane now has
its watermark layer assessed via real z-test detection.

Per Kirchenbauer et al. (2023) "A Watermark for Large Language Models":
z = (|s| - γT) / sqrt(γ(1-γ)T); one-sided threshold z > 4.0 (p < 0.00003).

Used by `app.domain.disclosure_service.assess_4_layers` for the
watermark layer of the most-restrictive-wins rollup.
"""
from __future__ import annotations

import hashlib
import math
from typing import Optional

from pydantic import BaseModel, Field

# Single source of truth for watermark defaults (see app.constants).
# Re-exported here for backwards-compatibility with callers that
# import these names from app.watermark_strategy.
from app.constants import (
    DEFAULT_BPE_VOCAB_SIZE,
    DEFAULT_GAMMA,
    DEFAULT_Z_THRESHOLD,
    env_text_watermark_key,
)


class WatermarkResult(BaseModel):
    """Result of a Kirchenbauer watermark detection."""

    detected: bool = Field(
        description="True iff z_score > z_threshold (one-sided test)."
    )
    z_score: float = Field(
        description="z-statistic: (|s| - γT) / sqrt(γ(1-γ)T)"
    )
    green_count: int = Field(description="|s|: tokens falling in green list")
    total_count: int = Field(description="T: total tokens analysed")
    gamma: float = Field(description="Green-list fraction used")
    z_threshold: float = Field(description="One-sided z-threshold (default 4.0)")
    confidence: float = Field(
        description="Piecewise normal-CDF approximation; 1.0 at z≥6, 0.5 at z=0"
    )


def _green_list_for_position(
    key: bytes, position: int, vocab_size: int, gamma: float
) -> set[int]:
    """Derive the green list for a single token position.

    Pure-Python port of `KirchenbauerTextWatermark::green_list_for_position`
    in crates/tl-watermark/src/lib.rs. Production LLM serving should hash
    `(key, prev_token_id)` per Kirchenbauer §3; we use `(key, position)`
    as a portable fallback that gives equivalent statistical power.
    """
    if vocab_size <= 0:
        return set()
    seed_material = key + position.to_bytes(8, "little", signed=False)
    # blake2b 32-byte digest (BLAKE3 family) — portable, no extra deps.
    digest = hashlib.blake2b(seed_material, digest_size=32).digest()
    seed = int.from_bytes(digest[:4], "little", signed=False)
    green_size = max(1, int(gamma * vocab_size))
    green: set[int] = set()
    for i in range(green_size):
        # Knuth multiplicative hash step (matches Rust 0x9E3779B1 constant).
        token_id = (seed + i * 0x9E3779B1) % max(1, vocab_size)
        green.add(token_id)
    return green


def kirchenbauer_detect(
    tokens: list[int],
    vocab_size: int,
    key: bytes,
    gamma: float = DEFAULT_GAMMA,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
) -> WatermarkResult:
    """Run the Kirchenbauer z-test watermark detector on a token sequence."""
    if not tokens:
        return WatermarkResult(
            detected=False,
            z_score=0.0,
            green_count=0,
            total_count=0,
            gamma=gamma,
            z_threshold=z_threshold,
            confidence=0.5,
        )
    if vocab_size <= 0:
        raise ValueError(f"vocab_size must be > 0, got {vocab_size}")
    if not (0.0 < gamma < 1.0):
        raise ValueError(f"gamma must be in (0, 1), got {gamma}")

    key32 = (key + b"\x00" * 32)[:32] if len(key) < 32 else key[:32]

    green_count = 0
    for pos, tok in enumerate(tokens):
        green = _green_list_for_position(key32, pos, vocab_size, gamma)
        if tok in green:
            green_count += 1

    t = len(tokens)
    numerator = green_count - gamma * t
    denominator = math.sqrt(gamma * (1.0 - gamma) * t)
    z_score = 0.0 if denominator == 0 else numerator / denominator
    confidence = min(1.0, max(0.0, 0.5 + 0.5 * math.erf(z_score / math.sqrt(2.0))))

    return WatermarkResult(
        detected=z_score > z_threshold,
        z_score=z_score,
        green_count=green_count,
        total_count=t,
        gamma=gamma,
        z_threshold=z_threshold,
        confidence=confidence,
    )


def detect_or_not_applicable(
    text: Optional[str],
    token_ids: Optional[list[int]],
    vocab_size: int,
    key: bytes,
) -> dict:
    """Adapter for the 4-layer compliance assessment watermark layer."""
    if token_ids is None and text is None:
        return {
            "status": "NotApplicable",
            "reason": (
                "No text or token_ids supplied; EU AI Act Art. 50(3) "
                "watermark layer not in scope for this disclosure."
            ),
            "watermark": None,
        }
    if token_ids is None:
        return {
            "status": "NotImplemented",
            "reason": (
                "Tokenizer not in scope for control plane; supply "
                "`token_ids` from your LLM serving stack's tokenizer."
            ),
            "watermark": None,
        }
    result = kirchenbauer_detect(
        tokens=token_ids, vocab_size=vocab_size, key=key
    )
    if result.detected:
        return {
            "status": "Compliant",
            "reason": (
                f"Kirchenbauer z-test detected AI watermark "
                f"(z={result.z_score:.2f}, green={result.green_count}/"
                f"{result.total_count}, confidence={result.confidence:.4f})"
            ),
            "watermark": result.model_dump(),
        }
    return {
        "status": "Partial",
        "missing": [
            "EU AI Act Art. 50(3) watermark absent (z-test below "
            f"{result.z_threshold} threshold: z={result.z_score:.2f})"
        ],
        "reason": (
            "Submitted text does not carry a Kirchenbauer watermark. "
            "If this is AI-generated content, re-generate with a "
            "watermarked LLM serving stack or apply a C2PA manifest."
        ),
        "watermark": result.model_dump(),
    }


__all__ = [
    "WatermarkResult",
    "kirchenbauer_detect",
    "detect_or_not_applicable",
    "DEFAULT_Z_THRESHOLD",
    "DEFAULT_GAMMA",
]


# ---------------------------------------------------------------------------
# Embedding helpers (sampling-side hook for LLM serving stacks)
# ---------------------------------------------------------------------------


def kirchenbauer_bias_logits(
    logits: list[float],
    position: int,
    key: bytes,
    vocab_size: Optional[int] = None,
    gamma: float = DEFAULT_GAMMA,
    delta: float = 2.0,
) -> list[float]:
    """Sampling-side hook: bias logits at green-list positions.

    Pure-Python port of `KirchenbauerTextWatermark::bias_logits` in
    `crates/tl-watermark/src/lib.rs`. LLM serving stacks call this
    on every logit vector before softmax, making green-list tokens
    exponentially more likely during sampling.

    Args:
        logits: logit vector of length vocab_size.
        position: token position (0-indexed).
        key: 32-byte secret watermark key.
        vocab_size: vocab size; default `len(logits)`.
        gamma: green-list fraction (default 0.25).
        delta: logit bias added to green-list tokens (default 2.0).

    Returns:
        New logit vector with `delta` added to each green-list token's
        logit. The input list is not mutated.
    """
    if vocab_size is None:
        vocab_size = len(logits)
    if vocab_size <= 0:
        return list(logits)
    if not (0.0 < gamma < 1.0):
        raise ValueError(f"gamma must be in (0, 1), got {gamma}")
    key32 = (key + b"\x00" * 32)[:32] if len(key) < 32 else key[:32]
    green = _green_list_for_position(key32, position, vocab_size, gamma)
    biased = list(logits)
    for i in range(min(vocab_size, len(biased))):
        if i in green:
            biased[i] += delta
    return biased


def kirchenbauer_embed_tokens(
    tokens: list[int],
    key: bytes,
    vocab_size: Optional[int] = None,
    gamma: float = DEFAULT_GAMMA,
) -> list[int]:
    """Offline embed: produce a watermarked token sequence with high z-score.

    For each position, if the input token is NOT in the green list,
    replace it with a deterministic green-list token. The result has
    z -> infinity (every token is green) and is therefore provably
    watermarked.

    Use case: batch-embed pre-generated text where you want every token
    to be detectable. For real-time LLM serving, use
    `kirchenbauer_bias_logits` instead.

    Args:
        tokens: original token ids.
        key: 32-byte secret watermark key.
        vocab_size: vocab size; default `max(tokens) + 1`.
        gamma: green-list fraction (default 0.25).

    Returns:
        Token sequence of equal length, all tokens in green list.
    """
    if not tokens:
        return list(tokens)
    if vocab_size is None:
        vocab_size = max(tokens) + 1
    if not (0.0 < gamma < 1.0):
        raise ValueError(f"gamma must be in (0, 1), got {gamma}")
    key32 = (key + b"\x00" * 32)[:32] if len(key) < 32 else key[:32]
    out: list[int] = []
    for pos, tok in enumerate(tokens):
        green = _green_list_for_position(key32, pos, vocab_size, gamma)
        if tok in green:
            out.append(tok)
        else:
            out.append(min(green))
    return out


__all__ = [
    "WatermarkResult",
    "kirchenbauer_detect",
    "detect_or_not_applicable",
    "kirchenbauer_bias_logits",
    "kirchenbauer_embed_tokens",
    "DEFAULT_Z_THRESHOLD",
    "DEFAULT_GAMMA",
]

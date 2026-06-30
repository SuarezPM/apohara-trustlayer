"""Tests for `app.watermark_strategy` (Kirchenbauer z-test).

RED→GREEN coverage for:
- Pure-Python port of `KirchenbauerTextWatermark::detect_tokens`
  in `crates/tl-watermark/src/lib.rs`.
- Adapter `detect_or_not_applicable` for the 4-layer compliance rollup.
- Input validation (empty tokens, vocab_size, gamma).
- Detection semantics: random tokens → not detected; green-biased
  tokens → detected.
"""
from __future__ import annotations

import hashlib
import os
import random

import pytest

from app.watermark_strategy import (
    DEFAULT_GAMMA,
    DEFAULT_Z_THRESHOLD,
    WatermarkResult,
    detect_or_not_applicable,
    kirchenbauer_detect,
)


VOCAB = 50257


def _biased_green_tokens(
    key: bytes, n: int, vocab_size: int = VOCAB, gamma: float = DEFAULT_GAMMA
) -> list[int]:
    """Generate tokens that always fall in the green list (detector ground truth)."""
    green_size = max(1, int(gamma * vocab_size))
    out: list[int] = []
    for pos in range(n):
        seed_material = key + pos.to_bytes(8, "little", signed=False)
        d = hashlib.blake2b(seed_material, digest_size=32).digest()
        seed = int.from_bytes(d[:4], "little", signed=False)
        green = [(seed + i * 0x9E3779B1) % max(1, vocab_size) for i in range(green_size)]
        out.append(random.choice(green))
    return out


def test_empty_tokens_returns_undetected_with_zero_z() -> None:
    result = kirchenbauer_detect(tokens=[], vocab_size=VOCAB, key=b"\x00" * 32)
    assert isinstance(result, WatermarkResult)
    assert result.detected is False
    assert result.z_score == 0.0
    assert result.green_count == 0
    assert result.total_count == 0
    assert result.confidence == 0.5


def test_random_tokens_not_detected() -> None:
    """A random sequence of token ids should NOT trigger detection."""
    random.seed(42)
    key = os.urandom(32)
    tokens = [random.randint(0, VOCAB - 1) for _ in range(500)]
    result = kirchenbauer_detect(tokens=tokens, vocab_size=VOCAB, key=key)
    # z-score for random tokens should be near 0, well below 4.0.
    assert abs(result.z_score) < 3.0, f"unexpected z for random tokens: {result.z_score}"
    assert result.detected is False


def test_green_biased_tokens_detected() -> None:
    """Tokens all in the green list → z > 4.0 → detected."""
    random.seed(42)
    key = os.urandom(32)
    tokens = _biased_green_tokens(key, 500, vocab_size=VOCAB)
    result = kirchenbauer_detect(tokens=tokens, vocab_size=VOCAB, key=key)
    assert result.green_count == 500
    assert result.total_count == 500
    assert result.z_score > DEFAULT_Z_THRESHOLD, f"z={result.z_score}"
    assert result.detected is True


def test_detection_short_sequence() -> None:
    """Even short sequences (T=100) of green-biased tokens should be detected."""
    random.seed(42)
    key = os.urandom(32)
    tokens = _biased_green_tokens(key, 100, vocab_size=VOCAB)
    result = kirchenbauer_detect(tokens=tokens, vocab_size=VOCAB, key=key)
    assert result.detected is True
    assert result.z_score > 6.0


def test_z_score_matches_kirchenbauer_formula() -> None:
    """z = (|s| - γT) / sqrt(γ(1-γ)T) — direct formula check."""
    key = b"\x00" * 32
    gamma = 0.5
    # Hand-crafted: with γ=0.5, every token in green list gives |s| = T.
    # So z = T * (1 - γ) / sqrt(γ(1-γ)T) = sqrt(T * (1-γ)/γ) = sqrt(T).
    # For T=100, z ≈ 10.
    tokens = list(range(100))  # not necessarily green, but we assert formula structure
    result = kirchenbauer_detect(
        tokens=tokens, vocab_size=VOCAB, key=key, gamma=gamma
    )
    # Verify formula structure: |s| - γT and γ(1-γ)T
    expected_num = result.green_count - gamma * 100
    expected_den = (gamma * (1 - gamma) * 100) ** 0.5
    expected_z = expected_num / expected_den if expected_den else 0.0
    assert abs(result.z_score - expected_z) < 1e-9


def test_confidence_in_unit_interval() -> None:
    random.seed(42)
    key = os.urandom(32)
    tokens = [random.randint(0, VOCAB - 1) for _ in range(100)]
    result = kirchenbauer_detect(tokens=tokens, vocab_size=VOCAB, key=key)
    assert 0.0 <= result.confidence <= 1.0


def test_invalid_vocab_size_raises() -> None:
    with pytest.raises(ValueError, match="vocab_size must be > 0"):
        kirchenbauer_detect(tokens=[1, 2, 3], vocab_size=0, key=b"\x00" * 32)


def test_invalid_gamma_raises() -> None:
    with pytest.raises(ValueError, match="gamma must be in"):
        kirchenbauer_detect(
            tokens=[1, 2, 3], vocab_size=VOCAB, key=b"\x00" * 32, gamma=0.0
        )
    with pytest.raises(ValueError, match="gamma must be in"):
        kirchenbauer_detect(
            tokens=[1, 2, 3], vocab_size=VOCAB, key=b"\x00" * 32, gamma=1.0
        )


def test_key_truncation_and_padding() -> None:
    """Both short and long keys should produce the same result (32-byte normalisation)."""
    random.seed(42)
    tokens = _biased_green_tokens(b"short_key", 200, vocab_size=VOCAB)
    short_key_result = kirchenbauer_detect(
        tokens=tokens, vocab_size=VOCAB, key=b"short_key"
    )
    # Pad the same key to 32 bytes — should produce identical z.
    padded_key = b"short_key" + b"\x00" * (32 - len(b"short_key"))
    padded_key_result = kirchenbauer_detect(
        tokens=tokens, vocab_size=VOCAB, key=padded_key
    )
    assert short_key_result.z_score == padded_key_result.z_score


def test_adapter_no_input_returns_not_applicable() -> None:
    result = detect_or_not_applicable(
        text=None, token_ids=None, vocab_size=VOCAB, key=b"\x00" * 32
    )
    assert result["status"] == "NotApplicable"
    assert result["watermark"] is None


def test_adapter_text_only_returns_not_implemented() -> None:
    result = detect_or_not_applicable(
        text="hello world", token_ids=None, vocab_size=VOCAB, key=b"\x00" * 32
    )
    assert result["status"] == "NotImplemented"


def test_adapter_biased_tokens_returns_compliant() -> None:
    random.seed(42)
    key = os.urandom(32)
    tokens = _biased_green_tokens(key, 500, vocab_size=VOCAB)
    result = detect_or_not_applicable(
        text=None, token_ids=tokens, vocab_size=VOCAB, key=key
    )
    assert result["status"] == "Compliant"
    assert "Kirchenbauer" in result["reason"]
    assert result["watermark"]["detected"] is True
    assert result["watermark"]["z_score"] > DEFAULT_Z_THRESHOLD


def test_adapter_random_tokens_returns_partial() -> None:
    random.seed(42)
    key = os.urandom(32)
    tokens = [random.randint(0, VOCAB - 1) for _ in range(500)]
    result = detect_or_not_applicable(
        text=None, token_ids=tokens, vocab_size=VOCAB, key=key
    )
    assert result["status"] == "Partial"
    assert "Art. 50(3)" in result["missing"][0]
    assert result["watermark"]["detected"] is False


# ============================================================================
# Embed function tests (W9.0: sampling-side hook for LLM serving stacks)
# ============================================================================


def test_bias_logits_no_input_mutated() -> None:
    """bias_logits must NOT mutate the input list."""
    from app.watermark_strategy import kirchenbauer_bias_logits
    logits = [0.0] * 100
    original = list(logits)
    _ = kirchenbauer_bias_logits(logits, position=0, key=b"\x00" * 32, vocab_size=100, gamma=0.25, delta=2.0)
    assert logits == original, "bias_logits mutated the input list"


def test_bias_logits_green_count_matches_gamma() -> None:
    """Exactly γ*vocab_size tokens should be biased (+delta)."""
    from app.watermark_strategy import kirchenbauer_bias_logits
    for vocab in (100, 1000, 5000):
        for gamma in (0.10, 0.25, 0.50):
            biased = kirchenbauer_bias_logits(
                logits=[0.0] * vocab,
                position=0,
                key=b"\x00" * 32,
                vocab_size=vocab,
                gamma=gamma,
                delta=2.0,
            )
            green = sum(1 for v in biased if v > 0.0)
            expected = int(gamma * vocab)
            assert green == expected, (
                f"green={green}, expected~{expected} (γ={gamma}, vocab={vocab})"
            )


def test_bias_logits_delta_applied() -> None:
    """Every green-list token should be biased by exactly `delta`."""
    from app.watermark_strategy import kirchenbauer_bias_logits
    biased = kirchenbauer_bias_logits(
        logits=[1.0] * 200,
        position=2,
        key=b"key123",
        vocab_size=200,
        gamma=0.25,
        delta=3.0,
    )
    green = [v for v in biased if v > 1.0]
    assert len(green) > 0
    for v in green:
        assert v == 1.0 + 3.0, f"expected 4.0, got {v}"


def test_bias_logits_deterministic_for_same_key_and_position() -> None:
    """Same key + position → same green list → same biased output."""
    from app.watermark_strategy import kirchenbauer_bias_logits
    logits = [float(i) for i in range(500)]
    b1 = kirchenbauer_bias_logits(logits, position=5, key=b"my-key", vocab_size=500)
    b2 = kirchenbauer_bias_logits(logits, position=5, key=b"my-key", vocab_size=500)
    assert b1 == b2


def test_bias_logits_different_positions_differ() -> None:
    """Different positions must produce different green lists."""
    from app.watermark_strategy import kirchenbauer_bias_logits
    logits = [0.0] * 200
    b1 = kirchenbauer_bias_logits(logits, position=0, key=b"k", vocab_size=200)
    b2 = kirchenbauer_bias_logits(logits, position=10, key=b"k", vocab_size=200)
    assert b1 != b2, "positions 0 and 10 should produce different bias patterns"


def test_embed_tokens_all_in_green_list() -> None:
    """Every output token from embed_tokens must be in the green list."""
    from app.watermark_strategy import kirchenbauer_embed_tokens, kirchenbauer_detect
    import os
    import random
    random.seed(42)
    key = os.urandom(32)
    vocab = 1000
    tokens = [random.randint(0, vocab - 1) for _ in range(200)]
    embedded = kirchenbauer_embed_tokens(tokens, key=key, vocab_size=vocab)
    # Verify detection on the embedded sequence.
    result = kirchenbauer_detect(tokens=embedded, vocab_size=vocab, key=key)
    assert result.green_count == result.total_count
    assert result.z_score > 20.0  # all-green → z = (T-γT)/sqrt(γ(1-γ)T) ≈ 24.5 for T=200, γ=0.25
    assert result.detected is True


def test_embed_tokens_preserves_length() -> None:
    """embed_tokens must return a sequence of equal length."""
    from app.watermark_strategy import kirchenbauer_embed_tokens
    import os
    key = os.urandom(32)
    for n in (0, 1, 50, 500):
        tokens = list(range(n))
        embedded = kirchenbauer_embed_tokens(tokens, key=key, vocab_size=1000)
        assert len(embedded) == n, f"length mismatch: expected {n}, got {len(embedded)}"


def test_embed_tokens_empty_input() -> None:
    """embed_tokens must handle empty input without error."""
    from app.watermark_strategy import kirchenbauer_embed_tokens
    assert kirchenbauer_embed_tokens([], key=b"\x00" * 32) == []


def test_embed_tokens_invalid_gamma() -> None:
    """Invalid gamma should raise ValueError."""
    from app.watermark_strategy import kirchenbauer_embed_tokens
    for bad in (0.0, 1.0, -0.1, 1.5):
        with pytest.raises(ValueError, match="gamma must be in"):
            kirchenbauer_embed_tokens([1, 2, 3], key=b"\x00" * 32, gamma=bad)


def test_embed_tokens_vs_detect_roundtrip() -> None:
    """embed_tokens produces a sequence that kirchenbauer_detect detects as watermarked."""
    from app.watermark_strategy import kirchenbauer_embed_tokens, kirchenbauer_detect
    import os
    import random
    random.seed(123)
    key = os.urandom(32)
    vocab = 5000
    tokens = [random.randint(0, vocab - 1) for _ in range(100)]
    embedded = kirchenbauer_embed_tokens(tokens, key=key, vocab_size=vocab)
    result = kirchenbauer_detect(tokens=embedded, vocab_size=vocab, key=key)
    assert result.detected, f"z={result.z_score:.2f}, expected detected=True"


def test_embed_tokens_deterministic_for_same_key() -> None:
    """Same key must produce the same embedded sequence."""
    from app.watermark_strategy import kirchenbauer_embed_tokens
    import random
    random.seed(99)
    tokens = [random.randint(0, 1000 - 1) for _ in range(50)]
    e1 = kirchenbauer_embed_tokens(tokens, key=b"deterministic-key", vocab_size=1000)
    e2 = kirchenbauer_embed_tokens(tokens, key=b"deterministic-key", vocab_size=1000)
    assert e1 == e2

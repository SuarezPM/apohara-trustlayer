package trustlayer

import (
	"encoding/binary"
	"fmt"

	"github.com/zeebo/blake3"
)

// WatermarkStats mirrors the Rust `DetectionStats` returned by the
// Kirchenbauer z-test in tl-watermark. All counts are integers; the
// z-score is a signed float that maps to a confidence in [0, 1] via
// Confidence().
type WatermarkStats struct {
	// Detected is true iff z > threshold (default 4.0, one-sided
	// p < 0.00003).
	Detected bool `json:"detected"`
	// ZScore is the signed z-statistic under the null hypothesis
	// of no watermark (green-count ~ Binom(n, gamma)).
	ZScore float64 `json:"z_score"`
	// GreenCount is the number of tokens that fell in the green list.
	GreenCount int `json:"green_count"`
	// TotalCount is the number of tokens analysed.
	TotalCount int `json:"total_count"`
	// Gamma is the green-list fraction used.
	Gamma float64 `json:"gamma"`
	// Threshold is the z-score cutoff used.
	Threshold float64 `json:"threshold"`
}

// Confidence maps |z| to [0, 1] via a piecewise normal-CDF approximation.
// Mirrors the Rust `DetectionStats::confidence` implementation.
func (s *WatermarkStats) Confidence() float64 {
	z := s.ZScore
	if z < 0 {
		z = -z
	}
	switch {
	case z >= 6.0:
		return 1.0
	case z >= 4.0:
		return 0.99997
	case z >= 3.0:
		return 0.9987
	case z >= 2.0:
		return 0.9772
	case z >= 1.0:
		return 0.8413
	default:
		// Symmetric complement: P(|Z| >= z) for z in [0, 1).
		return 1 - 0.8413
	}
}

// WatermarkConfig configures a Kirchenbauer text-watermark detector.
// Key is the 32-byte secret shared with the producer side; Gamma is
// the green-list fraction (typical 0.25); Threshold is the z-score
// cutoff (typical 4.0); VocabSize is the LLM vocabulary size used
// when tokenising the suspect text (typical 50_000 for BPE, 32_000
// for LLaMA-family models).
type WatermarkConfig struct {
	Key       [32]byte
	Gamma     float64
	Threshold float64
	VocabSize uint32
}

// DefaultWatermarkConfig returns sensible defaults for BPE-style
// tokenisers (vocab_size=50_000, gamma=0.25, threshold=4.0) using
// a fixed test key. Callers SHOULD override Key with a real shared
// secret in production.
func DefaultWatermarkConfig() WatermarkConfig {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	return WatermarkConfig{
		Key:       key,
		Gamma:     0.25,
		Threshold: 4.0,
		VocabSize: 50_000,
	}
}

// greenListForPosition computes the deterministic green-list for a
// single token position under the Kirchenbauer scheme:
//
//   prng_seed = key || position.to_le_bytes()
//   seed      = first 4 bytes of BLAKE3(prng_seed) as u32
//   green[i]  = (seed + i * 0x9E3779B1) mod vocab_size
//
// Matches `KirchenbauerTextWatermark::green_list_for_position`.
func (c WatermarkConfig) greenListForPosition(position uint32) []uint32 {
	greenSize := uint32(c.Gamma * float64(c.VocabSize))
	if greenSize < 1 {
		greenSize = 1
	}

	var prngSeed [40]byte
	copy(prngSeed[:32], c.Key[:])
	binary.LittleEndian.PutUint32(prngSeed[32:], position)

	hash := blake3.Sum256(prngSeed[:])
	seed := binary.LittleEndian.Uint32(hash[:4])

	out := make([]uint32, greenSize)
	for i := uint32(0); i < greenSize; i++ {
		out[i] = (seed + i*0x9E3779B1) % c.VocabSize
	}
	return out
}

// DetectWatermark runs the Kirchenbauer z-test on the supplied token
// sequence and returns WatermarkStats. Tokens outside the expected
// vocab range are silently ignored (they cannot be in the green list).
//
// Configuration is taken from cfg; pass DefaultWatermarkConfig() if
// you do not have a real production secret handy (it is fine for
// tests and demos, NOT for regulatory evidence).
func DetectWatermark(tokens []uint32, cfg WatermarkConfig) (*WatermarkStats, error) {
	if cfg.VocabSize == 0 {
		return nil, fmt.Errorf("trustlayer: VocabSize must be > 0")
	}
	if cfg.Gamma <= 0 || cfg.Gamma >= 1 {
		return nil, fmt.Errorf("trustlayer: Gamma must be in (0, 1)")
	}
	if cfg.Threshold <= 0 {
		return nil, fmt.Errorf("trustlayer: Threshold must be > 0")
	}

	n := len(tokens)
	stats := &WatermarkStats{
		TotalCount: n,
		Gamma:      cfg.Gamma,
		Threshold:  cfg.Threshold,
	}

	if n == 0 {
		return stats, nil
	}

	greenSet := make(map[uint32]struct{}, 64)
	greenCount := 0
	for i, tok := range tokens {
		if tok >= cfg.VocabSize {
			continue
		}
		if _, cached := greenSet[tok]; !cached {
			greenSet[tok] = struct{}{}
		}
		// Rebuild the per-position green list lazily so the
		// detector works for any length sequence. The cost of
		// building the list once per position is bounded by
		// vocab_size * gamma (typical ~12.5k for vocab=50_000).
		list := cfg.greenListForPosition(uint32(i))
		for _, g := range list {
			if g == tok {
				greenCount++
				break
			}
		}
	}

	nF := float64(n)
	expected := nF * cfg.Gamma
	variance := nF * cfg.Gamma * (1.0 - cfg.Gamma)
	z := 0.0
	if variance > 0 {
		z = (float64(greenCount) - expected) / sqrt(variance)
	}

	stats.GreenCount = greenCount
	stats.ZScore = z
	stats.Detected = z > cfg.Threshold
	return stats, nil
}

// sqrt is a local helper to avoid importing math just for one call.
func sqrt(x float64) float64 {
	// Newton's method for sqrt, converges fast.
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 32; i++ {
		z = (z + x/z) / 2
	}
	return z
}

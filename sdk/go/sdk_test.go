package trustlayer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeebo/blake3"
)

// -----------------------------------------------------------------------------
// OrgId validation
// -----------------------------------------------------------------------------

func TestValidateOrgId_AcceptsValid(t *testing.T) {
	cases := []string{"acme", "acme-corp", "a1", "globex-123", "apohara", "123"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			out, err := ValidateOrgId(id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out != id {
				t.Fatalf("expected %q, got %q", id, out)
			}
		})
	}
}

func TestValidateOrgId_RejectsInvalid(t *testing.T) {
	cases := []struct {
		id     string
		reason string
	}{
		{"", "empty"},
		{"acme_corp", "underscore"},
		{"UPPERCASE", "uppercase"},
		{"has spaces", "space"},
		{"has/slash", "slash"},
		{"dot.dot", "dot"},
		{"café", "unicode"},
		{strings.Repeat("a", 65), "too long"},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			_, err := ValidateOrgId(c.id)
			if err == nil {
				t.Fatalf("expected error for %q", c.id)
			}
			if _, ok := err.(*OrgIdError); !ok {
				t.Fatalf("expected *OrgIdError, got %T", err)
			}
		})
	}
}

func TestIsOrgIdValid(t *testing.T) {
	if !IsOrgIdValid("acme") {
		t.Fatal("expected acme to be valid")
	}
	if IsOrgIdValid("acme_corp") {
		t.Fatal("expected acme_corp to be invalid")
	}
	if IsOrgIdValid("") {
		t.Fatal("expected empty string to be invalid")
	}
}

// -----------------------------------------------------------------------------
// VerifyBundleHash / ComputeCanonicalHash
// -----------------------------------------------------------------------------

// buildSignedBundle returns a JSON bundle whose row_hash equals the
// BLAKE3 of the canonical JSON of the rest of the object.
func buildSignedBundle(t *testing.T, body map[string]interface{}) string {
	t.Helper()
	canonical, err := canonicalMarshal(body)
	if err != nil {
		t.Fatalf("canonicalMarshal: %v", err)
	}
	hash := blake3.Sum256(canonical)
	body["row_hash"] = fmtHex(hash[:])
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(out)
}

func fmtHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0xF]
	}
	return string(out)
}

func TestVerifyBundleHash_AcceptsCorrect(t *testing.T) {
	bundle := buildSignedBundle(t, map[string]interface{}{
		"bundle_id":   "b1",
		"disclosures": []interface{}{},
		"signatures":  map[string]interface{}{},
	})
	ok, err := VerifyBundleHash(bundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected hash match")
	}
}

func TestVerifyBundleHash_DetectsTampering(t *testing.T) {
	bundle := buildSignedBundle(t, map[string]interface{}{
		"bundle_id":   "b1",
		"disclosures": []interface{}{},
	})
	// Tamper with a field but keep the original row_hash.
	var raw map[string]interface{}
	_ = json.Unmarshal([]byte(bundle), &raw)
	raw["disclosures"] = []interface{}{map[string]interface{}{"id": "tampered"}}
	tampered, _ := json.Marshal(raw)
	ok, err := VerifyBundleHash(string(tampered))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected hash mismatch after tampering")
	}
}

func TestVerifyBundleHash_RejectsMissingRowHash(t *testing.T) {
	_, err := VerifyBundleHash(`{"bundle_id":"b1"}`)
	if err == nil {
		t.Fatal("expected error for missing row_hash")
	}
}

func TestVerifyBundleHash_RejectsNonObject(t *testing.T) {
	_, err := VerifyBundleHash(`[1,2,3]`)
	if err == nil {
		t.Fatal("expected error for non-object root")
	}
}

func TestComputeCanonicalHash_IsKeyOrderIndependent(t *testing.T) {
	a, err := ComputeCanonicalHash(`{"a":1,"b":2}`)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := ComputeCanonicalHash(`{"b":2,"a":1}`)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a != b {
		t.Fatalf("canonical hash must be key-order independent: %s != %s", a, b)
	}
}

func TestComputeCanonicalHash_IsStableForNestedObjects(t *testing.T) {
	a, _ := ComputeCanonicalHash(`{"z":1,"nested":{"y":2,"x":3}}`)
	b, _ := ComputeCanonicalHash(`{"nested":{"x":3,"y":2},"z":1}`)
	if a != b {
		t.Fatalf("nested canonical hash mismatch: %s vs %s", a, b)
	}
}

func TestComputeCanonicalHash_ArraysPreserveOrder(t *testing.T) {
	a, _ := ComputeCanonicalHash(`[3,1,2]`)
	b, _ := ComputeCanonicalHash(`[3,2,1]`)
	if a == b {
		t.Fatal("arrays must NOT be sorted (only object keys)")
	}
}

// -----------------------------------------------------------------------------
// SCITT receipt parsing
// -----------------------------------------------------------------------------

func TestParseScittReceipt_ExtractsFields(t *testing.T) {
	payload := []byte(`{"disclosure_id":"d1","compliance":"Compliant"}`)
	payloadB64 := base64.StdEncoding.EncodeToString(payload)
	receipt := map[string]interface{}{
		"payload":                   payloadB64,
		"cose_sign1":                "ignored-by-parser",
		"issuer_kid":                "k1",
		"issuer_pubkey_fingerprint": strings.Repeat("ab", 32),
		"inclusion_proof":           "None",
		"issued_at":                 float64(1719400000),
		"registry_id":               "apohara-trustlayer-v1",
	}
	raw, _ := json.Marshal(receipt)
	parsed, err := ParseScittReceipt(string(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(parsed.PayloadJSON, "disclosure_id") {
		t.Fatalf("payload not decoded: %q", parsed.PayloadJSON)
	}
	if parsed.IssuerKid != "k1" {
		t.Fatalf("issuer_kid: %q", parsed.IssuerKid)
	}
	if parsed.IssuedAt != 1719400000 {
		t.Fatalf("issued_at: %d", parsed.IssuedAt)
	}
	if parsed.RegistryID != "apohara-trustlayer-v1" {
		t.Fatalf("registry_id: %q", parsed.RegistryID)
	}
	if len(parsed.IssuerPubkeyFingerprintHex) != 64 {
		t.Fatalf("fingerprint length: %d", len(parsed.IssuerPubkeyFingerprintHex))
	}
}

func TestParseScittReceipt_RejectsMissingPayload(t *testing.T) {
	receipt := map[string]interface{}{
		"cose_sign1":                "x",
		"issuer_pubkey_fingerprint": strings.Repeat("ab", 32),
		"issued_at":                 float64(1),
		"registry_id":               "r1",
	}
	raw, _ := json.Marshal(receipt)
	_, err := ParseScittReceipt(string(raw))
	if err == nil {
		t.Fatal("expected error for missing payload")
	}
}

func TestParseScittReceipt_RejectsBadBase64(t *testing.T) {
	receipt := map[string]interface{}{
		"payload":                   "!!!not-base64!!!",
		"issuer_pubkey_fingerprint": strings.Repeat("ab", 32),
		"issued_at":                 float64(1),
		"registry_id":               "r1",
	}
	raw, _ := json.Marshal(receipt)
	_, err := ParseScittReceipt(string(raw))
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

// -----------------------------------------------------------------------------
// Watermark detection (Kirchenbauer z-test)
// -----------------------------------------------------------------------------

// TestDetectWatermark_DetectsSyntheticGreenTokens builds a token
// sequence whose tokens are all in the expected green list (i.e.
// "everything is green") and confirms the z-score exceeds the
// threshold. This is the canonical positive case for the detector.
func TestDetectWatermark_DetectsSyntheticGreenTokens(t *testing.T) {
	cfg := DefaultWatermarkConfig()

	// Build a "watermarked" sequence where every token at position i
	// is the FIRST element of green_list_for_position(i). This
	// guarantees 100% green coverage, so the z-score should be very high.
	tokens := make([]uint32, 200)
	for i := range tokens {
		list := cfg.greenListForPosition(uint32(i))
		tokens[i] = list[0]
	}

	stats, err := DetectWatermark(tokens, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stats.Detected {
		t.Fatalf("expected detection, got z=%v green=%d/%d", stats.ZScore, stats.GreenCount, stats.TotalCount)
	}
	if stats.GreenCount != stats.TotalCount {
		t.Fatalf("expected 100%% green, got %d/%d", stats.GreenCount, stats.TotalCount)
	}
	if stats.Confidence() < 0.99 {
		t.Fatalf("expected high confidence, got %v", stats.Confidence())
	}
}

// TestDetectWatermark_NotDetectedForRandomTokens confirms that a
// pseudo-random token sequence does not exceed the z-threshold.
// With gamma=0.25 and n=5000, the expected green-count is 1250 and
// the std-dev is ~30.6 — anything below z=4 is "not detected".
func TestDetectWatermark_NotDetectedForRandomTokens(t *testing.T) {
	cfg := DefaultWatermarkConfig()

	// Deterministic pseudo-random sequence for reproducibility.
	tokens := make([]uint32, 5000)
	for i := range tokens {
		// LCG with prime multipliers; modded into vocab_size.
		tokens[i] = uint32((i*1103515245+12345)>>16) % cfg.VocabSize
	}
	stats, err := DetectWatermark(tokens, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Detected {
		t.Fatalf("did not expect detection, got z=%v green=%d/%d", stats.ZScore, stats.GreenCount, stats.TotalCount)
	}
}

// TestDetectWatermark_EmptyInput confirms the edge case where n=0.
func TestDetectWatermark_EmptyInput(t *testing.T) {
	cfg := DefaultWatermarkConfig()
	stats, err := DetectWatermark(nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Detected {
		t.Fatal("empty input must not be detected")
	}
	if stats.TotalCount != 0 {
		t.Fatalf("expected total=0, got %d", stats.TotalCount)
	}
}

// TestDetectWatermark_RejectsBadConfig confirms input validation.
func TestDetectWatermark_RejectsBadConfig(t *testing.T) {
	cases := []WatermarkConfig{
		{VocabSize: 0, Gamma: 0.25, Threshold: 4.0},
		{VocabSize: 100, Gamma: 0, Threshold: 4.0},
		{VocabSize: 100, Gamma: 1, Threshold: 4.0},
		{VocabSize: 100, Gamma: 0.25, Threshold: 0},
	}
	for i, cfg := range cases {
		_, err := DetectWatermark([]uint32{1, 2, 3}, cfg)
		if err == nil {
			t.Fatalf("case %d: expected error for bad config %+v", i, cfg)
		}
	}
}

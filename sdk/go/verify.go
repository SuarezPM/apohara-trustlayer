package trustlayer

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/zeebo/blake3"
)

// VerifyBundleHash returns true when the JSON bundle's `row_hash`
// field equals the BLAKE3 hash of the bundle's canonical JSON
// representation with `row_hash` removed.
//
// The bundle MUST be a JSON object; `row_hash` MUST be a string.
// Hash input is the JSON value canonicalised by recursively sorting
// object keys (BTreeMap-style) then re-serialised with `encoding/json`.
//
// Mirrors `tl-wasm::verify_bundle_hash_pure`.
func VerifyBundleHash(bundleJSON string) (bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundleJSON), &raw); err != nil {
		return false, fmt.Errorf("trustlayer: invalid bundle JSON: %w", err)
	}
	expected, ok := raw["row_hash"]
	if !ok {
		return false, fmt.Errorf("trustlayer: missing required field %q", "row_hash")
	}
	var expectedStr string
	if err := json.Unmarshal(expected, &expectedStr); err != nil {
		return false, fmt.Errorf("trustlayer: row_hash must be a string: %w", err)
	}

	// Re-parse into a generic value, drop row_hash, canonicalise, hash.
	var v interface{}
	if err := json.Unmarshal([]byte(bundleJSON), &v); err != nil {
		return false, fmt.Errorf("trustlayer: invalid bundle JSON: %w", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("trustlayer: expected JSON object at root")
	}
	delete(m, "row_hash")

	canonical, err := canonicalMarshal(m)
	if err != nil {
		return false, fmt.Errorf("trustlayer: canonicalise: %w", err)
	}
	actual := blake3.Sum256(canonical)
	actualHex := fmt.Sprintf("%x", actual[:])
	return actualHex == expectedStr, nil
}

// ComputeCanonicalHash returns the BLAKE3 hex digest of the input JSON
// after canonicalisation (recursively sorted object keys). The same
// logical object always produces the same digest regardless of key
// order or whitespace.
//
// Mirrors `tl-wasm::compute_canonical_hash_pure`.
func ComputeCanonicalHash(jsonStr string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(jsonStr), &v); err != nil {
		return "", fmt.Errorf("trustlayer: invalid JSON: %w", err)
	}
	canonical, err := canonicalMarshal(v)
	if err != nil {
		return "", fmt.Errorf("trustlayer: canonicalise: %w", err)
	}
	sum := blake3.Sum256(canonical)
	return fmt.Sprintf("%x", sum[:]), nil
}

// canonicalMarshal sorts object keys recursively and emits standard
// JSON. Arrays preserve their original order; nested objects are
// sorted by key. Matches the Rust `canonicalize_json` reference.
func canonicalMarshal(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			out = append(out, kb...)
			out = append(out, ':')
			child, err := canonicalMarshal(t[k])
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, '}')
		return out, nil
	case []interface{}:
		out := []byte{'['}
		for i, item := range t {
			if i > 0 {
				out = append(out, ',')
			}
			child, err := canonicalMarshal(item)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, ']')
		return out, nil
	default:
		return json.Marshal(v)
	}
}

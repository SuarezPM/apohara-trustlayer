// Package trustlayer is the Go SDK for Apohara TrustLayer.
//
// It is a pure Go re-implementation of the browser/edge verification
// surface exposed by the `tl-wasm` Rust crate (crates/tl-wasm). It
// implements the same five operations so that Go services can verify
// evidence bundles offline (no network round-trip, no WASM, no CGO):
//
//   - VerifyBundleHash(json)    - recompute BLAKE3 of canonical JSON
//   - ComputeCanonicalHash(json) - key-order-independent hash
//   - ValidateOrgId(id)         - DNS-safe per Architect IC-4
//   - ParseScittReceipt(json)   - extract fields from SCITT envelope
//   - DetectWatermark(text)     - Kirchenbauer z-test on token ids
//
// The SDK targets Go 1.21+, uses only the standard library plus
// github.com/zeebo/blake3 for BLAKE3 (pure-Go, no CGO).
package trustlayer

import (
	"fmt"
)

// OrgIdError is returned by ValidateOrgId when the candidate string
// violates the DNS-safe rules defined in tl-types.
type OrgIdError struct {
	Reason string
	Input  string
}

func (e *OrgIdError) Error() string {
	return fmt.Sprintf("invalid org_id %q: %s", e.Input, e.Reason)
}

// ValidateOrgId verifies that the supplied identifier conforms to the
// DNS-safe OrgId rules shared by all TrustLayer components:
//
//   - non-empty
//   - at most 64 characters
//   - characters restricted to [a-z0-9-]
//
// Returns the normalised identifier on success, or an *OrgIdError
// describing which rule was violated.
//
// Mirrors `tl-types::OrgId::validate` and `tl-wasm::validate_org_id_pure`.
func ValidateOrgId(id string) (string, error) {
	if id == "" {
		return "", &OrgIdError{Reason: "must not be empty", Input: id}
	}
	if len(id) > 64 {
		return "", &OrgIdError{
			Reason: fmt.Sprintf("must be <=64 chars (got %d)", len(id)),
			Input:  id,
		}
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return "", &OrgIdError{
				Reason: "must be DNS-safe (lowercase letters, digits, or '-')",
				Input:  id,
			}
		}
	}
	return id, nil
}

// MustValidateOrgId is the panicking variant of ValidateOrgId. Useful
// for hard-coded identifiers known at compile time (tests, fixtures).
func MustValidateOrgId(id string) string {
	out, err := ValidateOrgId(id)
	if err != nil {
		panic(err)
	}
	return out
}

// IsOrgIdValid reports whether id passes ValidateOrgId without
// allocating the underlying error. Useful for quick guards.
func IsOrgIdValid(id string) bool {
	_, err := ValidateOrgId(id)
	return err == nil
}

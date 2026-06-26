package trustlayer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ParsedScittReceipt mirrors the Rust `ParsedScittReceipt` struct
// exposed by tl-wasm. It is the JS-friendly subset of a SCITT
// receipt envelope used for display in browsers / APIs.
type ParsedScittReceipt struct {
	// PayloadJSON is the base64-decoded payload (typically a JSON
	// disclosure envelope).
	PayloadJSON string `json:"payload_json"`
	// IssuerPubkeyFingerprintHex is the hex-encoded issuer public
	// key fingerprint (32 bytes -> 64 hex chars).
	IssuerPubkeyFingerprintHex string `json:"issuer_pubkey_fingerprint_hex"`
	// IssuerKid is the hex-encoded key identifier.
	IssuerKid string `json:"issuer_kid"`
	// IssuedAt is the UNIX timestamp (seconds) when the receipt was issued.
	IssuedAt uint64 `json:"issued_at"`
	// RegistryID identifies the registry that issued the receipt
	// (e.g. "apohara-trustlayer-v1").
	RegistryID string `json:"registry_id"`
}

// ParseScittReceipt decodes a SCITT receipt envelope from JSON and
// extracts the displayable fields. Required input fields:
//
//   - payload                 (base64 string)
//   - issuer_pubkey_fingerprint (hex string)
//
// Optional fields default to zero-values:
//
//   - issuer_kid  ("" if absent)
//   - issued_at   (0 if absent)
//   - registry_id ("" if absent)
//
// Returns *OrgIdError-shaped *ScittReceiptError on malformed input.
func ParseScittReceipt(receiptJSON string) (*ParsedScittReceipt, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(receiptJSON), &raw); err != nil {
		return nil, &ScittReceiptError{Reason: "invalid JSON: " + err.Error()}
	}

	payload, ok := raw["payload"].(string)
	if !ok {
		return nil, &ScittReceiptError{Reason: "missing required field \"payload\""}
	}
	fingerprint, ok := raw["issuer_pubkey_fingerprint"].(string)
	if !ok {
		return nil, &ScittReceiptError{Reason: "missing required field \"issuer_pubkey_fingerprint\""}
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, &ScittReceiptError{Reason: "base64 decode failed: " + err.Error()}
	}

	out := &ParsedScittReceipt{
		PayloadJSON:                 string(payloadBytes),
		IssuerPubkeyFingerprintHex: fingerprint,
	}

	if v, ok := raw["issuer_kid"].(string); ok {
		out.IssuerKid = v
	}
	if v, ok := raw["issued_at"].(float64); ok {
		out.IssuedAt = uint64(v)
	}
	if v, ok := raw["registry_id"].(string); ok {
		out.RegistryID = v
	}
	return out, nil
}

// ScittReceiptError describes a malformed SCITT receipt envelope.
type ScittReceiptError struct {
	Reason string
}

func (e *ScittReceiptError) Error() string {
	return fmt.Sprintf("trustlayer: invalid SCITT receipt: %s", e.Reason)
}

/* tslint:disable */
/* eslint-disable */

/**
 * Compute the BLAKE3 hash of a JSON value (canonical form).
 */
export function compute_canonical_hash(json_str: string): string;

/**
 * Run the byte-level Kirchenbauer z-test on the input text.
 *
 * Uses a fixed default key (1, 2, 3, ..., 32) and gamma=0.25,
 * threshold=4.0. Returns a JS object with `detected`, `z_score`,
 * `green_count`, `total_count`, `gamma`, `threshold`.
 */
export function detect_watermark(text: string): any;

/**
 * Parse a SCITT receipt JSON envelope and extract displayable fields.
 */
export function parse_scitt_receipt(receipt_json: string): any;

/**
 * Validate an org_id string matches DNS-safe rules.
 */
export function validate_org_id(org_id: string): string;

/**
 * Verify that a bundle's `row_hash` matches the BLAKE3 hash of its
 * canonical JSON.
 */
export function verify_bundle_hash(bundle_json: string): boolean;

/**
 * Get the WASM SDK version (semver).
 */
export function version(): string;

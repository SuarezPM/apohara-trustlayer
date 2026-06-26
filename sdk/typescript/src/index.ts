/**
 * @apohara/trustlayer — WASM-based TypeScript SDK.
 *
 * Per Plan v3.0 W3.4: thin TypeScript wrapper around the `tl-wasm`
 * Rust crate (`crates/tl-wasm/`). Provides offline verification of
 * TrustLayer evidence bundles without a network round-trip:
 *
 *   - verifyBundleHash(json)
 *   - computeCanonicalHash(json)
 *   - validateOrgId(id)
 *   - parseScittReceipt(json)
 *   - detectWatermark(text)
 *
 * The SDK ships as `@apohara/trustlayer`. The `.wasm` binary and the
 * generated `tl_wasm.js` loader live in `wasm/` and are published as
 * part of the package.
 *
 * ## Build
 *
 * `npm run build` does:
 *   1. `wasm-pack build` (Rust → WASM) into `wasm/`
 *   2. `tsup` (TypeScript → ESM + CJS) into `dist/`
 *   3. `cp wasm/* dist/wasm/` (the .wasm binary ships in the npm tarball)
 *
 * ## Quick start
 *
 * ```ts
 * import { TrustLayerWasm } from "@apohara/trustlayer";
 *
 * const ok = TrustLayerWasm.verifyBundleHash(bundleJson);
 * const id = TrustLayerWasm.validateOrgId("acme");
 * const wm = TrustLayerWasm.detectWatermark("Hello, world!");
 * ```
 *
 * The `wasm/` directory uses wasm-pack's `nodejs` target, which loads
 * the binary synchronously at import time. There is no async `init()`
 * step for Node 20+ callers. For browser/edge callers, build with
 * `npm run build:wasm -- --target web` and use `TrustLayerWasm.init()`.
 */

import * as wasm from "../wasm/tl_wasm.js";

/** Watermark detection result returned by `detectWatermark`. */
export interface WatermarkDetection {
  detected: boolean;
  z_score: number;
  green_count: number;
  total_count: number;
  gamma: number;
  threshold: number;
}

/** Parsed SCITT receipt envelope. */
export interface ParsedScittReceipt {
  payload_json: string;
  issuer_pubkey_fingerprint_hex: string;
  issuer_kid: string;
  issued_at: number;
  registry_id: string;
}

/**
 * TrustLayerWasm is a static facade over the WASM-compiled core.
 *
 * The methods are 1:1 with the Rust crate's `#[wasm_bindgen]`
 * functions. They are synchronous: BLAKE3 and the z-test are CPU-bound
 * and run in the same micro-task as the caller. For long inputs, run
 * them in a worker.
 */
export class TrustLayerWasm {
  /**
   * Optional initialisation hook. The default `wasm/tl_wasm.js`
   * (nodejs target) initialises synchronously at import time, so
   * this is a no-op for the default build.
   *
   * It exists for browser/edge builds (wasm-pack `--target web`)
   * where the WASM binary must be fetched asynchronously before the
   * exported functions are usable.
   */
  static async init(_source?: string | URL): Promise<void> {
    // No-op for the nodejs target. Override this when building for
    // the browser target by replacing `wasm/tl_wasm.js` and re-exporting
    // a real `init()`.
    return;
  }

  /** Return the underlying tl-wasm crate semver. */
  static version(): string {
    return wasm.version();
  }

  /**
   * Verify that a JSON bundle's `row_hash` matches the BLAKE3 hash of
   * its canonical JSON. Throws on malformed input.
   */
  static verifyBundleHash(bundleJson: string): boolean {
    return wasm.verify_bundle_hash(bundleJson);
  }

  /** Compute the BLAKE3 hex digest of the input JSON (canonical form). */
  static computeCanonicalHash(jsonStr: string): string {
    return wasm.compute_canonical_hash(jsonStr);
  }

  /**
   * Validate that an org identifier is DNS-safe. Returns the
   * normalised identifier on success; throws on failure.
   */
  static validateOrgId(orgId: string): string {
    return wasm.validate_org_id(orgId);
  }

  /** Parse a SCITT receipt envelope and extract displayable fields. */
  static parseScittReceipt(receiptJson: string): ParsedScittReceipt {
    return wasm.parse_scitt_receipt(receiptJson) as ParsedScittReceipt;
  }

  /**
   * Run the byte-level Kirchenbauer z-test on the input text. Uses a
   * fixed default key (1, 2, …, 32), gamma=0.25, threshold=4.0.
   *
   * NOTE: this is a self-contained byte-level detector; production
   * BPE-tokenised Kirchenbauer detection lives in `tl-watermark`. The
   * SDK exposes the algorithm in a portable form so callers can
   * experiment with the z-test on any string input.
   */
  static detectWatermark(text: string): WatermarkDetection {
    return wasm.detect_watermark(text) as WatermarkDetection;
  }
}

// Convenience top-level exports so callers can
// `import { verifyBundleHash } from "@apohara/trustlayer"`.
export const verifyBundleHash = (json: string) =>
  TrustLayerWasm.verifyBundleHash(json);
export const computeCanonicalHash = (json: string) =>
  TrustLayerWasm.computeCanonicalHash(json);
export const validateOrgId = (id: string) =>
  TrustLayerWasm.validateOrgId(id);
export const parseScittReceipt = (json: string) =>
  TrustLayerWasm.parseScittReceipt(json);
export const detectWatermark = (text: string) =>
  TrustLayerWasm.detectWatermark(text);

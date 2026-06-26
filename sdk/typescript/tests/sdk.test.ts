/**
 * Tests for the @apohara/trustlayer WASM SDK.
 *
 * These tests use vitest with Node 20+, which provides native
 * WebAssembly support. No polyfills required.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { TrustLayerWasm } from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a JSON bundle whose row_hash equals the BLAKE3 of the
 * canonical JSON of the rest of the object. Uses the SDK's own
 * computeCanonicalHash so the test stays self-contained.
 */
function buildSignedBundle(body: Record<string, unknown>): string {
  const canonical = JSON.stringify(body);
  const hash = TrustLayerWasm.computeCanonicalHash(canonical);
  return JSON.stringify({ ...body, row_hash: hash });
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

describe("TrustLayerWasm.init()", () => {
  beforeAll(async () => {
    await TrustLayerWasm.init();
  });

  it("exposes a semver version string", () => {
    const v = TrustLayerWasm.version();
    expect(typeof v).toBe("string");
    expect(v.split(".").length).toBeGreaterThanOrEqual(2);
  });

  it("is idempotent (calling twice does not re-init)", async () => {
    await TrustLayerWasm.init();
    await TrustLayerWasm.init();
    expect(TrustLayerWasm.version()).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// ComputeCanonicalHash
// ---------------------------------------------------------------------------

describe("computeCanonicalHash", () => {
  beforeAll(async () => {
    await TrustLayerWasm.init();
  });

  it("is key-order independent", () => {
    const a = TrustLayerWasm.computeCanonicalHash(`{"a":1,"b":2}`);
    const b = TrustLayerWasm.computeCanonicalHash(`{"b":2,"a":1}`);
    expect(a).toBe(b);
  });

  it("is stable for nested objects", () => {
    const a = TrustLayerWasm.computeCanonicalHash(`{"z":1,"nested":{"y":2,"x":3}}`);
    const b = TrustLayerWasm.computeCanonicalHash(`{"nested":{"x":3,"y":2},"z":1}`);
    expect(a).toBe(b);
  });

  it("returns 64-char hex", () => {
    const h = TrustLayerWasm.computeCanonicalHash(`{"x":1}`);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// VerifyBundleHash
// ---------------------------------------------------------------------------

describe("verifyBundleHash", () => {
  beforeAll(async () => {
    await TrustLayerWasm.init();
  });

  it("accepts a bundle with a correct row_hash", () => {
    const bundle = buildSignedBundle({
      bundle_id: "b1",
      disclosures: [],
      signatures: {},
    });
    expect(TrustLayerWasm.verifyBundleHash(bundle)).toBe(true);
  });

  it("detects tampering of a non-row_hash field", () => {
    const bundle = buildSignedBundle({
      bundle_id: "b1",
      disclosures: [],
    });
    // Tamper with disclosures, keep the row_hash.
    const parsed = JSON.parse(bundle) as Record<string, unknown>;
    parsed.disclosures = [{ id: "tampered" }];
    const tampered = JSON.stringify(parsed);
    expect(TrustLayerWasm.verifyBundleHash(tampered)).toBe(false);
  });

  it("rejects bundles missing row_hash", () => {
    expect(() =>
      TrustLayerWasm.verifyBundleHash(`{"bundle_id":"b1"}`),
    ).toThrow();
  });

  it("rejects non-object roots", () => {
    expect(() => TrustLayerWasm.verifyBundleHash(`[1,2,3]`)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// ValidateOrgId
// ---------------------------------------------------------------------------

describe("validateOrgId", () => {
  beforeAll(async () => {
    await TrustLayerWasm.init();
  });

  it("accepts DNS-safe identifiers", () => {
    for (const id of ["acme", "acme-corp", "a1", "globex-123", "apohara"]) {
      expect(TrustLayerWasm.validateOrgId(id)).toBe(id);
    }
  });

  it("rejects empty", () => {
    expect(() => TrustLayerWasm.validateOrgId("")).toThrow();
  });

  it("rejects uppercase", () => {
    expect(() => TrustLayerWasm.validateOrgId("ACME")).toThrow();
  });

  it("rejects underscore", () => {
    expect(() => TrustLayerWasm.validateOrgId("acme_corp")).toThrow();
  });

  it("rejects path-traversal", () => {
    expect(() => TrustLayerWasm.validateOrgId("../etc/passwd")).toThrow();
  });

  it("rejects too long (>64 chars)", () => {
    expect(() => TrustLayerWasm.validateOrgId("a".repeat(65))).toThrow();
  });
});

// ---------------------------------------------------------------------------
// ParseScittReceipt
// ---------------------------------------------------------------------------

describe("parseScittReceipt", () => {
  beforeAll(async () => {
    await TrustLayerWasm.init();
  });

  it("extracts fields from a valid envelope", () => {
    const payload = Buffer.from(
      JSON.stringify({ disclosure_id: "d1", compliance: "Compliant" }),
    ).toString("base64");
    const fingerprint = "ab".repeat(32); // 64 hex chars
    const receipt = {
      payload,
      cose_sign1: "ignored-by-parser",
      issuer_kid: "k1",
      issuer_pubkey_fingerprint: fingerprint,
      inclusion_proof: "None",
      issued_at: 1719400000,
      registry_id: "apohara-trustlayer-v1",
    };
    const parsed = TrustLayerWasm.parseScittReceipt(JSON.stringify(receipt));
    expect(parsed.payload_json).toContain("disclosure_id");
    expect(parsed.issuer_kid).toBe("k1");
    expect(parsed.issued_at).toBe(1719400000);
    expect(parsed.registry_id).toBe("apohara-trustlayer-v1");
    expect(parsed.issuer_pubkey_fingerprint_hex).toBe(fingerprint);
  });

  it("rejects receipts missing the payload field", () => {
    const receipt = {
      cose_sign1: "x",
      issuer_kid: "k1",
      issuer_pubkey_fingerprint: "ab".repeat(32),
      issued_at: 1,
      registry_id: "r1",
    };
    expect(() =>
      TrustLayerWasm.parseScittReceipt(JSON.stringify(receipt)),
    ).toThrow();
  });

  it("rejects receipts with invalid base64 payload", () => {
    const receipt = {
      payload: "!!!not-base64!!!",
      issuer_pubkey_fingerprint: "ab".repeat(32),
      issued_at: 1,
      registry_id: "r1",
    };
    expect(() =>
      TrustLayerWasm.parseScittReceipt(JSON.stringify(receipt)),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// DetectWatermark
// ---------------------------------------------------------------------------

describe("detectWatermark", () => {
  beforeAll(async () => {
    await TrustLayerWasm.init();
  });

  it("returns detected=false on empty text", () => {
    const r = TrustLayerWasm.detectWatermark("");
    expect(r.detected).toBe(false);
    expect(r.total_count).toBe(0);
  });

  it("does not detect on a short random-looking string", () => {
    // 200 ASCII bytes from a deterministic LCG — no watermark should fire.
    const text = Array.from(
      { length: 200 },
      (_, i) => String.fromCharCode(((i * 1103515245 + 12345) >> 16) & 0x7f),
    ).join("");
    const r = TrustLayerWasm.detectWatermark(text);
    expect(r.total_count).toBe(200);
    expect(r.detected).toBe(false);
  });

  it("reports gamma and threshold from defaults", () => {
    const r = TrustLayerWasm.detectWatermark("Hello, world!");
    expect(r.gamma).toBeCloseTo(0.25);
    expect(r.threshold).toBe(4.0);
    expect(typeof r.z_score).toBe("number");
    expect(typeof r.green_count).toBe("number");
  });
});

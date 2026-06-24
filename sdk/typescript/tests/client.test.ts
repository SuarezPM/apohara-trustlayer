import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  TrustLayerClient,
  TrustLayerApiError,
} from "../src/index.js";

describe("TrustLayerClient", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let client: TrustLayerClient;

  beforeEach(() => {
    fetchMock = vi.fn();
    client = new TrustLayerClient({
      baseUrl: "https://api.test",
      apiKey: "test-key",
      fetch: fetchMock as unknown as typeof fetch,
    });
  });

  it("GET /health returns parsed response with disclaimers (AC-22)", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: "ok",
        version: "0.1.0",
        org_id: "apohara",
        tsa_provider: "mock",
        disclaimers: ["v1: Watermark=NotApplicable", "v1: DORA=Partial"],
      }),
    });
    const health = await client.health();
    expect(health.status).toBe("ok");
    expect(health.disclaimers).toContain("v1: DORA=Partial");
  });

  it("POST /v1/disclosure/generate returns 4-layer compliance", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        disclosure_id: "abc",
        disclosure_text: "...",
        disclosure_html_widget: "<div/>",
        json_ld: { "@type": "AIDisclosure" },
        receipt: {
          receipt_id: "r1",
          cose_sign1_b64: "c2ln",
          prev_hash: "a".repeat(64),
          row_hash: "b".repeat(64),
          created_at: "2026-06-24T00:00:00Z",
        },
        compliance: {
          disclosure_layer: { status: "Compliant" },
          provenance_layer: { status: "Compliant" },
          watermark_layer: { status: "NotApplicable" },
          retention_layer: { status: "Partial", missing: ["multi-tenant"] },
          rollup: "Partial",
        },
        disclaimers: ["v1: Watermark=NotApplicable"],
      }),
    });
    const res = await client.generateDisclosure({
      ai_system_id: "sys",
      artifact: { kind: "text", content: "x", content_hash: "a".repeat(64) },
      deployer: { name: "Acme", country_code: "DE", sector: "tech" },
    });
    expect(res.compliance.rollup).toBe("Partial");
    expect(res.disclaimers).toContain("v1: Watermark=NotApplicable");
  });

  it("rejects invalid content_hash (zod validation)", async () => {
    await expect(
      client.generateDisclosure({
        ai_system_id: "sys",
        // @ts-expect-error — intentional invalid input
        artifact: { kind: "text", content: "x", content_hash: "tooshort" },
        deployer: { name: "Acme", country_code: "DE", sector: "tech" },
      }),
    ).rejects.toThrow();
  });

  it("POST /v1/verify/provenance passes through to public endpoint", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        verification_id: "v1",
        cose_signature: { valid: true, algorithm: "EdDSA" },
        overall_status: "PASS",
        verified_at: "2026-06-24T00:00:00Z",
        disclaimers: [],
      }),
    });
    const v = await client.verifyProvenance({ coseSign1B64: "c2ln" });
    expect(v.overall_status).toBe("PASS");
  });

  it("raises TrustLayerApiError on 4xx with disclaimers", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({
        error: "invalid",
        disclaimers: ["v1: DORA=Partial"],
      }),
    });
    await expect(client.health()).rejects.toThrow(TrustLayerApiError);
    try {
      await client.health();
    } catch (e) {
      expect(e).toBeInstanceOf(TrustLayerApiError);
      const apiErr = e as TrustLayerApiError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.disclaimers).toContain("v1: DORA=Partial");
    }
  });
});

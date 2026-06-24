/**
 * TrustLayer TypeScript SDK client.
 *
 * Per plan v3.1 §Vertical Slice Spec Block 4 + Round 4 decision:
 * HTTP-only v1 (WASM bundle deferred to v2). Edge-runtime compatible
 * (Cloudflare Workers, Deno, Bun). Uses native fetch (Node 20+, no
 * Node-only APIs).
 *
 * Boundary contract (Architect IC-4):
 * - `orgId` is a CONSTRUCTOR parameter (NOT an env var). Browsers
 *   must always pass it explicitly; Node callers may pass or rely
 *   on the default of "apohara" for the single-tenant v1.
 * - All endpoints accept zod-validated payloads.
 * - The `disclaimers` field in every response is parsed and made
 *   accessible to the caller for transparency (AC-22).
 */
import {
  type DisclosureGenerateRequest,
  DisclosureGenerateRequestSchema,
  type DisclosureGenerateResponse,
  DisclosureGenerateResponseSchema,
  type EvidenceBundleResponse as EvidenceBundleResponseT,
  EvidenceBundleResponseSchema,
  type HealthResponse,
  HealthResponseSchema,
  type VerificationReceipt,
  VerifyProvenanceRequestSchema,
  VerificationReceiptSchema,
} from "./schemas.js";

/** Configuration for the TrustLayer client. */
export interface TrustLayerConfig {
  /** Base URL of the control plane (no trailing slash). */
  baseUrl: string;
  /**
   * Org identifier (per Architect IC-4: OrgId newtype, no env var).
   * Browser builds MUST set this explicitly. Node callers may omit
   * (defaults to "apohara" for single-tenant v1; multi-tenant v1.1
   * will require explicit orgId per request from JWT).
   */
  orgId?: string;
  /** Bearer token for authenticated endpoints. */
  apiKey?: string;
  /** Request timeout in ms (default 30000). */
  timeoutMs?: number;
  /** Custom fetch implementation (for tests, edge runtimes). */
  fetch?: typeof fetch;
}

/** Error with TrustLayer API context (status + body + parsed disclaimers). */
export class TrustLayerApiError extends Error {
  public readonly status: number;
  public readonly body: unknown;
  public readonly disclaimers: string[];

  constructor(
    status: number,
    body: unknown,
    disclaimers: string[] = [],
    message?: string,
  ) {
    super(message ?? `TrustLayer API error ${status}`);
    this.name = "TrustLayerApiError";
    this.status = status;
    this.body = body;
    this.disclaimers = disclaimers;
  }
}

const DEFAULT_BASE_URL = "https://api.trustlayer.apohara.dev";
const DEFAULT_TIMEOUT_MS = 30_000;

export class TrustLayerClient {
  private readonly baseUrl: string;
  private readonly orgId: string | undefined;
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: TrustLayerConfig) {
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.orgId = config.orgId;
    this.apiKey = config.apiKey;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = config.fetch ?? fetch;
  }

  /** GET /health (no auth). */
  async health(): Promise<HealthResponse> {
    const res = await this.request("GET", "/health");
    return HealthResponseSchema.parse(await res.json());
  }

  /**
   * POST /v1/disclosure/generate (auth required).
   *
   * Generates a signed, chained, timestamped disclosure for an
   * AI-generated artifact. Returns the disclosure text + JSON-LD +
   * signed receipt + 4-layer compliance assessment + v1 disclaimers.
   */
  async generateDisclosure(
    req: DisclosureGenerateRequest,
  ): Promise<DisclosureGenerateResponse> {
    const validated = DisclosureGenerateRequestSchema.parse(req);
    const res = await this.request(
      "POST",
      "/v1/disclosure/generate",
      validated,
    );
    const body = await res.json();
    return DisclosureGenerateResponseSchema.parse(body);
  }

  /**
   * POST /v1/verify/provenance (PUBLIC, no auth).
   *
   * Verifies a COSE_Sign1 receipt. Returns PASS/FAIL + reasons per
   * layer + v1 disclaimers.
   */
  async verifyProvenance(args: {
    coseSign1B64: string;
    tsaTokenB64?: string;
  }): Promise<VerificationReceipt> {
    const validated = VerifyProvenanceRequestSchema.parse({
      cose_sign1_b64: args.coseSign1B64,
      tsa_token_b64: args.tsaTokenB64,
    });
    const res = await this.request("POST", "/v1/verify/provenance", validated);
    const body = await res.json();
    return VerificationReceiptSchema.parse(body);
  }

  /**
   * GET /v1/evidence/{bundle_id} (PUBLIC, no auth).
   *
   * Downloads a complete evidence bundle.
   */
  async getEvidenceBundle(bundleId: string): Promise<EvidenceBundleResponseT> {
    if (!bundleId || typeof bundleId !== "string") {
      throw new Error("bundle_id must be a non-empty string");
    }
    const res = await this.request("GET", `/v1/evidence/${encodeURIComponent(bundleId)}`);
    const body = await res.json();
    return EvidenceBundleResponseSchema.parse(body);
  }

  /**
   * Internal HTTP wrapper. Adds JSON headers + bearer token (if set)
   * + timeout. Parses error responses into TrustLayerApiError.
   */
  private async request(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": `@apohara/trustlayer/0.1.0`,
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await this.fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const errBody = await this.safeJson(res);
        const disclaimers = Array.isArray((errBody as { disclaimers?: unknown })?.disclaimers)
          ? ((errBody as { disclaimers: string[] }).disclaimers)
          : [];
        throw new TrustLayerApiError(res.status, errBody, disclaimers);
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  private async safeJson(res: Response): Promise<unknown> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
}

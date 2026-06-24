/**
 * @apohara/trustlayer — HTTP-only TypeScript SDK.
 *
 * Per plan v3.1 §Vertical Slice Spec Block 4: this is the v1 SDK.
 * WASM bundle deferred to v2 (Q3 2026). napi-rs addon deferred to v3.
 *
 * @example
 * ```ts
 * import { TrustLayerClient } from "@apohara/trustlayer";
 *
 * const client = new TrustLayerClient({ baseUrl: "https://api.trustlayer.apohara.dev" });
 * const disclosure = await client.generateDisclosure({
 *   ai_system_id: "my-system-v1",
 *   artifact: { kind: "text", content: "Hello", content_hash: "a".repeat(64) },
 *   deployer: { name: "Acme", country_code: "DE", sector: "tech" },
 * });
 * console.log(disclosure.disclosure_text, disclosure.compliance.rollup);
 * ```
 */
export {
  TrustLayerClient,
  TrustLayerConfig,
  TrustLayerApiError,
} from "./client.js";

export type {
  ArtifactKind,
  ComplianceStatus,
  Artifact,
  Deployer,
  DisclosureOptions,
  DisclosureGenerateRequest,
  DisclosureGenerateResponse,
  VerificationReceipt,
  HealthResponse,
} from "./schemas.js";

// Re-export zod schemas for callers that want to validate payloads outside the client.
export {
  ArtifactSchema,
  DeployerSchema,
  DisclosureGenerateRequestSchema,
  DisclosureGenerateResponseSchema,
  VerifyProvenanceRequestSchema,
  VerificationReceiptSchema,
  EvidenceBundleResponseSchema,
  HealthResponseSchema,
} from "./schemas.js";

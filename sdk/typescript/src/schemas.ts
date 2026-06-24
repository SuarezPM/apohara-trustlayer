/**
 * Zod schemas (runtime validation) for TrustLayer API request/response bodies.
 *
 * Per plan v3.1 §Vertical Slice Spec + Block 4: SDK uses zod (peer dep)
 * to validate at the runtime boundary. No `any` types (CLAUDE.md §3).
 */
import { z } from "zod";

// =============================================================================
// Shared enums
// =============================================================================

export const ArtifactKindSchema = z.enum([
  "text",
  "image",
  "audio",
  "video",
  "model_output",
  "agent_trace",
]);
export type ArtifactKind = z.infer<typeof ArtifactKindSchema>;

export const ComplianceStatusSchema = z.enum([
  "Compliant",
  "Partial",
  "NonCompliant",
  "Unknown",
  "NotApplicable",
]);
export type ComplianceStatus = z.infer<typeof ComplianceStatusSchema>;

// =============================================================================
// Disclosure generation
// =============================================================================

export const ArtifactSchema = z.object({
  kind: ArtifactKindSchema,
  content: z.string().min(1),
  content_hash: z
    .string()
    .length(64, "content_hash must be 64-char hex (SHA-256)"),
});
export type Artifact = z.infer<typeof ArtifactSchema>;

export const DeployerSchema = z.object({
  name: z.string().min(1),
  country_code: z
    .string()
    .length(2, "country_code must be ISO 3166-1 alpha-2"),
  sector: z.string().min(1),
});
export type Deployer = z.infer<typeof DeployerSchema>;

export const DisclosureOptionsSchema = z.object({
  include_watermark_hook: z.boolean().default(false),
  tsa_provider: z
    .enum(["mock", "free_tsa", "digicert"])
    .default("mock"),
  policy_strategies: z
    .array(z.enum(["article_50", "dora"]))
    .default(["article_50", "dora"]),
});
export type DisclosureOptions = z.infer<typeof DisclosureOptionsSchema>;

export const DisclosureGenerateRequestSchema = z.object({
  ai_system_id: z.string().min(1),
  artifact: ArtifactSchema,
  deployer: DeployerSchema,
  options: DisclosureOptionsSchema.default({
    include_watermark_hook: false,
    tsa_provider: "mock",
    policy_strategies: ["article_50", "dora"],
  }),
});
export type DisclosureGenerateRequest = z.infer<typeof DisclosureGenerateRequestSchema>;

export const ComplianceLayerStatusSchema = z.object({
  status: ComplianceStatusSchema,
  verified_at: z.string().nullable().optional(),
  evidence_refs: z.array(z.string()).default([]),
  missing: z.array(z.string()).default([]),
  reason: z.string().nullable().optional(),
  violations: z.array(z.string()).default([]),
});

export const SignedReceiptSchema = z.object({
  receipt_id: z.string(),
  cose_sign1_b64: z.string(),
  tsa_token_b64: z.string().nullable().optional(),
  tsa_url: z.string().nullable().optional(),
  prev_hash: z.string(),
  row_hash: z.string(),
  created_at: z.string(),
});

export const DisclosureGenerateResponseSchema = z.object({
  disclosure_id: z.string(),
  disclosure_text: z.string(),
  disclosure_html_widget: z.string(),
  json_ld: z.record(z.unknown()),
  c2pa_manifest_ref: z.record(z.unknown()).nullable().optional(),
  receipt: SignedReceiptSchema,
  compliance: z.object({
    disclosure_layer: ComplianceLayerStatusSchema,
    provenance_layer: ComplianceLayerStatusSchema,
    watermark_layer: ComplianceLayerStatusSchema,
    retention_layer: ComplianceLayerStatusSchema,
    rollup: z.enum(["Compliant", "Partial", "NonCompliant", "Unknown"]),
  }),
  // AC-22: anti-greenwashing disclaimers.
  disclaimers: z.array(z.string()),
});
export type DisclosureGenerateResponse = z.infer<typeof DisclosureGenerateResponseSchema>;

// =============================================================================
// Verification
// =============================================================================

export const VerifyProvenanceRequestSchema = z.object({
  cose_sign1_b64: z.string(),
  tsa_token_b64: z.string().optional(),
  expected_payload_cbor_b64: z.string().optional(),
});

export const VerificationReceiptSchema = z.object({
  verification_id: z.string(),
  cose_signature: z.record(z.unknown()),
  tsa_verification: z.record(z.unknown()).nullable().optional(),
  chain_verification: z.record(z.unknown()).nullable().optional(),
  key_verification: z.record(z.unknown()).nullable().optional(),
  overall_status: z.enum(["PASS", "FAIL"]),
  verified_at: z.string(),
  disclaimers: z.array(z.string()),
});
export type VerificationReceipt = z.infer<typeof VerificationReceiptSchema>;

// =============================================================================
// Evidence bundle
// =============================================================================

export const EvidenceBundleResponseSchema = z.object({
  bundle_id: z.string(),
  created_at: z.string(),
  disclosures: z.array(z.record(z.unknown())),
  key_chain: z.record(z.unknown()),
  signature: z.record(z.unknown()),
  tsa_token: z.record(z.unknown()).nullable().optional(),
  verification_instructions: z.string(),
  disclaimers: z.array(z.string()),
});

// =============================================================================
// Health
// =============================================================================

export const HealthResponseSchema = z.object({
  status: z.enum(["ok", "degraded", "down"]),
  version: z.string(),
  org_id: z.string(),
  tsa_provider: z.string(),
  disclaimers: z.array(z.string()),
});
export type HealthResponse = z.infer<typeof HealthResponseSchema>;

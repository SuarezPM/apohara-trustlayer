# TrustLayer Threat Model — STRIDE-per-component

**Generated:** 2026-06-24
**Scope:** STRIDE analysis of the 5 components of the TrustLayer platform.
**Methodology:** Per STRIDE classification, each component analyzed for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.

---

## 1. `tl-*` Rust crypto crates (`tl-chain`, `tl-evidence`, `tl-receipt`, `tl-gate`, `tl-aibom`, `tl-compliance`, `tl-orchestrator`, `tl-frontend`, `tl-types`)

### Spoofing
- **Risk:** Attacker forges COSE_Sign1 signatures using a stolen private key.
- **Mitigation:** Ed25519 keypair is per-tenant, derived from HKDF-SHA256(master_seed, tenant_id). Master seed lives in HSM (production) or file (dev). tl-evidence::signer::signer_for_tenant is NEVER exposed to Python SDK (Architect IC-2 strict).
- **Residual risk:** Master seed compromise → all tenants compromised. Mitigation: HSM + quarterly rotation.

### Tampering
- **Risk:** Attacker modifies a hash chain entry's payload after it's been signed.
- **Mitigation:** BLAKE3 hash chain with append-only semantics; each row's row_hash includes chain_id, row_number, prev_hash, payload, cose_sign1_b64, created_at. Modifying any field changes the row_hash, breaking the chain.
- **Residual risk:** Control plane must use `SELECT ... FOR UPDATE` on chain head row (serializes appends). v1 control plane scaffold enforces this at the DB role level (not application level).

### Repudiation
- **Risk:** Issuer claims they didn't issue a disclosure.
- **Mitigation:** Each row_hash is deterministically derived and cryptographically signed via COSE_Sign1. The signature includes the row_hash, binding issuer to content. Disclosure records are INSERT-only (no UPDATE/DELETE at DB role level).

### Information Disclosure
- **Risk:** Signed receipt leaks sensitive data (e.g., PII in payload).
- **Mitigation:** Payload is the AI-generated content; the receipt does not include server-side context (org_id is a public identifier; tenant_id may be sensitive but is only included in the disclosure text per EU AI Act Art. 50).
- **Residual risk:** DORA Art. 19-20 evidence pack may contain operational metadata. v1.1 will add field-level redaction.

### Denial of Service
- **Risk:** Attacker floods the chain with high-cost signatures.
- **Mitigation:** SignerService is cached per-tenant (HKDF derivation is constant-time, not slow). Verification is constant-time. BLAKE3 hashing is hardware-accelerated.
- **Residual risk:** No rate limit on signing (only on verify endpoint). v1.1: per-tenant signing rate limit.

### Elevation of Privilege
- **Risk:** Bug in Rust core allows RCE via crafted input.
- **Mitigation:** Memory safety (Rust); no unsafe code in tl-* (workspace-wide `#![deny(unsafe_code)]` is in v1.1 scope); input validation on all external boundaries (COSE_Sign1 size limits, chain_id format).

---

## 2. `tl-ffi` PyO3 binding

### Spoofing
- **Risk:** Attacker forges PyO3 extension to leak private key.
- **Mitigation:** tl-ffi exposes ONLY `verify_*` and `hash_*` functions. NO `sign_*` exposed. `sign_envelope` is internal to the Rust crate.
- **Residual risk:** A malicious tl-ffi PyO3 extension could still perform OOB reads/writes. Mitigation: PyO3 uses Rust memory safety; verify wheel signature (SLSA L3 + sigstore) before install.

### Tampering
- **Risk:** Malicious PyO3 overrides legitimate verify functions.
- **Mitigation:** Wheel signed via `cargo-dist` + sigstore (v1.1); pip install verifies wheel signature.

### Information Disclosure
- **Risk:** PyO3 extension leaks process memory.
- **Mitigation:** PyO3 isolates the Rust runtime; no unsafe shared state.

### Elevation of Privilege
- **Risk:** PyO3 enables arbitrary Rust execution in Python process.
- **Mitigation:** PyO3 sandbox prevents syscalls beyond what Python allows; all Rust code is memory-safe.

---

## 3. `tl-mcp-server` (rmcp 1.8)

**NOTE:** US-13 is BLOCKED on rmcp 1.8 macro. Threat model analysis applies when the macro integration is resolved (US-13 follow-on).

### Spoofing
- **Risk:** Malicious MCP host (e.g., compromised Claude Code) sends forged tool inputs to extract secrets.
- **Mitigation:** `sign_artifact` requires caller to be authenticated against the control plane. tl-mcp-server forwards to the control plane which enforces auth.

### Information Disclosure
- **Risk:** MCP server exposes more data than the caller is authorized for.
- **Mitigation:** Each tool returns redacted projections of full data; org_id is a public field but tenant_id is gated per-request.

---

## 4. `services/control_plane/` (FastAPI)

### Spoofing
- **Risk:** Attacker forges JWT to access authenticated endpoints.
- **Mitigation:** JWT signed with HS256 (v1) or RS256 (v1.1 with external IDP); audience claim enforces single-audience tokens; expires_in < 1 hour.

### Tampering
- **Risk:** Attacker modifies audit records.
- **Mitigation:** INSERT-only tables (DB role enforcement). Even the control plane app role lacks UPDATE/DELETE on these tables.

### Information Disclosure
- **Risk:** Sensitive data leaks via error messages or stack traces.
- **Mitigation:** structlog for structured logging; PII redaction by default; stack traces only in dev environment.

### Denial of Service
- **Risk:** Attacker floods `/v1/verify/provenance` (public, no auth).
- **Mitigation:** `slowapi` rate limit: 60 req/min per IP unauth, 1000 req/day. k8s multi-replica with in-memory rate limits (per-replica count).

### Elevation of Privilege
- **Risk:** Bug in FastAPI handler allows RCE.
- **Mitigation:** FastAPI's Pydantic v2 input validation at the boundary. Append-only audit tables (even an RCE in the app cannot delete audit data).

---

## 5. `apohara-agentguard` (seccomp+Landlock sandbox)

### Information Disclosure
- **Risk:** Sandbox escape allows process to read outside the allowed path.
- **Mitigation:** Landlock filesystem policy + seccomp-bpf syscall filter enforced at agent start. Default-deny posture (allowlist only safe syscalls).

### Denial of Service
- **Risk:** Agent is resource-starved by malicious input.
- **Mitigation:** seccomp-bpf blocks fork-bomb syscalls; Landlock quotas file descriptors; tokio task budget enforced at runtime.

---

## Cross-cutting risks

### R10 (signing key compromise)
- **Risk:** All tenants compromised if master signing key leaks.
- **Mitigation:** Master key in HSM (production); never in code or env file. v1.1: KeyRotationPolicy with grace period.

### R12 (EU AI Act deadline)
- **Risk:** v1 ships after 2 August 2026.
- **Mitigation:** 39 days remaining; vertical slice is achievable; manual review gate before public push.

### R15 (PyO3 wheel supply chain)
- **Risk:** Compromised PyPI package backdoors the verify path.
- **Mitigation:** SLSA L3 provenance attestation for the wheel; sigstore-signed wheel; pip install verifies (v1.1).

### R18 (RFC 3161 bundle size)
- **Risk:** Evidence bundle grows unbounded with TSA tokens.
- **Mitigation:** Bundle size budget < 5 MB / 100 disclosures (AC-18). Strategy: TSA token deduplication per chain_id (one token per chain, not per disclosure) OR Merkle anchoring (v1.1).

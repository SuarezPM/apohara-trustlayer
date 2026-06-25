# Watermark subprocess threat model (v1.1.1, Plan v1.2 Block 4 v1.1.1)

> **Generated:** 2026-06-25
> **Source:** Plan v1.2 Block 4 v1.1.1 (closes auditor-4 BRECHA 3)
> **Threat-model gate:** per Plan v3.1 §Risks R-NEW-W1 to W3

This document enumerates the risks of the watermark subprocess path
(c2patool via firejail) and the corresponding mitigations. **No
v1.1.1 release goes out without this document being publicly
documented in the audit_artifacts/threat_model/ directory.**

## What this watermarker does

Per EU AI Act Art. 50(3), content flagged as AI-generated must carry
a watermark. TrustLayer v1.1.1 ships three watermark providers
(`crates/tl-watermark/`):

1. `C2paWatermark` — embeds a C2PA manifest (image + video) via
   the `c2patool` CLI.
2. `AudioSealWatermark` — embeds a Meta AudioSeal signal (audio).
3. `KirchenbauerTextWatermark` — biases LLM logits via the
   Kirchenbauer et al. (2023) algorithm (text).

`C2paWatermark` invokes `c2patool` as a subprocess wrapped in
`firejail` (sandboxing per the locked user decision: "watermark sandbox:
firejail — more portable across distros, audit trail built-in").

## Threat surface

The subprocess receives:
- A user-supplied input file (any bytes; we don't pre-filter)
- A user-supplied output path (writable, can be /tmp/* or similar)
- The `APOHARA_LEDGER_HMAC_KEY` env var (passed through firejail's env)
- A TLS cert chain (bundled with c2patool; we pass via firejail fs-bind)

The subprocess can:
- Read its input file
- Write its output file
- Spawn children (c2patool may invoke other tools)
- Read environment variables passed via firejail
- Make outbound network calls (c2patool validates cert chains online by default)

The subprocess CANNOT (with firejail hardening):
- Read files outside the workspace or /tmp
- Write files outside /tmp
- Access the network (we explicitly `--no-net` in production)
- Access the host's secret material (we don't pass any env var except
  `APOHARA_LEDGER_HMAC_KEY`, and even that is rate-limited via
  firejail's `--rlimit-fsize` and `--rlimit-cpu`)

## Risks (R-NEW-W1 to W3)

### R-NEW-W1: Arbitrary code execution via malicious input

**Risk**: A user uploads a PNG that exploits a `c2patool` bug
(e.g. parser buffer overflow). The sandbox is breached; c2patool
runs arbitrary code as the control-plane user.

**Severity**: HIGH (P0 — direct code execution in our process)

**Mitigation** (stack):
1. **firejail** (REQUIRED) — `--read-only=/` so c2patool cannot write
   outside /tmp; `--tmp=/tmp` to scope writes; `--no-net` so no
   outbound connections; `--rlimit-as=8G` to bound memory.
2. **c2patool-specific** — pin c2patool to a known-good version
   (Adoptium-style 6-month release cycle; no nightly).
3. **Audit** — every c2patool execution is logged to the audit
   trail with input sha256 + output sha256 + firejail exit code.
4. **Honest disclosure** — the README states: "v1.1.1 watermark
   path uses c2patool via firejail. **Production deployments MUST
   install firejail ≥ 0.9.66 + c2patool ≥ 0.10.0**; missing
   firejail = loud error (per IC-3, no silent fallback)."

### R-NEW-W2: Filesystem access outside the workspace

**Risk**: A successful c2patool exploit could read
`/etc/passwd`, write to `/etc/cron.d/`, etc.

**Severity**: MEDIUM (post-sandbox breach)

**Mitigation**:
1. firejail's `--read-only=/` makes the entire filesystem read-only
   EXCEPT /tmp.
2. firejail's `--tmp=/tmp` whitelists writes to /tmp only.
3. We pass `APOHARA_LEDGER_HMAC_KEY` via firejail's `--env`
   (not via inherited env), so the secret is scoped to the
   sandbox child.
4. **No re-mount of host paths** — we never use `--bind` to expose
   host paths into the sandbox.

### R-NEW-W3: Outbound network exfiltration

**Risk**: A successful c2patool exploit could send the user's
input file + our internal HMAC key to an attacker-controlled server.

**Severity**: HIGH (data exfiltration)

**Mitigation**:
1. firejail's `--no-net` flag (set in the production wrapper, not
   in tests) — this drops the network namespace entirely. c2patool
   cannot make any TCP/UDP/ICMP/Unix-socket calls.
2. **Cert chain validation offline** — c2patool's default behavior
   is to validate C2PA issuer certs against Adobe's hosted
   truststore. This is NOT possible with `--no-net`; we configure
   c2patool to use a bundled offline truststore (`--trust-store
   /opt/apohara-trustlayer/c2pa-truststore.pem`).
3. **Audit** — every c2patool execution is logged; an unexpected
   `--no-net` failure surfaces as `Err(WatermarkError::ApplyFailed(_))`
   to the control plane (loud error, no silent fallback).

## What is NOT in scope

- **Hardware attacks** (Rowhammer, Spectre, etc.) — out of scope;
  hardware-level mitigations are the responsibility of the
  deployment host.
- **Network attacks on the control plane** — out of scope; the
  control plane's own threat model is `audit_artifacts/threat_model/STRIDE.md`.
- **Compromise of firejail itself** — out of scope; the deployment
  is responsible for using a recent firejail from a trusted source.

## v1.1.1 stub implementations

Per the locked user decision (scope = conservative + honest), the
v1.1.1 commit ships **stub implementations** for the three providers:

- `C2paWatermark::apply` invokes the real `c2patool` subprocess
  (production path; gated on firejail availability).
- `AudioSealWatermark::stub()` produces a deterministic marker
  (sufficient for integration tests; the real Meta AudioSeal model
  is a 2-3 day PyO3 + ONNX task deferred to a follow-up commit).
- `KirchenbauerTextWatermark::new(key)` implements the green-list
  algorithm per the paper (production-quality code, no FFI, no
  model calls).

The stubs are honest (named `_stub` in the public surface) and
the error path is loud (per IC-3). Production deploys wire the
real models; the test infrastructure uses the stubs.

## Reviewer checklist

- [ ] All 3 risks have explicit mitigations
- [ ] Mitigations are concrete (not "use best practices")
- [ ] `firejail` is the only sandbox (no alternative paths)
- [ ] `--no-net` is set in production
- [ ] `--read-only=/` is set in production
- [ ] Audit trail captures every execution
- [ ] Honest disclosure in README mentions the 3 risks

## See also

- `crates/tl-watermark/src/lib.rs` — the implementation with
  detailed docstrings.
- `audit_artifacts/spec_facts_audit.md` — v1.1.x spec reconciliation
  (the Art. 50(3) gap is explicitly closed in v1.1.1).
- `README.md` §"NotApplicable" — the honest disclosure that
  pre-v1.1.1 is `WatermarkLayer::NotApplicable`; v1.1.1 flips it
  to `Compliant` when one of the three providers is configured.

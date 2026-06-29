# Apohara TrustLayer — Auditor Wiring + Code-Quality Roadmap (end-to-end)

**Source:** external auditor report (`AUDITORÍA TÉCNICA — APOHARA TRUSTLAYER v3.0+W9+ULT.md`) + 2 deep code audits (themis-orchestrator, apohara-agentguard) + `.omo/` wave files + README "WAIT for". Business items explicitly excluded.

**Baseline (verified green before this plan):** `cargo build --workspace` 0 errors · `cargo test --workspace` 1542 passed 0 fail · pytest 295 passed / 12 skipped / 4 xfailed 0 fail. Prior session already fixed: tl-mcp-server lib/bin build break, dead imports sweep, agentguard secret-name unification (F18), pld.py `Optional` import, de-submodule of apohara-agentguard.

## Resolved strategic decisions (from interview)

1. **Unwired themis modules — split disposition:** 3 defense (circuit_breaker/human_guard/rogue_monitor) → wire into agent loop behind cargo `defense` feature (default off); 3 test-only (mcp_proxy/dual_llm/context) → `#[cfg(test)]`; routing_config → wire into bin; 2 orphans (featherless_openclaw/subprocess) → delete.
2. **Adversarial fixtures — real behind flag + honest verdict:** `run_scenario` calls real OASB subprocess / agentdojo API when `TL_ADVERSARIAL_LIVE=1`; else verdict = `CONTROL_REGISTERED` (not `PASS`). Live path mockable for CI.
3. **Production boundary — ready-to-execute, no live creds:** code + migration + config + deploy scripts/docs gated by env. Operator with creds runs the live path. No secrets touched.
4. **Code-quality scope — ALL debt:** includes god-object refactors, process_invoice extraction, full dedup, ruff. Maximum quality.

## Auditor inaccuracies corrected (ground plan in actual code, not the report)

- **HSM IS wired:** `services/control_plane/app/main.py:78-86` calls `get_signer()` and injects `signer=signer` into `NotaryServiceProduction`; `notary/service.py:104` uses `self.signer.algorithm()` in the COSE protected header. Gap = creds/env + test, NOT code.
- **Verification page IS backend-served:** `app/verification_page.py` serves `GET /verify/{cert_id}` (HTML L1/L2/L3) + `GET /v1/verify/{cert_id}` (JSON). Gap = the `verification_steps` are placeholders (`verification_page.py:159-164` "placeholder signature in dev", "L3 production: TODO") — L3 crypto is NOT computed.
- **Notary store is SQLite, NOT Postgres:** `notary/db.py` uses `sqlite3` + `notary.db` (262KB at repo root). `db/session.py` uses asyncpg/Postgres for other models. The notary certificate store was never migrated (docstring `notary/db.py:4-5` admits "W3.0 W3.2 deferred").
- **Adversarial "PASS" is control-presence, not execution:** `adversarial_scaffold.py:35-44` returns PASS if a CordonEnforcerMapping entry exists; real OASB/AgentDojo/ATLAS fixtures are NOT executed (.omo wave3 deferred).

---

## Phase 0 — Baseline hardening & safe cleanups (zero behavior change)

**Gate:** `cargo build --workspace` 0 err · `cargo test --workspace` 1542+ pass 0 fail · pytest 295+ pass 0 fail.

- **P0.1 Python ruff safe auto-fix:** apply `ruff check --fix` for F401 (29 dead imports), F811 (double-import `notary/service.py:300` APIRouter/HTTPException/status redefined from line 25), F841 (9 unused vars). Manual review of remaining F-rules. Skip PLC0415/UP045/RUF022 style-only unless trivial.
- **P0.2 Bare excepts (auditor B1):** the 7 `# noqa: BLE001` sites (`qes_adapter.py:578`, `rfc9162_verifier.py:294`, `notary/scitt.py:84`, `middleware/__init__.py:117,147`, `domain/disclosure_service.py:267`, `db/session.py:95`) currently share generic boilerplate "intentional degraded mode". Replace each with a SPECIFIC per-site justification (e.g. "SCITT submission is best-effort; must not block primary cert generation"). Then triage the ~13 unmarked `except Exception as e:` (`qes_adapter.py:187,226,365,403,446,524,539,639`, `notary/service.py:227,258,353`, `certificate_generator.py:163,229`, `qtsp.py:97,114`, `catalyst_production.py:130,168`, `notary/scitt.py:149`, `rfc9162_verifier.py:274`): either add `# noqa: BLE001` + specific justification, or narrow to the concrete exception type.
- **P0.3 agentguard dead-code cleanups:** `is_compound` (`gate/compound.rs:127`) → `#[cfg(test)]` (test-only). Decide `extra_seps` param on `split_compound_with_separators` (`gate/compound.rs:32`) — route gate IFS resplit through it OR drop the param (gate/mod.rs:140-158 does ad-hoc rewrite).
- **P0.4 themis orphans deletion:** delete `crates/themis-orchestrator/src/featherless_openclaw/` (192L, 0 refs) and `src/subprocess.rs` (188L, declared in lib.rs:111, never imported). Remove their `mod` declarations from lib.rs.

---

## Phase 1 — Latent bug fixes (security / correctness)

**Gate:** green (as above).

- **P1.1 agentguard F16 — glob matcher drift (latent bug):** 4 matchers with divergent `*`/empty semantics: `config.rs:309 glob_match` (anchored), `hook/mod.rs:452 arg_pattern_matches`, `policy/matcher.rs:21 pattern_matches` (canonical, `pub(crate)`), `gate/mod.rs:319 custom_block_matches`. `matcher.rs:2-13` + `:52` explicitly warn they "CANNOT drift" yet they have (`pattern_matches("*","")`=false vs `arg_pattern_matches("*","")`=true). Unify `arg_pattern_matches` + `custom_block_matches` bodies to delegate to `pattern_matches`. Decide anchored vs non-anchored: gate/config want non-anchored contains-of-parts; keep `glob_match` anchored only if allow-list genuinely needs it (document why).
- **P1.2 agentguard F18 — secret-name unification:** DONE in prior session (`secrets.rs`). Verify still in place; no action unless regressed.
- **P1.3 agentguard F9 — `.expect()` on poisoned mutex (hot path):** `policy/engine.rs:245` `self.counters.lock().expect("budget mutex poisoned")` → map to `PolicyError::Poisoned` (add variant) or `Verdict::block("policy budget lock poisoned")` (fail-closed posture consistent with the crate).
- **P1.4 agentguard F10 — 5× `unreachable!()` on `Tier::Ask`:** `main.rs:161,193`, `policy/engine.rs:221`, `hook/mod.rs:427`, `firewall/mod.rs:107`. Replace with safe fallback (`Tier::Allow` / `Verdict::allow()` / `continue`) OR model Ask-exclusion in the type system (`SevTier` newtype). At minimum document the invariant at source `verdict.rs:110 severity_to_tier`.
- **P1.5 themis F12 — `.expect()` on `Result` non-infallible:** `orchestrator.rs:518` (`.expect("...infallible for our types")` on a `Result<Vec<u8>, serde_json::Error>`) and `packet.rs:160` (`blake3_hash()` `.expect(...)`). Propagate via `OrchestratorError::Evidence` / `PacketError`. `tenants.rs:180-184` `panic!` in `with_default_tenants()` → `Result`.
- **P1.6 themis F13 — O(n²) clone:** `orchestrator.rs:313` `decisions.iter().cloned()` per stage clones the growing vector × 8 stages. Change `AgentContext::with_upstream_stream` to take `&[AgentDecision]` (or `Arc<[...]>`); `orchestrator.rs:333` `decisions.push(decision.clone())` → move where possible.

---

## Phase 2 — Safe de-duplication (DRY, no behavior change)

**Gate:** green.

- **P2.1 agentguard F15 — `Tier::rank` ×5:** add `pub fn rank(self) -> u8` on `Tier` in `verdict.rs` (canonical ordering test already at `verdict.rs:158`); delete `hook/mod.rs:484 tier_rank`, `policy/engine.rs:373 tier_rank_local`, `main.rs:240,423,529` inline `rank` ×3.
- **P2.2 agentguard F17 — `lookup_arg` ×2:** `hook/mod.rs:439` and `policy/engine.rs:319` byte-identical dotted-JSON-path walker → single `pub(crate)` (e.g. `hook::contract::HookInput::lookup_arg` or a `util` mod).
- **P2.3 agentguard F19/F20/F21 — helpers ×3:** `truncate`/`truncate_bytes`/`cap_reason` (`gate/mod.rs:391`, `audit.rs:161`, `hook/contract.rs:282`) → one `pub(crate) fn truncate_char_boundary`; `strip_quotes` (`gate/normalize.rs:428`, `gate/resolve.rs:67`, `gate/decode.rs:82`) → one `pub(crate)`; paren/backtick extractors (`gate/compound.rs:206,236` vs `gate/normalize.rs:354,375`) → unify on the `compound` versions (handle escapes, return `(String, usize)`).
- **P2.4 themis F14 — `StubAgent` ×4:** `orchestrator.rs:655`, `http.rs:940`, `bin/themis-orchestrator.rs:196`, `tests/a2a_discovery.rs:43` → single fixture-aware `StubAgent` in `test_support.rs`.
- **P2.5 themis F16 — agent pipeline table ×5:** `orchestrator.rs:242-290` stages, `:342-351` agent_role match, `:613-625` next_agent_mention, `:752-760` + `http.rs:968-1000` test pairs, `bin:211-219` → single `const AGENT_PIPELINE: &[(&str, InvoiceState, DecisionType, AgentRole, &[&str])]`.
- **P2.6 themis F15 — `build_default_state` ×3:** `http.rs:113-138`, `test_support.rs:495`, `http.rs:964` inline test → one constructor + builder-style overrides.
- **P2.7 themis F17/F18 — a2a_handler boilerplate:** `a2a_handler.rs:449-572` (131L, 7 sequential match blocks), repeated in `handle_message_send:221`, `handle_tasks_get:352` (~12 sites) → `require_str(params, "field")` / `require_obj` helpers.

---

## Phase 3 — Wire the unwired (split disposition)

**Gate:** green + new tests for each wired path pass.

- **P3.1 themis defense modules → cargo feature `defense` (default off):** wire `circuit_breaker.rs` (wrap agent calls in `process_invoice`), `human_guard.rs` (gate destructive ops), `rogue_monitor.rs` (monitor agent loop) into the agent-loop path under `#[cfg(feature = "defense")]`. Add `defense` to `crates/themis-orchestrator/Cargo.toml` `[features]`. Add tests under `#[cfg(feature = "defense")]` for each wired path. Default build (feature off) preserves current behavior → zero regression risk.
- **P3.2 themis test-only → `#[cfg(test)]`:** `mcp_proxy.rs`, `dual_llm.rs`, `context.rs` (verify_and_send) → gate module declarations + their integration tests. Keep `tests/*_e2e.rs` working.
- **P3.3 themis routing_config → wire into bin:** `bin/themis-orchestrator.rs` currently calls `build_routed_dispatch` using `routing.rs` constants directly, bypassing `routing_config.rs`. Wire `RoutingConfig::load_or_default()` (`routing_config.rs`) at startup to feed `build_routed_dispatch`. Add test that a `routing.toml` override is honored.
- **P3.4 themis dead Events → publish or remove:** `events.rs:34 Event::AgentCompleted`, `:48 Event::BaaarHalt` have 0 production publish sites. Publish `AgentCompleted` at the end of the agent loop; publish `BaaarHalt` where the BAAAR `Outcome::Halt` is detected (`orchestrator.rs` halt path). If a variant is genuinely unused, remove it.
- **P3.5 adversarial real-behind-flag:** `app/adversarial_scaffold.py run_scenario` — when `TL_ADVERSARIAL_LIVE=1`, invoke real OASB v0.3.2 (Node.js subprocess at `services/control_plane/oasb_runtime/oasb/`) for OASB scenarios, real agentdojo v0.1.35 Python API for AgentDojo scenarios, CordonEnforcer-control-VERIFIED for ATLAS. Else verdict = `CONTROL_REGISTERED` (rename from `PASS`); `NOT_RUN` reserved for scenarios with no mapping. Make live path mockable (env `TL_ADVERSARIAL_LIVE_MOCK=1` stubs the subprocess) so CI stays green without Node.js/transformers. Update `app/api/adversarial.py` responses + tests.
- **P3.6 verification page L3 real crypto:** `app/verification_page.py:156-165` placeholder steps → real computation: (a) recompute content hash (blake3/sha256) and compare to stored; (b) verify COSE_Sign1 signature against issuer public key (fingerprint lookup); (c) verify TSA token via `qes_adapter` pyhanko/CMS path; (d) verify SCITT/Rekor inclusion via `app/rfc9162_verifier.py verify_inclusion_proof` (public surface: `reconstruct_root_rfc9162`, `verify_inclusion_proof`, `verify_federated_receipt`, `extract_sth_root`). Render per-step pass/fail with real evidence. The JSON `verify_api` (`:170`) likewise returns real `verification_steps`.

---

## Phase 4 — Structural refactors (god-objects, big functions) — isolated, higher risk

**Gate:** green after EACH sub-item (commit per item to localize regressions).

- **P4.1 themis F8/F1 — AppState encapsulation:** `http.rs:44-105` (13 `pub` fields, handlers mutate DashMaps directly) → private fields + typed methods `store_run`, `get_packet`, `store_sealed` preserving the packet_id key-aliasing invariant across the 3 DashMaps.
- **P4.2 themis F6 — Orchestrator god-object:** `orchestrator.rs:69-94` (8 fields / 7 responsibilities) → extract `AgentRegistry`, `RekorAnchoring`, `EvidenceSealing` collaborators; Orchestrator coordinates.
- **P4.3 themis F9 — process_invoice 268L:** `orchestrator.rs:209-474` (5 nesting levels, duplicated halt paths) → extract `run_agent_stage`, `publish_provider_event`, `publish_handoff_event`, `check_baaar_and_maybe_halt`, `force_advance_to_done`, `halt_and_return` (single helper for the duplicated assemble+sign+return).
- **P4.4 themis F10 — get_packet_json 245L:** `http.rs:632-847` (hand-builds 25-field JSON map) → `FlattenedPacketWireFormat` struct `#[derive(Serialize)]` + `from_signed(&SignedPacket, Option<&SealedPacket>)`; handler becomes ~10 lines.
- **P4.5 themis F3/F4/F5 — pub fields → private + getters:** `packet.rs:95 EvidencePacket` (9 pub), `packet.rs:168 SignedPacket` (5 pub incl. crypto), `tenants.rs:31 Tenant` (4 pub), `dual_llm.rs:123 DualLlm`. `blake3_hash_hex` computed not settable. `attach_peer_verdict` used instead of direct field mutation.
- **P4.6 agentguard F5/F6/F7/F8 — encapsulation:** `lib.rs:5-13` whole `pub mod` tree → `pub(crate)` internals + selective `pub use` re-export of the ~10 real API symbols; `config.rs:236 EnvDisable` → `pub(crate)`; `verdict.rs:35 Verdict` → add `pub rule_id: Option<String>` + `pub category: Option<String>` (or `provenance: Option<RuleRef>`), set at construction, delete `parse_rule_label` (`hook/mod.rs:166-185`); `config.rs:72 Config` (13 fields) → nest `GateConfig`/`FirewallConfig`/`KillSwitch` sub-structs (follow existing `[audit]`/`[canary]`/`[policy]` pattern).

---

## Phase 5 — Production-ready (ready-to-execute, no live creds)

**Gate:** green + ready-to-execute scripts run with fixtures (not real endpoints).

- **P5.1 NotaryDB SQLite → Postgres (A4):** add `CertificateRecord(Base)` SQLAlchemy model in `db/models.py` following `DisclosureRecord` pattern (18 cols + UNIQUE(content_hash,submitted_by) + 2 indexes, per `notary/db.py:45-69` SCHEMA). Make `NotaryDB` async (asyncpg for prod, aiosqlite for dev fallback via `DATABASE_URL` scheme). Migrate `verification_page.py` module-global `_db` to async (endpoints already `async def`). Add `app/notary/schema.sql` DDL following `risk_scoring/schema.sql` pattern. Data migration script `scripts/migrate_notary_sqlite_to_pg.py` (read `notary.db`, write to Postgres). Keep `notary.db` for dev. Update `main.py` NotaryDB construction.
- **P5.2 Postgres prod-grade config (B2, auditor):** `config.py` DATABASE_URL supports SSL (`DATABASE_URL_SSL=verify-full`), connection pooling (pool_size/max_overflow), at-rest encryption + PITR/backups documented in `docs/POSTGRES_PROD_DEPLOY.md` (RDS/Supabase, no real creds). Verify `db/session.py create_async_engine` honors SSL args.
- **P5.3 HSM live test + deploy doc (B3, auditor):** add `tests/test_hsm_signing.py` — inject a fake `HSMSigner` returning `algorithm()=="ML-DSA-65"`, assert the COSE_Sign1 protected header `alg` = "ML-DSA-65" via `notary/service.py _cose_sign1`; verify `hsm_adapter.get_signer()` prefers `AWSKmsMLDSASigner` when `TL_AWS_KMS_KEY_ID` set (mock boto3) else `EphemeralEd25519Signer`; verify `ThalesLunaPqcSigner` selection when `TL_THALES_PKCS11_MODULE` set (mock). Deploy doc `docs/HSM_PROD_DEPLOY.md` (AWS KMS `create-key --key-spec ML_DSA_65` + Thales env). Code is already wired (`main.py:78-86`); this is test + doc.
- **P5.4 End-to-end first real cert (B4, auditor "Challenge 2"):** e2e integration path `POST /v1/notarize` with real Actalis TSA + real SCITT submit + real ML-DSA-65 (when env) + PDF + public verify URL. Script `scripts/run_first_real_cert.sh` gated by env (`TL_TSA_URL`, `TL_SCITT_ENDPOINT`, `TL_AWS_KMS_KEY_ID`, `TL_VERIFY_DOMAIN`). CI path uses fixtures/mocks (`TL_TSA_MOCK=1`); live path for operator-with-creds. Assert: cert persisted (Postgres), verify page `GET /verify/{cert_id}` returns real L1/L2/L3 with all steps passing.
- **P5.5 W8.1 SCITT into verify page (D4):** ensure the cert's `rekor_entry_id` is populated by the real SCITT submit (P5.4) and `verification_page.py` L3 checks inclusion via `rfc9162_verifier.verify_inclusion_proof`. Closes the "SCITT entry: absent (W8.1 wire-up)" placeholder (`verification_page.py:161`).

---

## Out of scope (explicit)

- Business items: 5 outreach emails, Series A, EU AI Pact signup, GTM (per user).
- PQC-only EdDSA retirement (W4.2, planned 2028-01-01) — future, spec-dependent.
- C2PA 3.0 / Digital Omnibus — spec not ratified (current target 2.4).
- ISO/IEC 42001 + 27001 certification audit — external process (SoA backend already exists).
- CISO briefing PDF — marketing collateral, not code.
- Live deploy with real creds — per decision 3 (ready-to-execute only; operator injects secrets).

## Risks & mitigations

| Risk | Phase | Mitigation |
|---|---|---|
| Defense modules wired → agent-loop behavior change | P3.1 | cargo `defense` feature default-off; default build = current behavior; dedicated `#[cfg(feature="defense")]` tests |
| Structural refactors touch hot paths | P4.x | commit per sub-item; green gate after each; P4 isolated after P1-P3 |
| SQLite→Postgres persistence change | P5.1 | aiosqlite dev fallback; migration script; keep `notary.db`; async endpoints already exist |
| Real endpoints hit in CI | P5.4/P3.5 | env-gating (`TL_TSA_MOCK`, `TL_ADVERSARIAL_LIVE_MOCK`); fixtures for CI; live path opt-in |
| Glob matcher unify changes match semantics | P1.1 | pinned tests for `*`/empty before+after; document anchored vs non-anchored decision |

## Validation (every phase)

- `cargo build --workspace` → 0 errors, 0 `warning: unused`.
- `cargo test --workspace` → 1542+ passed, 0 failed (baseline; grows as tests added).
- `pytest` (PYTHONPATH=services/control_plane, with reportlab) → 295+ passed, 0 failed.
- `ruff check app/ --select F,E9` → 0 (after P0.1).
- Phase 5: ready-to-execute scripts run with fixtures; `make demo` still green.

## Open tactical questions for executor (non-blocking)

1. **Defense feature granularity:** single cargo `defense` feature on themis-orchestrator, or three separate features (`circuit-breaker`/`human-guard`/`rogue-monitor`)? Recommend single `defense` (simpler), flip to three if independent rollout needed.
2. **NotaryDB sync vs async:** fully async (asyncpg/aiosqlite) — verification_page + service endpoints are already `async def`. Recommend fully async; drop the sync sqlite3 path.
3. **Glob anchored decision (P1.1):** keep `config.rs glob_match` anchored (allow-list) + `pattern_matches` non-anchored (gate/hook/policy), documented. Confirm allow-list genuinely needs anchoring by reading its call site (`config.rs:184` on `command`).
4. **Events publish vs remove (P3.4):** publish `AgentCompleted` + `BaaarHalt` (they model real lifecycle events the EventBus is designed for). Only remove if a variant has no semantic home.

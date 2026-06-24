# Deprecated Repositories — Absorbed into apohara-trustlayer

**Date:** 2026-06-24
**Status:** All 11 listed repos are deprecated. Their functionality has been absorbed into this single canonical public repo: **[SuarezPM/apohara-trustlayer](https://github.com/SuarezPM/apohara-trustlayer)**.

## Why this consolidation?

The TrustLayer plan (consensus-validated through 2 iterations of Planner/Architect/Critic) established that:

1. **Single canonical public repo is the wedge** — the spec-facts audit documents this is the correct product narrative.
2. **15 absorbed crates** (8 vouch + 7 themis + apohara-agentguard) is the actual surface area — plan v3.1's "13 crates" was an undercount.
3. **VOUCH name is preserved** internally as the core engine codename (no rename, 812 tests preserved with `git mv`).

## What was absorbed

| Original repo | What was absorbed | Plan v3.1 reference |
|---|---|---|
| `apohara-themis/` | 7 themis substrate crates: `themis-{evidence,compliance,orchestrator,agents,compressor,band-client,frontend}` | US-02, US-03 (Block 1.3) |
| `apohara-vouch/` | 8 vouch crates renamed to `tl-{chain,evidence,receipt,gate,aibom,compliance,orchestrator,frontend}` | US-02 (Block 1.2) |
| `apohara-sealchain/` | Functionality merged into `tl-evidence` (5-layer crypto: HMAC + Ed25519 + C2PA + RFC 3161 + Rekor v2) | Plan absorbed repos list |
| `apohara-agentguard/` | seccomp+Landlock sandbox, full crate absorbed | US-03 (force-include) |
| `apohara-argus/` | slop detection, monitoring (scaffold-only) | Not absorbed — out of scope for v1 |
| `apohara-codesearch/` | MCP server packaging pattern copied (`mcp/npm/`) | US-13 (MCP server) |
| `apohara-catalyst/` | Worktree isolation, BYOC orchestrator (out of scope) | Not absorbed — out of scope for v1 |
| `apohara-compliance/` | EU AI Act scanner (scaffold-only) | Not absorbed — see plan v3.1 §Out-of-Scope |
| `apohara-probanza/` | verdict_engine (scaffold-only) | Not absorbed — out of scope for v1 |
| `apohara-vouch/` (empty) | — | Empty (vouch was renamed to themis; nothing to absorb) |
| `apohara-consilium/` | Governance OS (scaffold-only) | Not absorbed — out of scope for v1 |

## What was NOT absorbed (out of scope for v1)

These are deferred to v1.1 or beyond per `README.md` v1 Scope section:

- `apohara-argus/` — monitoring and anomaly detection (scaffold-only, not production-ready)
- `apohara-catalyst/` — BYOC CLI orchestrator (scaffold-only)
- `apohara-compliance/` — standalone scanner (scaffold-only, partial absorption in `crates/tl-compliance/`)
- `apohara-consilium/` — Governance OS (scaffold-only)
- `apohara-probanza/` — verdict engine (scaffold-only)

These repos were either scaffold-grade or not aligned with the v1 vertical slice. They remain available as references in the developer's local workspace but are NOT supported in the v1 release.

## Migration guide for users of the old repos

```bash
# Old: apohara-sealchain standalone
$ apohara-sealchain seal model.bin
SEALED model.bin.seal.json

# New: tl-evidence in the unified workspace
$ cargo run -p tl-evidence --bin tl-verify -- verify model.bin.bin.seal.json
# OR via the MCP server (Claude Code / Cursor):
#   tl_verify_provenance(cose_sign1_b64=...)
```

```bash
# Old: apohara-vouch-verify CLI
$ vouch-verify sample_packet.json

# New: tl-verify (renamed bin in the unified workspace)
$ cargo run --bin tl-verify -- verify sample_packet.json
# (now under bin/tl-verify/, not bin/vouch-verify/)
```

```bash
# Old: apohara-codesearch npm wrapper
$ npx -y @apohara/codesearch-mcp

# New: tl-mcp-server (different name, same packaging pattern)
$ npx -y @apohara/trustlayer-mcp
# (now at mcp/npm/, see US-13)
```

## Status of all 15 absorbed crates

All absorbed crates are at `crates/tl-{chain,evidence,...}` and `crates/themis-{evidence,compliance,orchestrator,agents,compressor,band-client,frontend}` and `crates/apohara-agentguard/` plus `bin/tl-verify/`. The `Cargo.toml` workspace lists all 17 members.

Test status: 1,256+ tests passing. See `docs/spec_facts_audit.md` for the 8 reconciled claims (including test count corrections).

## Pinning

- `coset = "=0.4.2"` (per plan v3.1 AC-20) — pinned due to "under construction" status in coset README.
- `cargo-deny = "0.16"` (workspace dev-dep) — pinned for reproducible advisory DB.
- `rmcp = "1.8"` (tl-mcp-server) — note: rmcp 1.8 macro `#[tool_router]` has unresolved trait bound issues; see US-13 follow-on.

## Contact

For questions about this consolidation, file an issue at:
https://github.com/SuarezPM/apohara-trustlayer/issues

# TRUSTLAYER — GAP ANALYSIS (junio 2026)

> **Autor:** Claude (Fable 5), staff engineer
> **Fecha:** 2026-06-24
> **Aplica a:** `apohara-trustlayer/` (TrustLayer como producto convergente)
> **Fuentes:** lectura directa de `reference/` + `docs/` + EXA research del Code of Practice (10 jun 2026), SCITT drafts, COSE, RFC 3161, Two Birds analysis.

---

## TL;DR (leer antes que nada)

**El plan original asumía que había que absorber 10 repos semi-vacíos para construir TrustLayer.** Eso está mal. La realidad:

1. **`apohara-themis/` ya ES VOUCH completo** — 16 crates Rust, 812 tests, audit 8.25/10, `vouch-verify` con Ed25519+BLAKE3+RFC 3161+CycloneDX AIBOM que verifica offline en <30s. **El "backbone crypto" del TrustLayer que el brief pedía construir ya existe.** El directorio `apohara-vouch/` está vacío precisamente porque VOUCH vive en themis.

2. **`apohara-sealchain/` y `apohara-agentguard/` están production-ready** (v0.2.0 y v0.3.0) y complementan a VOUCH sin solaparse.

3. **`apohara-probanza/` y `apohara-consilium/` son SCAFFOLD** (carpetas sin src), no productos. **Descartar como absorbed; construir SaaS layer desde cero** (o reusar `apohara-catalyst/` como harness).

4. **`apohara-argus/` (14 crates) tiene su propio MCP server y un audit chain firmado** — es el módulo de anomaly/slop defense que TrustLayer necesita pero NO como pieza de producto separada.

5. **El gap REAL de TrustLayer no es crypto** (resuelto por themis/sealchain) ni sandbox (resuelto por agentguard). **El gap real es la capa de policy engine + disclosure API + verification endpoint público que cumple EU AI Act Art. 50 + DORA + el Code of Practice del 10 junio 2026.** Eso hay que construirlo.

**Recomendación:** TrustLayer = `themis` (core) + `sealchain` (sealing complementario) + `agentguard` (sandbox) + `argus` (MCP gateway + audit log) + **capa NUEVA: policy engine, disclosure API, evidence bundle format, public verify endpoint.**

---

## 1. Estado real, repo por repo

### 1.1 `reference/apohara-themis/` — **ABSOBER, es VOUCH**

**Lo que parece:** Un repo llamado "themis" con themis-frontend.png.
**Lo que ES:** README se titula **"Apohara VOUCH · v9"**. Es el sistema completo de recibos cripto-verificables offline para decisiones multi-agente.

| Crate | Función | Estado |
|---|---|---|
| `vouch-chain` | Hash chain Ed25519 + BLAKE3 | ✅ production |
| `vouch-receipt` | Receipt format + offline verifier | ✅ production |
| `vouch-evidence` | Evidence packet + CycloneDX AIBOM | ✅ production |
| `vouch-aibom` | CycloneDX 1.6 binding | ✅ production |
| `vouch-gate` | BAAAR (post-LLM deterministic gate) | ✅ production, 10/10 proptest |
| `vouch-compliance` | DORA / EU AI Act / NIST AI RMF / OWASP mapping | ✅ production |
| `vouch-orchestrator` | 9-agent cross-framework coordination | ✅ production |
| `vouch-agents`, `vouch-frontend` | Agent definitions + UI | ✅ production |
| `themis-band-client` | Band Protocol integration | ✅ production |
| `themis-compliance`, `themis-evidence` | Wrappers themis | ✅ production |
| `themis-compressor`, `themis-orchestrator`, `themis-agents`, `themis-bench`, `themis-frontend` | Soporte | ✅ production |

**Métricas reales:** 812 tests pass / 0 fail, audit score 8.25/10, demo live en `vouch.apohara.dev`, 9-agent cross-framework court (LangGraph + CrewAI + Pydantic AI + ...), 10/10 chaos harness con 3-kill scenarios.

**Diferenciación defendible:**
- **Offline-verifiable evidence packets** (sin red, sin LLM, sin platform trust).
- **Deterministic post-LLM gate (BAAAR)** — 5 first-match-wins halt conditions, proptest-verified.
- **Cross-account Compliance Veto** — War-Room pattern para AI, verificado 10/10 contra chaos.

**Aporte a TrustLayer:** Este es el **núcleo crypto + receipts + evidence + compliance mapping**. NO re-construir. RENOMBRAR el workspace a `trustlayer-core/` y consolidar las crates vouch-* dentro de un workspace Rust único.

### 1.2 `reference/apohara-sealchain/` — **ABSOBER, complemento de themis**

**Estado:** v0.2.0 production-ready, 3 crates (`apohara-sealchain-core`, CLI/MCP, `sealchain-wasm` verify-only).
**Diferenciación:** 5 capas criptográficas en un solo binario (HMAC + Ed25519 + C2PA + RFC 3161 + Rekor v2), SLSA provenance, OpenSSF Scorecard passing, MCP server.

**Lo que sealchain tiene que themis NO tiene (o tiene pero más crudo):**
- `sealchain-wasm` — verify-only en browser (útil para el public verify endpoint).
- Trust profile honesto ("5 capas, cada una con su nivel de garantía") documentado en el README.
- HuggingFace Action para CI.

**Aporte a TrustLayer:** Usar `sealchain-core` como **alternativa/complemento a vouch-chain** para casos que solo necesitan artifact sealing (no evidence packets). El SDK Python puede exponer ambas.

**Decisión concreta:** NO forzar reemplazo. Convivencia justificada — themis es para receipts multi-agente, sealchain es para sealing de artefactos individuales (modelos, datasets, outputs).

### 1.3 `reference/apohara-agentguard/` — **ABSOBER, sandbox layer**

**Estado:** v0.3.0, single crate Rust, modules `firewall/` `gate/` `hook/` `mcp/` `policy/` `sandbox/linux/` + `audit.rs` + `verdict.rs`.
**Diferenciación:** AST-level bash parsing (no substring matching), seccomp-bpf + Landlock sin root, prompt-injection firewall sin modelo, offline.

**Aporte a TrustLayer:** Es **el sandbox que falta en themis** — themis sella decisiones de agentes pero NO confina lo que esos agentes ejecutan. agentguard lo hace. Integración: cuando vouch-receipt se emite, agentguard emite un `tool_execution_receipt` antes/después de cada tool call, y vouch-chain lo encadena.

### 1.4 `reference/apohara-argus/` — **ABSOBER como módulo de defensa**

**Estado:** 14 crates Rust, v0.1.0, MSRV 1.88. Workspace más grande del ecosistema.
**Crates relevantes para TrustLayer:**
- `apohara-argus-mcp` — MCP server para AI slop defense (PR review, pre-commit guard).
- `argus-slop` — detector de AI-generated slop en código (50+ reglas deterministas).
- `argus-verify` — chain verification.
- `argus-otel` — OpenTelemetry instrumentation.
- `argus-crypto` — primitives compartidos.

**Aporte a TrustLayer:** Integra como **runtime/anomaly_detection** + **mcp/audit_log**. El audit chain firmado de argus es un complemento útil al de themis (argus para eventos de tooling, themis para decisiones multi-agente).

**Decisión concreta:** NO consumir argus como producto. Extraer `argus-crypto` + `argus-mcp` como dependencias internas.

### 1.5 `reference/apohara-compliance/` — **ABSOBER como policy engine**

**Estado:** Single crate Rust + GitHub Action + skills. Cubre EU AI Act Art. 12/13/Annex III + OWASP Agentic + NIST AI RMF.
**Aporte:** Es el motor de mapping regla→control que el brief llama `policy/rules_engine/`. **themis-compliance** y compliance hacen cosas similares — definir UN SOLO policy engine consolidado y deprecar compliance/scanner como repo separado (o merge).

### 1.6 `reference/apohara-codesearch/` — **ABSOBER como MCP pattern**

**Estado:** v0.3.0 (2026-06-11), crates.io + npm publicados, SLSA L3, OpenSSF Best Practices badge.
**Aporte:** Es el **patrón MCP server** que TrustLayer SDK y `mcp/` server deben seguir. La estructura `npx -y @apohara/codesearch-mcp` es exactamente cómo TrustLayer MCP server debe distribuirse.

### 1.7 `reference/apohara-catalyst/` — **ABSOBER como harness CLI**

**Estado:** TS Bun + Rust crates (apohara-indexer, apohara-sandbox), v2.0.0-alpha.
**Aporte:** Es el wedge developer de "BYOC orchestrator" — corre agentes en worktrees aislados con quality gates. TrustLayer puede ofrecer un `tl` CLI que sea un thin wrapper sobre Catalyst + themis + agentguard.

### 1.8 `reference/apohara-synthex/` — **REFERENCIA, no absorber**

**Estado:** JS ESM v2.0.0, `prove/` (HMAC+Ed25519+RFC 3161+C2PA+Rekor), `redteam/` (5-lens), `adapters/{crewai,langchain}`.
**Razón para no absorber:** Es JS, no Rust; Crypto crítico en JS es opuesto al principio "Rust para todo lo crypto". Pero los **adapters a LangChain/CrewAI** son valiosos como referencia para SDK Python/TS.

### 1.9 `reference/apohara-probanza/` — **DESCARTAR como absorbed**

**Estado:** Scaffold Python. `core/`, `verdict_engine/`, `surfaces/`, `plugins/`, `tools/`, `ui/`, `landing/` — la mayoría son carpetas vacías. Solo `verdict_engine/` tiene código real (`mcp_server.py`, `envelope.py`, `verdict_vault.py`, `rule_of_two.py`, `judge_gates.py`, `fastapi_soar_routes.py`).
**Decisión:** Extraer `verdict_engine/` como `services/policy_engine/` en TrustLayer y deprecar el resto. **No invertir en consolidar el scaffold.**

### 1.10 `reference/apohara-consilium/` — **DESCARTAR**

**Estado:** Scaffold TS/Next.js. `packages/{backend,frontend,frontend-nextjs,logs}/` — todos sin src visible.
**Decisión:** **No absorbed.** El SaaS UI de TrustLayer se construye desde cero sobre FastAPI + un React/Next.js minimal. Consilium es aspiracional, no implementable en plazo razonable.

### 1.11 `reference/apohara-vouch/` — **VACÍO, no existe**

**Confirmado:** el directorio no existe en `reference/`. El brief original lo listaba como absorbedor. **Eliminá esa expectativa.** Todo "vouch" vive en `apohara-themis/` y eso es lo que se absorbe.

---

## 2. Mapa de absorción propuesto

```
trustlayer/
├── crates/                        # Workspace Rust unificado
│   ├── tl-types/                  # Newtypes, IDs, ComplianceAssessment
│   ├── tl-errors/                 # Error enums por módulo
│   ├── tl-crypto/                 # ← de vouch-chain + sealchain-core
│   │   ├── signing/               # Ed25519 + COSE_Sign1
│   │   ├── timestamps/            # RFC 3161 TSA client (FreeTSA mock en dev)
│   │   ├── chains/                # HashChain + Merkle
│   │   ├── keys/                  # KeyRotationPolicy + KeyStore trait
│   │   └── cose/                  # Wrapper sobre coset
│   ├── tl-provenance/             # ← de vouch-receipt + sealchain
│   │   ├── receipt/               # DisclosureRecord + VerificationReceipt
│   │   ├── evidence/              # EvidenceBundle format
│   │   ├── aibom/                 # CycloneDX 1.6 binding (de vouch-aibom)
│   │   ├── c2pa_bridge/           # c2pa-rs interop
│   │   └── scitt/                 # SCITT receipt generation (NUEVO)
│   ├── tl-policy/                 # ← de themis-compliance + apohara-compliance + probanza/verdict_engine
│   │   ├── strategies/            # Article50, DORA, NIST, ISO42001, Org
│   │   ├── engine/                # Strategy dispatcher + result aggregation
│   │   └── rules/                 # Rule corpus (corpus regulatorio)
│   ├── tl-sandbox/                # ← de agentguard
│   │   ├── profiles/              # SandboxProfile por tool type
│   │   ├── executor/              # Ejecución aislada
│   │   └── receipts/              # ToolExecutionReceipt
│   ├── tl-anomaly/                # ← de argus-slop + argus-lens
│   └── tl-watermark/              # NUEVO — hooks NO implementación
│       ├── text/                  # Adapter a Kirchenbauer et al.
│       ├── image/                 # Adapter a Tree-Ring
│       └── audio/                 # Adapter a AudioSeal
├── services/                      # Python FastAPI
│   ├── control_plane/             # API principal
│   │   ├── api/v1/
│   │   │   ├── disclosure.py      # POST /v1/disclosure/generate
│   │   │   ├── verify.py          # POST /v1/verify/{provenance,receipt}
│   │   │   ├── receipts.py        # GET /v1/receipts/{id}
│   │   │   ├── evidence.py        # GET /v1/evidence/{bundle_id}
│   │   │   └── policy.py          # POST /v1/policy/evaluate
│   │   ├── services/              # Business logic (NO en routes)
│   │   ├── repositories/          # PostgreSQL append-only
│   │   └── schemas/               # Pydantic v2
│   └── mcp_server/                # ← de codesearch-mcp pattern
├── dashboard/                     # React/Next.js minimal
├── sdk/python/                    # Cliente Python
├── sdk/typescript/                # Cliente TS
└── docs/
    ├── openapi/                   # Generada desde código
    ├── threat_model/              # Threat notes por path crítico
    └── compliance_maps/           # EU AI Act ↔ código ↔ test
```

---

## 3. Deuda técnica que impide venderlo HOY

| # | Bloqueador | Impacto comercial | Mitigación |
|---|---|---|---|
| 1 | No hay disclosure generator que cumpla Art. 50 + Code of Practice 10 jun 2026 | Empresas EU no pueden cumplir el 2-ago-2026 sin esto | **MVP vertical slice #1 (ver spec)** |
| 2 | No hay public verify endpoint sin autenticación | Regulador externo no puede auditar sin credenciales | **MVP vertical slice #2** |
| 3 | No hay EvidenceBundle format público | "¿me das el evidence pack para mi auditor?" → no existe | **MVP vertical slice #3** |
| 4 | Compliance model es bool/enum plano, no 4 capas | Un auditor serio no acepta "Compliant: true" | **ADR-004 + refactor de themis-compliance** |
| 5 | No hay COSE format en receipts (solo Ed25519 raw) | Compradores enterprise piden "COSE_Sign1" o "SCITT receipt" | **ADR-002 + tl-crypto/cose module** |
| 6 | RFC 3161 TSA client es mock en dev, no documentado en prod | Sin timestamp externo, signature es débil forensemente | **ADR-003 + tl-crypto/timestamps module con FreeTSA + DigiCert** |
| 7 | No hay key rotation policy explícita | Cambio de clave = re-firma masiva sin coordinación | **ADR + tl-crypto/keys module** |
| 8 | Naming overlap: trustlayer, themis, vouch, sealchain, agentguard | Buyer confundido | **Naming decision: "Apohara TrustLayer" como umbrella, "trustlayer-core" como crate, themis/sealchain deprecados como nombres públicos** |

---

## 4. Lo que es realmente diferenciador

1. **La combinación:** Ed25519 + BLAKE3 + RFC 3161 + C2PA + CycloneDX AIBOM en un solo sistema verificable offline en <30s. **Ningún competidor tiene esto.**

2. **9-agent cross-framework court** (themis/vouch-orchestrator) — LangGraph + CrewAI + Pydantic AI coordinando con Band Protocol y produciendo evidence packets. **Es hackathon-grade pero ningún enterprise vendor open-source lo tiene así.**

3. **Deterministic post-LLM gate (BAAAR)** — 5 halt conditions, proptest-verified 10/10. **Esto resuelve el problema de "AI agent decided X, but we can't explain why" que ningún competidor aborda.**

4. **Cross-account Compliance Veto** — Chaos harness 10/10 over 3-kill scenarios. **Si el websocket cross-account muere, hay veto local. Esto es robustez operativa que regulators respetan.**

5. **Offline verification** — sin red, sin LLM, sin platform trust. **DigiCert cobra por AI Trust Architecture, Vouch lo da gratis + open-source + auditable.**

6. **Multi-framework compliance mapping simultáneo** — DORA + EU AI Act + NIST AI RMF + OWASP Agentic 2026 en un solo artefacto. **Themis ya lo hace en tests (9/9 campos Art. 12 populados).**

---

## 5. Lo que NO es diferenciador (y por qué no construirlo)

| Feature | Razón para no construir |
|---|---|
| Watermarking implementation | R&D especializado (Kirchenbauer, Tree-Ring, AudioSeal). Confiar en adapters y poner hooks. |
| Key management propio | `tink-rust` (Google) + `rust-cryptoki` (PKCS#11) son la elección correcta. Inventar key management es irresponsable. |
| ORM/Dashboard complejo | React + minimal Next.js + tabular export. Enterprise quiere JSON+PDF, no dashboards bonitos. |
| Slack/Teams/Discord integrations v1 | Fase 3+. No es wedge de adopción para EU AI Act compliance. |
| HashiCorp Vault / AWS KMS adapter v1 | v2+. Empezar con env vars + file-based keystore + FreeTSA mock. |

---

## 6. Módulos a descartar completamente

| Repo | Acción |
|---|---|
| `apohara-vouch/` | Ya está absorbido en themis. Eliminar del brief. |
| `apohara-consilium/` | Scaffold. No absorbed. |
| `apohara-probanza/` (excepto `verdict_engine/`) | Scaffold. No absorbed. |
| `apohara-models/`, `apohara-soak/`, `apohara-hackathon-brain/`, `apohara-web-page/`, `apohara-aegis/` | Out of scope para TrustLayer v1. |
| `Apohara_PRIVATE/`, `brightdata-mcp/`, `Apohara_Context_Forge/` | Out of scope para TrustLayer v1. (Context Forge sí es transversal pero su rol es backbone de los otros módulos, no absorbed directo.) |

---

## 7. Riesgos que el gap analysis NO resuelve

1. **Adoption externa nula.** Ningún repo tiene stars significativos, usuarios externos conocidos, ni contratos. Esto NO se arregla con código — se arregla con 3-5 design partners pagos y un caso de uso publicado.

2. **Single-author ecosystem.** Bus factor crítico en themis y sealchain. Si el maintainer desaparece, el producto muere. **Acción:** documentar ADRs por cada decisión no trivial para reducir bus factor.

3. **Commoditización rápida.** Vanta, Drata, OneTrust, Credo AI, Lakera, Chainguard, JFrog MCP Registry, DigiCert AI Trust, Geordie AI ($30M Series A mayo 2026), Kai ($125M Series A marzo 2026). **Cada uno con capital + distribución.** TrustLayer compite con estos no en features sino en **integración + offline + EU-specificity**.

4. **EU AI Act 2-ago-2026 ya casi llega.** 39 días desde 2026-06-24. **El MVP debe estar en manos de 3 design partners antes de esa fecha**, no en septiembre.

5. **DORA ya está en vigor** desde enero 2025 para entidades financieras EU. **No hay urgencia nueva**, pero hay cliente existente con dolor.

---

## 8. Veredicto

El brief original asumía que había que construir TrustLayer desde cero absorbiendo 10 repos. **Eso era el plan equivocado.** El plan correcto es:

1. **RENOMBRAR** el producto a `Apohara TrustLayer` (umbrella) con `trustlayer-core/` (workspace Rust único) que consolida las crates `vouch-*` de themis y `sealchain-core`.
2. **AGREGAR** la capa que falta: policy engine (Strategy pattern), disclosure API, public verify endpoint, evidence bundle format.
3. **INTEGRAR** agentguard (sandbox) + argus (anomaly/MCP) como módulos complementarios.
4. **CONSTRUIR** desde cero: services/control_plane (FastAPI), sdk/python, sdk/typescript, dashboard minimal.
5. **DESCARTAR** consilium, probanza (excepto verdict_engine), vouch-vacío.

**El producto es viable y diferenciable.** El gap no es técnico, es de naming, empaquetado, y ejecución comercial.

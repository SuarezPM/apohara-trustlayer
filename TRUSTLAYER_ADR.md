# TRUSTLAYER — ARCHITECTURE DECISION RECORDS

> **Autor:** Claude (Fable 5), staff engineer
> **Fecha:** 2026-06-24
> **Estado:** v1 — pendiente aprobación de Pablo

Cada ADR documenta una decisión técnica NO OBVIA, sus alternativas rechazadas, y sus consecuencias. Las decisiones obvias no necesitan ADR.

---

## ADR-001: Rust para todo el stack criptográfico, sandbox y performance paths

**Status:** Accepted.

**Contexto.** TrustLayer manipula keys privadas, hashea evidencia, ejecuta sandboxes, valida chains. Lenguajes con garbage collector y memory unsafety son vetos categoricos para crypto. Python es cómodo pero pyca/cryptography es un wrapper sobre OpenSSL con superficie de ataque grande.

**Decisión.** Todo signing, hashing, chain verification, sandbox, MCP server core, y serialización binaria vive en Rust. Python solo orquesta (FastAPI), persiste (SQLAlchemy) y expone schemas (pydantic v2).

**Consecuencias.**
- (+) Memory safety + cargo audit + clippy + RustCrypto + sin CVEs de OpenSSL en el critical path.
- (+) Performance determinista para el verify endpoint público (objetivo <200ms p99).
- (+) El equipo necesita comfort con Rust — Pablo lo tiene (es autor de themis/sealchain/agentguard).
- (−) Python no firma nunca. Esto fuerza una arquitectura limpia: Python llama a Rust vía subprocess o PyO3, no inline.
- (−) Onboarding más lento. Pero el ecosistema Rust está documentado en cada crate absorbed.

**Alternativas rechazadas.**
- *Python + cryptography:* vetado por el ADR. crypto crítico en Python es operacionalmente irresponsable en 2026.
- *Go:* razonable, pero el codebase absorbed ya es Rust. Migrar es tirar meses de trabajo.
- *Zig:* interesante pero sin ecosistema crypto maduro. Diferido a v3+.

---

## ADR-002: COSE_Sign1 (RFC 9052) como formato de firma, no JWT, no Ed25519 raw

**Status:** Accepted.

**Contexto.** SCITT drafts (draft-ietf-scitt-architecture-22, en RFC Ed Queue), C2PA v2.1, y RATS architecture usan COSE_Sign1. Compradores enterprise serios en 2026 preguntan "habla COSE?" — si la respuesta es no, el producto queda fuera del shortlist.

**Decisión.** Todo artefacto firmado exportable (DisclosureRecord, VerificationReceipt, EvidenceBundle, ToolExecutionReceipt) usa COSE_Sign1 con:
- Algorithm: `EdDSA` (Ed25519) o `ES256` (P-256) según key chain.
- Protected header: `alg`, `kid` (key id), `content-type`, opcionalmente `tsa_token` (RFC 3161).
- Payload: CBOR-encoded del struct interno.
- AAD: vacío por defecto; configurable por contexto (e.g., bundle_id).

**Consecuencias.**
- (+) Interoperabilidad con validadores SCITT genéricos (`scitt-api-emulator`), C2PA tooling, y auditores externos.
- (+) Header protegido permite binding a key id + TSA token sin cambiar el payload.
- (−) COSE es CBOR, no JSON. SDKs deben serializar CBOR o exponer una vista JSON derivada (ver ADR-008 sobre SDKs).
- (−) `coset` crate está marcado "under construction" en su README. **Riesgo:** podemos necesitar fork o pinning agresivo. Mitigación: la crate v0.4.2 tiene 19M+ descargas, no va a desaparecer; nuestro wrapper (`tl-crypto/cose`) aísla el riesgo.

**Alternativas rechazadas.**
- *JWT (JWS):* es JSON-only, no soporta COSE_Key, no es lo que usa SCITT/C2PA. Vetado.
- *Ed25519 raw bytes con JSON envelope:* fácil pero no interoperable. Vetado.
- *PASETO:* razonable, mejor que JWT, pero COSE gana por ser el estándar IETF.

---

## ADR-003: RFC 3161 timestamp binding obligatorio en artefactos exportables

**Status:** Accepted.

**Contexto.** Una firma Ed25519 sin timestamp externo prueba "alguien con esta key firmó esto en algún momento". Una firma Ed25519 + RFC 3161 token prueba "alguien con esta key firmó esto ANTES de T". El segundo es **forensemente defendible**; el primero, no. DORA Art. 19 exige retention con tamper-evident timestamps. EU AI Act Code of Practice (10 jun 2026) refuerza esto en Sub-measure 1.1.1.

**Decisión.** Todo `DisclosureRecord`, `EvidenceBundle`, y `VerificationReceipt` exported incluye:
1. Un `TsaToken` (opaque bytes del TSA response, RFC 3161 DER-encoded).
2. Un `tsa_url` (URL del TSA emisor).
3. Un `tsa_verification_status` calculado on-verify.

En dev: mock TSA local (`tl-crypto/timestamps/mock.rs`) que firma con la misma key de TrustLayer (esto es honesto en tests pero **claramente etiquetado como no-production**).

En prod: cliente pluggable. Default: FreeTSA.org (free, no SLA). Tier Pro/Enterprise: DigiCert Assured Timestamping, GlobalSign, o HSM-backed interno.

**Consecuencias.**
- (+) Firma forensemente defendible.
- (+) Compatible con validadores forenses externos (forensic-timestamp-validator).
- (−) Dependencia externa de TSA. Mitigación: el cliente TSA es un trait (`TimestampAuthority`), no una lib concreta. Failover + cache local.
- (−) TSA outages impactan availability. Mitigación: receipt SE PUEDE emitir sin TSA, pero el campo es obligatorio para "FullyCompliant". Ver ADR-004.

**Alternativas rechazadas.**
- *Counter-signature de TrustLayer como "timestamp":* NO es timestamp externo. No prueba "antes de T", solo "después de S donde S es firmado". Insuficiente para forensics.
- *Blockchain anchoring (Bitcoin/Ethereum):* costoso, no regulatorio-friendly, distracts from EU AI Act focus.
- *Rekor v2 de Sigstore:* razonable pero Sigstore está enfocado en software supply chain, no AI artifacts. Tier 2 (Pro/Enterprise) podría ofrecer Rekor como alternative TSA.

---

## ADR-004: Compliance como 4 capas independientes, nunca como bool

**Status:** Accepted.

**Contexto.** El Code of Practice del 10 de junio de 2026 exige reportar marking (Layer 1 + Layer 2), labelling (Layer 3), y retention (Layer 4). The Two Birds analysis de junio 2026 confirma: C2PA sola (una capa) no cumple; la combinación obligatoria es visible disclosure + machine-readable provenance + watermarking + retention. Un reporte `compliant: true/false` colapsa información que un auditor necesita desagregada.

**Decisión.** El modelo `ComplianceAssessment` tiene 4 campos independientes:

```rust
pub struct ComplianceAssessment {
    pub disclosure_layer: LayerStatus,     // Layer 1: visible disclosure
    pub provenance_layer: LayerStatus,     // Layer 2: machine-readable provenance
    pub watermark_layer: LayerStatus,      // Layer 3: watermark/fingerprinting
    pub retention_layer: LayerStatus,      // Layer 4: retention + auditability
}

pub enum LayerStatus {
    Compliant { verified_at: DateTime<Utc>, evidence_refs: Vec<EvidenceRef> },
    Partial { missing: Vec<String>, reason: String },
    NonCompliant { violations: Vec<PolicyViolation> },
    Unknown { reason: String },
    NotApplicable { reason: String },
}
```

El agregador `ComplianceRollup` reporta un status global SOLO si las 4 capas son `Compliant` o `NotApplicable`. `Partial` o `NonCompliant` en cualquier capa → global es `Partial` o `NonCompliant` respectivamente, **nunca** `Compliant`.

**Consecuencias.**
- (+) Reporting honesto: un auditor ve exactamente qué falta.
- (+) Producto diferenciable: ningún competitor reporta por capa.
- (+) Compatible con EU AI Act Code of Practice que pide reportar cada dimensión.
- (−) UI/API más compleja. Mitigación: dashboard con expandable details; API con `?include=layers` opcional.
- (−) Más código en tests. Pero tests honestos > tests falsos.

**Alternativas rechazadas.**
- *Bool global:* vetado. La causa de por qué otros productos fallan.
- *Score numérico 0-100:* útil para marketing pero no para auditores. Reportamos score COMO resumen secundario, no como primary status.
- *Enum plano `{Compliant, Partial, NonCompliant}`:* vetado. Pierde la granularidad que el Code of Practice exige.

---

## ADR-005: Audit tables append-only en PostgreSQL, sin UPDATE, sin DELETE

**Status:** Accepted.

**Contexto.** DORA Art. 19, EU AI Act Art. 12, y SOC 2 CC7.2 exigen audit trails tamper-evident. PostgreSQL con `INSERT`-only enforcement (revocar UPDATE/DELETE en el rol de la app) + hash-chain interno por row + verificación periódica es el patrón estándar.

**Decisión.**
1. Tablas `disclosure_records`, `tool_execution_receipts`, `policy_decisions`, `key_rotation_events` son `INSERT`-only a nivel de aplicación Y de DB role.
2. Cada row incluye `prev_hash` y `row_hash` para chain verification.
3. Soft-deletion: columna `status` con valores `{Active, Retired, Superseded}`. Nunca `DELETE`.
4. Retention: 3 años mínimo (EU AI Act), 5 años para DORA. Policy se aplica por archivado (movimiento a `audit_archive` schema, no `DELETE`).
5. La verificación de chain corre en background job cada 1h, alerta si encuentra gap.

**Consecuencias.**
- (+) Tamper-evidence verificable on-demand.
- (+) Compatible con DORA + EU AI Act + SOC 2 sin retrofitting.
- (+) Chain verification es un producto:客户提供 verifier para auditores externos.
- (−) Storage cost crece linealmente. Mitigación: compresión + tiering (hot 90d → cold 5y).
- (−) Errores en data son difíciles de corregir. Mitigación: nueva row de "correction" con `supersedes_id` apuntando a la original.

**Alternativas rechazadas.**
- *Event sourcing con Kafka:* Kafka no es append-only-by-default; requiere configuración cuidadosa. No necesario para v1.
- *Blockchain:* NO. Storage cost + latency + regulatory ambiguity.
- *Qldb de AWS:* vendor lock-in. PostgreSQL es portable.

---

## ADR-006: Verification endpoint público sin autenticación, con rate limiting estricto

**Status:** Accepted.

**Contexto.** Un auditor externo, un regulador, o un comprador B2B debe poder verificar una firma sin pedir credenciales. Si el verify endpoint requiere API key, el moat cripto se rompe (el auditor tiene que confiar en TrustLayer para verificar la firma de TrustLayer — circular).

**Decisión.**
1. `POST /v1/verify/provenance` y `POST /v1/verify/receipt` son **públicos sin auth**.
2. `GET /v1/evidence/{bundle_id}` es **público sin auth**, retorna bundle completo + instrucciones de verificación offline.
3. Rate limiting estricto: 60 req/min por IP, 1000 req/día por IP sin auth. Tier autenticado (free API key con registro) sube a 10000/día.
4. Cada response de verify incluye el chain verification status: PASS / FAIL con razones específicas por capa.
5. El endpoint puede operar contra un mirror público del chain state. Si el principal está caído, el mirror sirve reads.

**Consecuencias.**
- (+) Auditor puede verificar sin credenciales. Esto es lo que un CISO enterprise necesita.
- (+) Diferenciador vs Credo AI, OneTrust que requieren login para todo.
- (+) Compatible con la promesa de themis: "verifiable in <30s — no network, no LLM, no platform trust".
- (−) Rate limiting estricto evita scraping. Si un competitor scrape, pueden rebuild la lógica — pero el moat es el **regulatory acceptance + ongoing updates**, no el código.
- (−) Public endpoint es superficie de ataque. Mitigación: input validation estricta, no SQL/NoSQL injection surface (verify es read-only + crypto operations), WAF delante.

**Alternativas rechazadas.**
- *Solo auth, con "request access" flow:* vetado. Rompe el use case del auditor externo.
- *Solo offline (cliente descarga + verifica local):* cierto para verify, pero el endpoint público es **además** del offline client. Ambos deben coexistir.

---

## ADR-007: Policy engine con Strategy pattern, no monolito

**Status:** Accepted.

**Contexto.** EU AI Act, DORA, NIST AI RMF, ISO 42001, NIS2, AI Liability Directive (en draft), y políticas internas de cada cliente son regulations distintas con overlap parcial. Un monolito que intenta cubrir todas falla por amplitud. Un motor extensible por strategy permite agregar regulations sin tocar el core.

**Decisión.** Cada regulation es una `PolicyStrategy`:

```rust
pub trait PolicyStrategy: Send + Sync {
    fn id(&self) -> &str;                    // "eu_ai_act_art50", "dora_art19", ...
    fn version(&self) -> &str;               // "v2026.06", para reproducabilidad
    fn applies_to(&self, ctx: &Context) -> bool;
    fn evaluate(&self, ctx: &Context, evidence: &EvidenceSet) -> PolicyDecision;
}
```

El `PolicyEngine` dispatcher:
1. Recibe un `Context` (sistema AI + jurisdiction + sector + user_attributes).
2. Selecciona strategies que `applies_to(ctx)`.
3. Ejecuta `evaluate()` en paralelo.
4. Agrega resultados en `AggregatedDecision` con conflict resolution explícito (most-restrictive-wins por default, configurable).

**Strategies v1:**
- `Article50PolicyStrategy` — EU AI Act Art. 50 (disclosure + marking).
- `DORAEvidenceStrategy` — DORA Art. 19-20 (ICT risk evidence pack).
- `NISTAIRMFMappingStrategy` — NIST AI RMF Govern/Map/Measure/Manage.
- `OrgSpecificPolicyStrategy` — org-customizable (config file).

**Consecuencias.**
- (+) Nueva regulation = nuevo crate, no cambio al engine. Zero modification of existing code.
- (+) Cada strategy puede tener su propio corpus regulatorio (text + metadata).
- (+) Tests aislados por strategy.
- (−) Conflicto entre strategies es responsabilidad del engine. Mitigación: regla explícita most-restrictive-wins, configurable, auditada.
- (−) Strategies pueden diverger. Mitigación: shared `EvidenceSet` schema + versionado semver por strategy.

**Alternativas rechazadas.**
- *OPA/Rego como backend:* razonable para v3, pero su DSL no es friendly para compliance officers. v1 usa Rust strategies, v3 puede exponer OPA adapter.
- *Cedar (AWS):* similar tradeoff. Mismo plan: v3 adapter opcional.
- *DSL custom declarativo (YAML/JSON):* tentador pero debuggear policies es horrible. Rust types > YAML.

---

## ADR-008: Watermark como hooks, no como implementación propia

**Status:** Accepted.

**Contexto.** Watermarking es R&D activo y especializado. Kirchenbauer et al. para text, Tree-Ring (Wen et al.) para image, AudioSeal (Meta 2024) para audio. Implementar uno internamente significa: (a) 6-12 meses de R&D, (b) reproducir papers sin ventaja, (c) quedarnos atrás cuando sale una técnica nueva.

**Decisión.** `tl-watermark/` define un trait `WatermarkProvider`:

```rust
pub trait WatermarkProvider: Send + Sync {
    fn kind(&self) -> WatermarkKind;            // Text, Image, Audio, Video
    fn embed(&self, artifact: &Artifact) -> Result<(WatermarkedArtifact, WatermarkRef)>;
    fn detect(&self, artifact: &Artifact) -> Result<DetectionResult>;
}
```

Adapters v1:
- `PassthroughWatermark` — no-op, reporta `NotApplicable`. Default.
- `KirchenbauerTextWatermark` — adapter al paper (puede ser stub si no hay impl open-source lista).
- `TreeRingImageWatermark` — adapter.
- `AudioSealWatermark` — adapter.

El customer puede traer su propio `WatermarkProvider` (SDK + trait).

**Consecuencias.**
- (+) Zero R&D en watermarking. Confiamos en el state-of-the-art.
- (+) Clientes pueden usar su watermarker preferido (importante para compliance officers que ya eligieron uno).
- (+) Trait permite mock para tests + futuro plugin de nuevos métodos.
- (−) Adapters pueden quedar atrás si upstream no mantiene. Mitigación: pinning + monitoring.
- (−) Si Kirchenbauer/Tree-Ring no tienen impl open-source production-ready, el adapter queda como stub. **Esto es honesto y reportado en TRUSTLAYER_GAP_ANALYSIS.md.**

**Alternativas rechazadas.**
- *Implementar Tree-Ring in-house:* 6-12 meses de trabajo sin upside vs usar upstream.
- *Solo TextWatermark:* insuficiente. EU AI Act Art. 50(3) cubre audio, image, video, text. Hacer solo text es producto incompleto.
- *C2PA "watermarking" como suficiente:* vetado por ADR-004 + Two Birds analysis.

---

## ADR-009: SDK en Python y TypeScript solamente para v1

**Status:** Accepted.

**Contexto.** El target user es un developer integrando TrustLayer en su stack. Cobertura de lenguajes tiene costo (mantener tests, releases, security advisories por SDK). Python y TypeScript cubren ~95% del ecosistema builder 2026.

**Decisión.** v1 SDK:
- `sdk/python/` — pip install `apohara-trustlayer`. FastAPI-friendly. aiohttp async. Pydantic v2 schemas.
- `sdk/typescript/` — npm install `@apohara/trustlayer`. fetch nativo. Zod runtime validation.

v2+ SDK (NO en scope v1): Go, Java, Rust (para embed en otros Rust projects), C#/.NET.
NO en v1 ni v2: Ruby, PHP, Elixir (ecosistemas shrinking).

**Consecuencias.**
- (+) Cobertura 95% sin overhead.
- (+) Pip + npm son canales de distribución zero-friction.
- (+) Tests en Python/TS son baratos.
- (−) Empresa enterprise con stack Java/Go puro no puede usar el SDK directamente. Mitigación: REST API + OpenAPI spec generada. Pueden consumir sin SDK.
- (−) Posible feedback de enterprise "necesitamos Java SDK". Documentado en roadmap v2.

**Alternativas rechazadas.**
- *Auto-generar SDK desde OpenAPI:* tentador pero genera SDKs de baja calidad. Hand-written SDKs con pydantic/zod > auto-generated.
- *Empezar con un solo lenguaje:* Python es lo más común pero TS tiene mejor type safety. Ambos desde día 1.

---

## ADR-010: Pricing híbrido (base + per-verified-outcome), no outcome-only, no seat-only

**Status:** Accepted.

**Contexto.** Tres modelos posibles:
- **A. Hybrid base + per-verified-outcome:** Tier base con N verifications incluidas + overage por verification.
- **B. Pure outcome (per-disclosure, per-verification):** máximo alignment, pero CFO no aprueba, y la "outcome" es ambigua (¿qué cuenta como outcome?).
- **C. Enterprise flat fee:** simple, ceiling bajo en SMB.

**Decisión.** Modelo A con tiers:

| Tier | Base mensual | Incluido | Overage | Target |
|---|---|---|---|---|
| **Free** | $0 | 100 verifications/mes, public verify only, docs + community | n/a | Indie devs, evaluación |
| **Starter** | $49/mo | 1,000 verifications, 1 sitio, dashboard, email support | $0.02/verification | Startups EU-exposed |
| **Pro** | $199/mo | 10,000 verifications, 5 sitios, webhooks, evidence export | $0.01/verification | Mid-market SaaS |
| **Team** | $499/mo | 50,000 verifications, unlimited sitios, audit log export, DORA pack | $0.005/verification | Fintech EU + plataformas |
| **Enterprise** | Custom | SLA, dedicated keys, custom retention, eIDAS QTSP, on-prem | Custom | Bancos, seguros, gov |

**Por qué A:**
- Base cubre el costo fijo de infraestructura (PostgreSQL, compute, key management).
- Per-verification incentiva el uso real (alignment) sin imposibilitar el budget.
- Outcome es verificable empíricamente: cada verification tiene un log entry. CFO puede audit.

**Wedge de entrada:** EU AI Act Art. 50 deadline (2-ago-2026). **Pricing en homepage debe mencionar el deadline explícitamente.**

**Consecuencias.**
- (+) Buyer predictability (base known) + alignment (overage scales with value).
- (+) Differentiator: Chainguard cobra enterprise-only; Sigstore es OSS-only sin SaaS; TrustLayer cubre SMB+enterprise con un solo pricing model.
- (+) Free tier con 100 verifications/mes = funnel de acquisition (developers evalúan sin friction).
- (−) Free tier puede ser abusado. Mitigación: rate limit + ToS.
- (−) Pricing complejo de comunicar. Mitigación: 1 tabla en homepage, calculator embed para overage.

**Alternativas rechazadas.**
- *Pure outcome:* vetado por previsibilidad. CFO objection: "¿cómo presupuesto $X si no sé cuántos outcomes voy a tener?".
- *Per-seat:* vetado por mismatch con el modelo de usage. TrustLayer no es "otro seat", es infrastructure per-evidence.
- *Enterprise-only (sin self-serve):* pierde funnel de acquisition. 80% del wedge EU AI Act es SMB + mid-market.

---

## Cambios respecto al brief original

| Brief original | ADR actual | Razón |
|---|---|---|
| "Rust + Python + TypeScript" | Confirmado | — |
| "5 estrategias: Article50, DORA, NISTAIRMF, ISO42001, OrgSpecific" | **Reducido a 4** + OrgSpecific | ISO 42001 es AISMS, no regulation per se. Su contenido se mapea dentro de las otras 4. Si un cliente pide ISO explícito, agregamos en v2. |
| "Merkle tree en receipt chains" | **Sí, pero como optimization, no como requirement** | Hash chain lineal es más simple y suficiente para v1. Merkle es upgrade de performance en bundle-level, no per-receipt. |
| "PDF export de evidence bundle" | **Sí + JSON canonical primero** | JSON canónico es lo que auditors verifican. PDF es bonus para humanos. |
| "Policy engine con 4 strategies" | **Confirmado** | — |

---

## Próximos ADRs esperados

- **ADR-011:** PyO3 vs subprocess para Rust↔Python interop.
- **ADR-012:** Cómo modelar tenant isolation (org_id en cada row vs row-level security vs schema-per-tenant).
- **ADR-013:** Key backup + recovery policy (HSM split vs Shamir vs cloud KMS).
- **ADR-014:** Threat model STRIDE por path crítico.
- **ADR-015:** Evidence bundle format spec (open spec, no patent).

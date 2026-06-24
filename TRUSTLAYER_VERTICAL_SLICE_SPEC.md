# TRUSTLAYER — VERTICAL SLICE SPEC (MVP)

> **Autor:** Claude (Fable 5), staff engineer
> **Fecha:** 2026-06-24
> **Status:** v1 — pendiente aprobación de Pablo
> **Objetivo:** definir el slice mínimo que prueba que TrustLayer funciona end-to-end. **Si este slice no funciona, no hay producto.**

---

## 1. La métrica de éxito (única, binaria)

**Un tercero externo, sin acceso privilegiado al sistema interno, sin credenciales, sin red corporativa, puede:**

1. ✅ Generar una disclosure para un texto generado por IA.
2. ✅ Recibir un signed receipt con timestamp TSA verificable.
3. ✅ Verificar la firma **offline** sin acceso interno al sistema.
4. ✅ Ver el estado de las 4 capas de cumplimiento con razones específicas por capa.
5. ✅ Descargar un evidence bundle completo en JSON canónico.
6. ✅ Entender **exactamente** por qué el sistema decidió `Compliant` / `Partial` / `Non-Compliant`.

**Si alguno de estos 6 pasos falla, no hay MVP. STOP y fix.**

---

## 2. Lo que el slice incluye (IN-SCOPE)

### 2.1 Rust crates (workspace `trustlayer-core/`)

```
crates/
├── tl-types/             # Newtypes: DisclosureId, BundleId, KeyId, SignatureBytes,
│                          #         HashBytes, TsaToken, LayerStatus, ComplianceAssessment
├── tl-errors/            # TlError enum por módulo (thiserror)
├── tl-crypto/
│   ├── signing/          # Ed25519 sign/verify + COSE_Sign1 wrapper sobre coset
│   ├── timestamps/       # RFC 3161 TSA client (mock + FreeTSA impl)
│   ├── keys/             # KeyStore trait + LocalFileKeyStore impl (env-var path)
│   └── chains/           # HashChain linear, prev_hash + row_hash
├── tl-provenance/
│   ├── receipt/          # DisclosureRecord + VerificationReceipt
│   ├── evidence/         # EvidenceBundle (CBOR-canonical + JSON view)
│   └── cose/             # COSE helpers sobre coset
└── tl-policy/
    ├── strategies/
    │   ├── article_50.rs       # EU AI Act Art. 50 (4 capas model)
    │   └── dora.rs             # DORA Art. 19-20 evidence pack
    └── engine/                 # Strategy dispatcher + AggregatedDecision
```

### 2.2 Python service (`services/control_plane/`)

```
services/control_plane/
├── api/v1/
│   ├── disclosure.py     # POST /v1/disclosure/generate
│   ├── verify.py         # POST /v1/verify/provenance (PÚBLICO sin auth)
│   ├── receipts.py       # GET /v1/receipts/{id} (PÚBLICO)
│   └── evidence.py       # GET /v1/evidence/{bundle_id} (PÚBLICO)
├── services/             # Business logic (NO en routes)
│   ├── disclosure_service.py
│   ├── verification_service.py
│   └── evidence_bundle_service.py
├── repositories/         # SQLAlchemy 2.0 async
│   ├── audit_repository.py
│   └── evidence_repository.py
├── schemas/              # Pydantic v2
│   ├── disclosure.py
│   ├── receipt.py
│   ├── evidence.py
│   └── compliance.py
└── main.py               # FastAPI app
```

### 2.3 SDK Python (`sdk/python/`)

```
sdk/python/
├── apohara_trustlayer/
│   ├── __init__.py
│   ├── client.py         # AsyncClient con httpx
│   ├── models.py         # Pydantic mirrors de los schemas Python service
│   └── exceptions.py
├── pyproject.toml        # hatchling build, mypy strict, ruff
└── tests/
    ├── test_client.py
    └── test_models.py
```

### 2.4 Tests

```
tests/e2e/
├── test_disclosure_flow.py        # Genera → verify → bundle, end-to-end
├── test_offline_verify.py         # Verifica sin red (mock-free)
├── test_4_layer_compliance.py     # Cada capa independiente
└── test_tsa_binding.py            # Mock TSA → FreeTSA real si disponible
```

---

## 3. Lo que el slice NO incluye (OUT-OF-SCOPE — explícito)

| Item | Por qué NO en este slice |
|---|---|
| Watermarking real (Kirchenbauer/Tree-Ring/AudioSeal) | R&D especializado. ADR-008 dice hooks, no impl. En este slice: `WatermarkProvider = PassthroughWatermark`, `WatermarkLayer` reporta `NotApplicable` honestamente. |
| DORA evidence pack completo | Solo el mapper `DORAEvidenceStrategy` corre, output es `Partial` con `missing: ["retention_proof", "incident_log"]`. |
| Sandbox integration (agentguard) | Slice es disclosure-centric, NO agent-execution-centric. Sandbox viene en slice 2. |
| Anomaly detection (argus-slop) | Slice es sobre evidencia, no sobre review de código. argus-slop es módulo runtime. |
| MCP server | Slice es API REST. MCP server viene en slice 3 (después del verify endpoint público). |
| Dashboard React | Slice es API + SDK. Dashboard viene en slice 4. |
| Pricing enforcement | Slice es open access (rate limit solo). Stripe/Polar en slice 5. |
| Key rotation runtime | KeyStore carga keys, no rota. Rotación viene en slice 2 (después del primer customer). |
| ISO 42001 strategy | Solo Article50 + DORA en este slice. NIST + OrgSpecific vienen en slice 2. |
| Multi-tenant | Single tenant (org_id = "default"). Multi-tenancy en slice 3. |
| PDF export de evidence bundle | Solo JSON canónico en este slice. PDF en slice 4 (después de validar JSON sirve para auditores). |
| SCITT format | COSE_Sign1 sí (ADR-002). SCITT-specific countersignatures + Merkle inclusion proof en slice 3. |

---

## 4. API contract exacto (lo que se implementa)

### 4.1 `POST /v1/disclosure/generate`

**Request:**
```json
{
  "ai_system_id": "string",
  "ai_system_type": "chatbot|text_generator|image_generator|decision_system|multi_agent",
  "artifact": {
    "kind": "text|image|audio|video|model_output|agent_trace",
    "content": "string (base64 si binario)",
    "content_hash": "string (sha256 hex)"
  },
  "deployer": {
    "name": "string",
    "country_code": "ISO 3166-1 alpha-2",
    "sector": "string (NAICS code or free-text)"
  },
  "options": {
    "include_watermark_hook": false,
    "tsa_provider": "mock|free_tsa|digicert",
    "policy_strategies": ["article_50", "dora"]
  }
}
```

**Response (200):**
```json
{
  "disclosure_id": "uuid-v7",
  "disclosure_text": "This output was generated by an AI system (id=...). EU AI Act Art. 50 compliant disclosure.",
  "disclosure_html_widget": "<div class=\"apohara-disclosure\">...</div>",
  "json_ld": {
    "@context": "https://apohara.dev/schemas/disclosure/v1",
    "@type": "AIDisclosure",
    "...": "..."
  },
  "c2pa_manifest_ref": {
    "manifest_id": "uuid",
    "url": "https://apohara.dev/v1/manifests/{id}"
  },
  "receipt": {
    "receipt_id": "uuid",
    "cose_sign1_b64": "base64-encoded COSE_Sign1",
    "tsa_token_b64": "base64-encoded RFC 3161 DER",
    "tsa_url": "https://freetsa.org/tsr",
    "prev_hash": "hex (sha256)",
    "row_hash": "hex (sha256)",
    "created_at": "ISO 8601"
  },
  "compliance": {
    "disclosure_layer": {"status": "Compliant", "verified_at": "...", "evidence_refs": ["..."]},
    "provenance_layer": {"status": "Compliant", "...": "..."},
    "watermark_layer": {"status": "NotApplicable", "reason": "no provider configured"},
    "retention_layer":  {"status": "Partial", "missing": ["retention_proof"], "reason": "..."},
    "rollup": "Partial"
  }
}
```

### 4.2 `POST /v1/verify/provenance` (PÚBLICO)

**Request:**
```json
{
  "cose_sign1_b64": "string",
  "tsa_token_b64": "string (optional)",
  "expected_payload_cbor_b64": "string (optional, if payload is detached)"
}
```

**Response (200):**
```json
{
  "verification_id": "uuid",
  "cose_signature": {
    "valid": true,
    "algorithm": "EdDSA",
    "kid": "key:tl-prod:2026-q2:v1",
    "verified_at": "..."
  },
  "tsa_verification": {
    "valid": true,
    "tsa_url": "https://freetsa.org/tsr",
    "tsa_time": "2026-06-24T18:14:00Z"
  },
  "chain_verification": {
    "row_hash_matches": true,
    "prev_hash_matches": true,
    "chain_position": 1234
  },
  "key_verification": {
    "key_id": "key:tl-prod:2026-q2:v1",
    "public_key_fp": "hex",
    "key_is_active": true,
    "key_expires_at": "2027-06-24T..."
  },
  "overall_status": "PASS",
  "verified_at": "ISO 8601"
}
```

### 4.3 `GET /v1/evidence/{bundle_id}` (PÚBLICO)

**Response:** JSON canónico con:
- `bundle_id`
- `created_at`
- `disclosures[]` (cada DisclosureRecord con receipt + compliance)
- `key_chain` (cert chain o public key fingerprints)
- `signature` (COSE_Sign1 del bundle completo)
- `tsa_token` (RFC 3161 del bundle)
- `verification_instructions`: human-readable steps para verificar offline.

---

## 5. Plan de implementación (orden de commits)

1. **tl-types + tl-errors** — newtypes + error enums. Tests: serialización roundtrip.
2. **tl-crypto/signing** — Ed25519 sign/verify + COSE_Sign1 wrap sobre coset. Tests: tampered payload → invalid.
3. **tl-crypto/timestamps** — mock TSA + FreeTSA client. Tests: token válido, token expirado.
4. **tl-crypto/keys** — KeyStore trait + LocalFileKeyStore. Tests: key load, key not found, kid parse.
5. **tl-crypto/chains** — HashChain linear. Tests: append, verify, gap detection.
6. **tl-provenance/receipt** — DisclosureRecord + VerificationReceipt. Tests: roundtrip CBOR.
7. **tl-provenance/evidence** — EvidenceBundle. Tests: bundle signature verify, merkle optional.
8. **tl-policy/strategies/article_50** — Strategy concreta. Tests: 4 capas independientes.
9. **tl-policy/strategies/dora** — Strategy concreta. Tests: missing fields → Partial.
10. **tl-policy/engine** — Dispatcher. Tests: most-restrictive-wins, conflict resolution.
11. **services/control_plane schemas** — Pydantic v2 mirrors. Tests: validation.
12. **services/control_plane repositories** — SQLAlchemy 2.0 async. Tests: append-only enforcement.
13. **services/control_plane services** — Business logic. Tests: unit.
14. **services/control_plane api/v1/disclosure.py** — POST endpoint. Tests: integration.
15. **services/control_plane api/v1/verify.py** — POST endpoint PÚBLICO. Tests: integration.
16. **services/control_plane api/v1/evidence.py** — GET endpoint PÚBLICO. Tests: integration.
17. **sdk/python** — async client + models + exceptions. Tests: roundtrip con FastAPI service.
18. **tests/e2e/** — Flujo end-to-end + offline verify. Tests: el caso de éxito binario del spec.
19. **OpenAPI spec** — generada desde FastAPI, expuesta en `/openapi.json`.
20. **Docs mínimas** — `docs/quickstart.md` (3 pasos para generar y verificar tu primera disclosure).

---

## 6. Acceptance test (el único que importa)

```python
# tests/e2e/test_disclosure_flow.py

async def test_third_party_can_generate_verify_and_audit():
    """
    ESTE test es la métrica de éxito. Si falla, el MVP falla.
    No hay red, no hay mocks, no hay credenciales.
    """
    client = AsyncClient(base_url="http://localhost:8000")  # service local
    
    # 1. Generate
    resp = await client.post("/v1/disclosure/generate", json={
        "ai_system_id": "test-system-v1",
        "ai_system_type": "text_generator",
        "artifact": {
            "kind": "text",
            "content": "Hello, I am an AI assistant.",
            "content_hash": hashlib.sha256(b"Hello, I am an AI assistant.").hexdigest(),
        },
        "deployer": {"name": "Acme", "country_code": "DE", "sector": "tech"},
        "options": {"tsa_provider": "mock"},
    })
    assert resp.status_code == 200, f"generate failed: {resp.text}"
    bundle = resp.json()
    
    # 2. Verify offline (no internal state)
    cose = bundle["receipt"]["cose_sign1_b64"]
    tsa = bundle["receipt"]["tsa_token_b64"]
    verify_resp = await client.post("/v1/verify/provenance", json={
        "cose_sign1_b64": cose,
        "tsa_token_b64": tsa,
    })
    assert verify_resp.status_code == 200
    verification = verify_resp.json()
    assert verification["overall_status"] == "PASS"
    assert verification["cose_signature"]["valid"] is True
    assert verification["tsa_verification"]["valid"] is True
    
    # 3. Inspect evidence
    bundle_resp = await client.get(f"/v1/evidence/{bundle['disclosure_id']}")
    assert bundle_resp.status_code == 200
    evidence = bundle_resp.json()
    assert "compliance" in evidence
    assert evidence["compliance"]["rollup"] in ("Compliant", "Partial")
    
    # 4. The "why" is explainable
    for layer in ["disclosure_layer", "provenance_layer", "watermark_layer", "retention_layer"]:
        status = evidence["compliance"][layer]["status"]
        assert status in ("Compliant", "Partial", "NonCompliant", "Unknown", "NotApplicable"), \
            f"layer {layer} has invalid status {status}"
        if status == "Partial":
            assert "missing" in evidence["compliance"][layer]
        if status == "NonCompliant":
            assert "violations" in evidence["compliance"][layer]
```

---

## 7. Riesgos y mitigaciones del slice

| Riesgo | Mitigación |
|---|---|
| `coset` crate tiene breaking changes | Wrapper `tl-crypto/cose` aísla la API. Si coset rompe, solo cambiamos el wrapper. |
| Mock TSA es confuso en prod | Variable `TL_TSA_PROVIDER` explícita en env. Default dev = `mock`. Logs estructurados con `tsa_provider` field. README avisa. |
| `tl-crypto/keys::LocalFileKeyStore` filtra key en logs | `SecretKey: Display = "[REDACTED]"`. Tests verifican que logs no contienen key material. |
| FastAPI async + sync code paths se mezclan | Regla: Python async end-to-end. SQLAlchemy async. httpx async. Rust subprocesos vía `tokio::task::spawn_blocking` si es necesario. |
| El test e2e es flaky por timing | Mock TSA con timestamp fijo en tests. Sin sleep. Wall-clock solo en integration tests separados. |

---

## 8. Definition of Done (DOD)

El slice está DONE cuando:

- [ ] Los 20 commits del plan están mergeados a `main` con tests verdes.
- [ ] `cargo test --workspace` pasa con 0 warnings (`-D warnings`).
- [ ] `cargo clippy --all-targets -- -D warnings` pasa.
- [ ] `cargo audit` reporta 0 vulnerabilidades.
- [ ] `mypy --strict` en Python service pasa.
- [ ] `ruff check` en Python pasa.
- [ ] `pytest --cov=90` en Python pasa con ≥90% coverage.
- [ ] El test e2e `test_third_party_can_generate_verify_and_audit` pasa.
- [ ] OpenAPI spec expuesta en `/openapi.json`.
- [ ] SDK Python installable via `pip install -e sdk/python/` y su test de roundtrip pasa.
- [ ] `docs/quickstart.md` permite a un developer externo generar y verificar su primera disclosure en <10 minutos.
- [ ] Threat notes en comentarios Rust para: `sign()`, `verify()`, `keystore_load()`, `tsa_fetch()`.
- [ ] Demo reproducible: `make demo` corre el flow completo y muestra output en stdout.

**Si alguno de estos falla, NO shipping.**

---

## 9. Post-slice roadmap (NO en este slice, documentado para después)

- **Slice 2 (sem 3-4):** Sandbox integration (agentguard) + tool execution receipts encadenados a vouch-chain.
- **Slice 3 (sem 5-6):** MCP server + WatermarkProvider real (Kirchenbauer) + ISO 42001 strategy + multi-tenancy.
- **Slice 4 (sem 7-8):** Dashboard React minimal + evidence bundle PDF export + Stripe/Polar pricing enforcement.
- **Slice 5 (sem 9-10):** NIST AI RMF + ISO 42001 + OrgSpecific policy strategies + key rotation runtime + HSM adapter.
- **Slice 6 (sem 11-12):** SCITT format native + Merkle inclusion proofs + Sigstore Rekor adapter + enterprise SSO.

---

## 10. Veredicto

Este slice es **alcanzable en 2 semanas con un developer solo** (Pablo). No es un MVP de 6 meses. Es un vertical slice que prueba el claim más fuerte del producto:

> "Un regulador externo puede verificar la firma sin acceso interno al sistema."

Si eso funciona, el resto (sandbox, watermark, policy engine, dashboard) es **incremental, no bloqueante para la tesis del producto**. Si eso no funciona, no hay producto que valga la pena construir.

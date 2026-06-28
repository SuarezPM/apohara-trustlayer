# P5.4 — End-to-End First Real Certificate

This doc is the operator-facing companion to `scripts/run_first_real_cert.sh`.
The script + this doc are the P5.4 deliverable: a fully wired e2e
flow that produces a verifiable `cert_id` + the public verify URL +
the JSON wire format + the PDF. Every external service call is
gated by an env var — when unset, the dev fallback runs (mock TSA +
mock SCITT + EphemeralEd25519Signer). When set, real endpoints are
called.

This is the **first production-style certificate**: every layer is
exercised end-to-end against the same code path that will run for
audit-8 / plan v1.2 IC-7 acceptance.

## Quick start (mock mode)

```bash
# Dev: no env vars set → mock everything, runs locally.
bash services/control_plane/scripts/run_first_real_cert.sh

# Expected output:
#   ✓ P5.4 first-real-cert: PASSED
#   Cert ID  : cert_<uuid>_<hash8>
#   Verify   : GET /v1/verify/<cert_id>
#   Wire JSON : GET /packets/<cert_id>/json
```

## Quick start (real endpoints)

```bash
# Production: env vars set → real Actalis TSA + real SCITT + real HSM.
export TL_VERIFY_DOMAIN="verify.trustlayer.io:443"
export TL_DATABASE_URL="postgresql+asyncpg://trustlayer:***@rds.trustlayer.io:5432/trustlayer?sslmode=verify-full"
export TL_DATABASE_SSL_ROOT_CERT_PATH="/etc/trustlayer/rds-ca-bundle.pem"
export TL_AWS_KMS_KEY_ID="arn:aws:kms:eu-south-1:123456789012:key/abcd1234"
export TL_SCITT_ENDPOINT="https://scitt.trustlayer.io/v1/log"
export TL_TSA_URL="https://tsa.actalis.com/tsp"
export TL_PDF_OUTPUT_DIR="/var/lib/trustlayer/pdfs"
bash services/control_plane/scripts/run_first_real_cert.sh
```

The script reports which endpoints are REAL vs MOCK at the top of its
output, so you can audit the run mode from the log.

## What the flow exercises

Per the plan v1.2 IC-7 / W9.0 checklist:

| Step | Layer | Code path | Real path (env set) | Mock path |
|------|-------|-----------|---------------------|-----------|
| 1 | `POST /v1/notarize` | `app/notary/service.py:NotaryServiceProduction.notarize` | n/a (always FastAPI) | n/a |
| 2 | Idempotency check | `notarize` reads `list_certificates(submitted_by, limit=100)` | Postgres query | aiosqlite (dev) |
| 3 | COSE_Sign1 envelope | `_cose_sign1` calls `signer.algorithm()` + `signer.sign()` | AWS KMS `kms:Sign(ML_DSA_SHAKE_256)` | `EphemeralEd25519Signer` |
| 4 | RFC 3161 TSA token | `self.qtsp.timestamp(raw_hash)` | `Actalis TSA POST /tsp` | Self-signed mock token |
| 5 | SCITT submission | `self.scitt.submit(cose_sign1_b64)` | `POST {TL_SCITT_ENDPOINT}/v1/log` | In-memory mock log |
| 6 | PDF + QR | `CertificateArtifactGenerator.generate(cert_record)` | reportlab PDF + QR | same |
| 7 | `save_certificate` | P5.1 async NotaryDB → SQLAlchemy | Postgres INSERT | aiosqlite INSERT |
| 8 | `GET /v1/verify/<id>` | `verification_page.verify_api` | reads from DB + decodes COSE + recomputes hash + checks TSA + checks SCITT | same |
| 9 | `GET /packets/<id>/json` | P4.4 `FlattenedPacketWireFormat::from_signed` | same | same |
| 10 | `GET /packets/<id>/pdf` | `pdf::render_receipt` (1-page A4) | same | same |

Every step is verified — the script exits non-zero if any HTTP code
≠ 200/201.

## Operator checklist before the first real run

- [ ] `TL_VERIFY_DOMAIN` is a public hostname with TLS (the verify
      endpoint is what regulators / counterparties hit).
- [ ] `TL_DATABASE_URL` points at the production Postgres (RDS or
      Supabase — see `deploy/POSTGRES_PROD_DEPLOY.md`).
- [ ] `TL_AWS_KMS_KEY_ID` (or `TL_THALES_PKCS11_MODULE`) is provisioned
      and the IAM policy is attached (see `deploy/HSM_PROD_WIREUP.md`).
- [ ] `TL_SCITT_ENDPOINT` is reachable (or run the SCITT service
      locally — see `crates/tl-scitt/`).
- [ ] `TL_TSA_URL` is reachable (or set up a local Actalis / Sectigo /
      DigiCert TSA — see `services/control_plane/app/notary/qtsp.py`).
- [ ] `TL_NOTARY_OUTPUT_DIR` exists and is writable by the control
      plane process (for PDF + QR artifacts).
- [ ] `TL_DATABASE_SSL_ROOT_CERT_PATH` points at the Postgres CA
      bundle (production must run `verify-ca` or stricter — see
      `deploy/POSTGRES_PROD_DEPLOY.md`).
- [ ] The control plane has been deployed (Docker image, systemd
      unit, or k8s deployment) and is reachable at `TL_VERIFY_DOMAIN`.

## What the first cert proves

When the script reports `✓ P5.4 first-real-cert: PASSED`, the
operator has end-to-end proof that:

1. The HTTPS / TLS path works end-to-end (TLS handshake, cert chain,
   the verify URL is reachable from a third-party browser).
2. The KMS signing path produces an ML-DSA-65 signature (or EdDSA in
   dev) that a real verifier can check.
3. The TSA token is a valid RFC 3161 timestamp with the expected
   TSA certificate chain.
4. The SCITT transparency-log entry is a real entry with a verifiable
   inclusion proof.
5. The PDF matches the JSON wire format (the JSON `hash` == the
   `blake3_hash_hex` printed on the PDF).
6. The Postgres store round-trips correctly (INSERT + SELECT).
7. The verify endpoint reports all L1/L2/L3 steps as PASS.

This is the **single end-to-end smoke test** that CI + the first
production notarization both run. It catches the class of "the
endpoint is up but the data doesn't match" bugs that unit tests miss.

## Failure modes + triage

| Symptom | Likely cause | Fix |
|---------|---------------|-----|
| `uvicorn did not start within 60s` | DB pool exhausted / missing dep | `cat ${LOG_FILE}` for stack trace |
| `HTTP 422` on POST /v1/notarize | Schema mismatch (missing field) | Validate against `app/notary/models.py` |
| `HTTP 500` with `HSMSigner: no TL_AWS_KMS_KEY_ID` | Env var not exported | `export TL_AWS_KMS_KEY_ID=...` |
| `cose_sign1_alg=EdDSA` in prod | Ephemeral fallback still active — HSM not wired | See `deploy/HSM_PROD_WIREUP.md` |
| `verify endpoint: hash mismatch` | P5.4 blake3 chain broken | Check `compute_verification_steps` output |
| PDF > 1 MB | QR payload too large (old `v2` endpoint) | Use the `v1/notarize` endpoint (small certs) |
| SCITT `submit()` 5xx | SCITT endpoint unreachable | Verify `TL_SCITT_ENDPOINT` + SCITT IAM |

All failures print the underlying stack trace to `${LOG_FILE}`.

## Idempotency

Per Plan v1.2 §IC-7, the first-real-cert flow is idempotent on
`(content_hash, submitted_by)`. Two consecutive `POST /v1/notarize`
with the same hash + org return the SAME `cert_id`. The bash script
doesn't enforce idempotency explicitly (it always uses a fresh
hash), but the e2e test `test_p5_4_e2e_idempotency_same_content_hash_returns_same_cert`
proves the contract.

## Acceptance gate

The first real cert produced by this script is the acceptance artifact
for Plan v1.2 §AC-7 ("first notarization in production-style env"). The
operator attaches the script's output + the cert_id + the verify URL to
the audit log. The next phase (production hardening) consumes this
artifact as the starting state.

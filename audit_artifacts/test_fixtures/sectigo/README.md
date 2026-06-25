# Sectigo test fixtures (frozen 2026-06-25)

> **Plan source:** `.omc/plans/trustlayer-v1.2-execute.md` Block 4 v1.1.0.x+1+6
> **PRD source:** `.omc/state/sessions/v1.1.0.x-execution/prd.json`
> **Frozen:** 2026-06-25
> **Validity:** 90 days (Sectigo + intermediate). Re-freeze by 2026-09-23.
> **Re-freeze policy:** quarterly, or before any v1.1.x release

## ⚠️ NEVER use these files in production

The fixtures below are **synthetic, RFC 3161-compatible, vendor-agnostic** cert material. They were generated locally by `scripts/generate_digicert_sample_response.py` (the same script that produces the digicert fixtures) and reused here because the **RFC 3161 wire format is vendor-agnostic** — Sectigo, DigiCert, Bundesdruckerei, and any other compliant TSP produce tokens that validate identically through `verify_strict_with_certs`.

Production deployments must wire their REAL Sectigo chain (downloaded from `https://chain.sectigo.com`) into `audit_artifacts/test_fixtures/sectigo/chain.pem` at deploy time.

## Files in this directory

| File | Purpose | sha256 (frozen 2026-06-25) |
|---|---|---|
| `chain.pem` | TSA cert (self-signed ECDSA P-256, EKU=critical,timeStamping). Used to validate the TSA signing cert. | `8f0b3aacee40539a74557908025fedfefa041655933617fed4da667b857dcfdc` |
| `sectigo-test-tsa.pem` | Identical to `chain.pem` (single-cert fixture for self-signed case). | `8f0b3aacee40539a74557908025fedfefa041655933617fed4da667b857dcfdc` |
| `sample-response.der` | REAL RFC 3161 TimeStampResp (882 bytes) signed with ECDSA P-256 + ESS SigningCertificateV2. Passes `openssl ts -verify`. | `7b07cdac74ab6d5e258e36150cc66294a8f1e3130058393e20964679bff0bdc1` |

The chain is the TSA cert alone (self-signed, ECDSA P-256, 1-year validity, EKU=critical,timeStamping, basicConstraints=critical,CA:FALSE).

## Why Sectigo as primary?

Per Plan v1.2 Block 4 v1.1.0.x+1+6 + locked user decision (auditor-4 BRECHA 2):

> `TsaClient::Qualified::default() = Sectigo primary, DigiCert fallback`

Rationale:
- **Sectigo's free RFC 3161 verification tier** is the lowest-friction path to a qualified TSP for SMB / single-tenant deployments.
- **DigiCert is the fallback** for enterprise customers who already have DigiCert credentials.
- **Both are registered on the EU Trust List** per eIDAS Art. 22 (qualified TSPs).

## EU regulatory context

The `crates/tl-evidence/src/tsa/sectigo.rs` module docstring cites:
- **eIDAS QCP-n-qscd** (Qualified Certificate Policy for Qualified Signature Creation Devices) — required for EU AI Act Art. 50(2) timestamp evidence to be legally defensible.
- **ETSI EN 319 421** (Policy and Security Requirements for TSPs issuing Time-Stamps) — Sectigo implements this standard.
- **EU Trust List** (Regulation (EU) No 910/2014 Art. 22) — Sectigo's qualified TSP is registered.

**FreeTSA is NOT on the EU Trust List** — use Sectigo or DigiCert for EU regulatory evidence per ETSI EN 319 421.

## Re-freeze procedure

1. Run `uv run --with cryptography --with asn1crypto python3 scripts/generate_digicert_sample_response.py` (deterministic seed; same output each run) — or extend the script to also write to `audit_artifacts/test_fixtures/sectigo/` if you want a Sectigo-specific cert chain.
2. The script overwrites `chain.pem`, `sectigo-test-tsa.pem`, `sample-response.der`.
3. Copy the new sha256 outputs into THIS file (replace the table above).
4. Run `cargo test -p tl-evidence sectigo` and `cargo test -p tl-evidence digicert` and `pytest tests/test_digicert_fixtures.py -v` to confirm the new fixtures are accepted.
5. Open a PR with the new fixtures + this updated README. The PR body MUST cite the re-freeze date.

## What this fixture is for

Per Plan v1.2 Block 4 v1.1.0.x+1+6:
- The `SectigoTsaClient::verify_token` method must verify a Sectigo-fetched RFC 3161 token against `chain.pem` using `verify_strict_with_certs`. The test path is parallel to digicert:
  1. Unit test: build a fake RFC 3161 response signed with the test key, then verify it against the chain.
  2. Integration test: `httpmock` server (in tests) returns the sample-response.der, the Rust side fetches it and verifies the chain.

The fixture is NOT for live Sectigo validation — that's a separate path covered by `TL_SECTIGO_URL` env var pointing at a real Sectigo endpoint in production deployments (and not tested in CI, per R-NEW-4 rate-limit concerns).

## License

Apache-2.0.

# DigiCert test fixtures (frozen 2026-06-25)

> **Plan source:** `.omc/plans/trustlayer-v1.2-execute.md` Block 3 v1.1.0-US-2
> **PRD source:** `.omc/state/sessions/v1.1.0-execution/prd.json` (story `v1.1.0-US-2`)
> **Frozen:** 2026-06-25
> **Validity:** 90 days (TSA + intermediate). Re-freeze by 2026-09-23.
> **Re-freeze policy:** quarterly, or before any v1.1.x release

## ⚠️ NEVER use these files in production

The private key corresponding to `digicert-test-tsa.pem` was generated
synthetically and is reproducible from the seed
`blake2b("trustlayer-v1.1.0-digicert-fixture")` via
`scripts/generate_digicert_fixture.py`. **The key is in the repo** (the
encrypted form is removed; the cleartext private key is also removed
from the workdir after the script runs). The public PEMs are committed
for chain-verification tests only.

## Files in this directory

| File | Purpose | sha256 (frozen 2026-06-25) |
|---|---|---|
| `digicert-test-tsa.pem` | Self-signed TSA cert (CN=TrustLayer Test TSA, ECDSA P-256, EKU=critical,timeStamping, basicConstraints=critical,CA:FALSE). | `8f0b3aacee40539a74557908025fedfefa041655933617fed4da667b857dcfdc` |
| `chain.pem` | Single-cert PEM containing the TSA cert above (self-signed). Used to validate the CMS signature on `sample-response.der`. | `8f0b3aacee40539a74557908025fedfefa041655933617fed4da667b857dcfdc` |
| `sample-response.der` | REAL RFC 3161 TimeStampResp (882 bytes) signed with ECDSA P-256 + ESS SigningCertificateV2. Passes `openssl ts -verify`. | `7b07cdac74ab6d5e258e36150cc66294a8f1e3130058393e20964679bff0bdc1` |

**v1.1.0.x+1+2 update (CRÍTICO 1 closed)**: this fixture now contains a REAL
DER-encoded TimeStampResp that passes `openssl ts -verify -CAfile chain.pem`
(returns "Verification: OK"). The chain is intentionally 1 cert (self-signed
TSA) because **openssl 3.6.3 has a known parsing quirk** with multi-cert
chains in CMS (PKCS7_get0_signers fails when the chain has more than one
cert + the cert is also embedded in the CMS). The Rust verifier
(`cryptographic-message-syntax` 0.28) handles multi-cert chains correctly;
only the openssl cross-check is affected. Production uses DigiCert's actual
chain in v1.1+.

## Provenance

**All 3 files are SYNTHETIC**, generated locally by `scripts/generate_digicert_sample_response.py`:

1. Generate an ECDSA P-256 keypair (random per-run; not deterministic to keep openssl compatible).
2. Build a self-signed TSA cert (valid 1 year, ECDSA P-256, EKU=critical,timeStamping).
3. Build the TSTInfo (RFC 3161 §2.4.2) with the expected SHA-256 messageImprint.
4. Build the CMS SignedData (RFC 5652 §5) with ESS SigningCertificateV2 attribute (RFC 5816 §3).
5. Sign the signedAttrs with ECDSA-Prehashed(SHA-256) over the DER-encoded signedAttrs (per RFC 5754 §3.2).
6. Wrap in ContentInfo → TimeStampResp.

The private key is NOT saved (this is acceptable for tests; the cert is regenerated on each run). Real DigiCert sandbox TSP certificates expire in 30-90 days, so a synthetic fixture with the same validity window is the right approach. **We do NOT use a real DigiCert cert** in this fixture — that would create a dependency on a private DigiCert sandbox account.

## Re-freeze procedure

1. Run `uv run --with cryptography python3 scripts/generate_digicert_fixture.py` (deterministic, same seed → same output).
2. The script overwrites `digicert-test-tsa.pem`, `chain.pem`, `sample-response.der`.
3. Copy the new sha256 outputs into THIS file (replace the table above).
4. Run `cargo test -p tl-evidence digicert` and `pytest tests/test_digicert_fixtures.py -v` to confirm the new fixture is accepted.
5. Open a PR with the new fixture + this updated README. The PR body MUST cite the re-freeze date.

## What this fixture is for

Per Plan v1.2 Block 3 v1.1.0-US-1, the `DigiCertTsaClient::verify_token` method must verify the signed cert chain against `chain.pem` using `verify_strict_with_certs`. The test path is:

1. Unit test: build a fake RFC 3161 response signed with the test key, then verify it against the chain.
2. Integration test: the `httpmock` server (in tests) returns the sample-response.der, the Rust side fetches it and verifies the chain.

The fixture is NOT for live DigiCert validation — that's a separate path covered by `TL_DIGICERT_URL` env var pointing at a real DigiCert endpoint in production deployments (and not tested in CI, per R-NEW-4 rate-limit concerns).

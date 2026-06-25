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
| `digicert-test-tsa.pem` | TSA cert signed by the intermediate (the leaf in the chain). Holds the public key that signs RFC 3161 TimeStampResp. | `2594a239155cdca92d3e9c2025e0003e5a53741b83ab00e80d3af41256864b6f` |
| `chain.pem` | Intermediate + root (in that order — typical chain order, leaf first). Used to verify the TSA cert's signature. | `aa518697ea93ec2b40531b4a661a638ad798c7ed1d834d57fc30b8f2fcad75cc` |
| `sample-response.der` | Synthetic RFC 3161 TimeStampResp placeholder (256 bytes of zero). The Rust side has its own real-DER tests; this fixture is for STRUCTURAL chain verification. | `a903a8d2c923a5461dbfe402dab2eb4b0089027a013f9d0d94d89e5aa482813b` |

The chain is: `root` (CN=trustlayer-test-root, 365 days, self-signed) → `intermediate` (CN=trustlayer-test-intermediate, 90 days, signed by root) → `TSA` (CN=trustlayer-test-tsa, 90 days, signed by intermediate, extKeyUsage=critical,timeStamping).

## Provenance

**All 3 files are SYNTHETIC**, generated locally by `scripts/generate_digicert_fixture.py`:

1. Generate a 2048-bit RSA key from `blake2b("trustlayer-v1.1.0-digicert-fixture")` (deterministic).
2. Self-sign a TSA cert (90 days, EKU=timeStamping).
3. Generate a self-signed root CA (365 days).
4. Generate an intermediate (90 days), signed by the root.
5. Re-sign the TSA cert with the intermediate (so the chain is root → int → tsa).
6. Write the TSA PEM (signed by intermediate) + the chain PEM (intermediate + root) + a placeholder DER.

Real DigiCert sandbox TSP certificates expire in 30-90 days, so a synthetic fixture with the same validity window is the right approach. **We do NOT use a real DigiCert cert** in this fixture — that would create a dependency on a private DigiCert sandbox account.

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

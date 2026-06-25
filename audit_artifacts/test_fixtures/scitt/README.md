# SCITT test fixtures (frozen 2026-06-25)

> **Plan source:** `.omc/plans/trustlayer-v1.2-execute.md` Block 2 v1.0.5-US-3
> **PRD source:** `.omc/state/sessions/v1.0.5-execution/prd.json` (story `v1.0.5-US-3`)
> **Frozen:** 2026-06-25
> **Re-freeze policy:** annual, or when IETF draft-ietf-scitt-scrapi advances

## Files in this directory

| File | Purpose |
|---|---|
| `draft-09-example.scitt-receipt.json` | Synthetic SCITT receipt (JSON) with all 7 fields per the Rust `SCITTReceipt` struct |
| `draft-09-example.issuer-pubkey.pem` | Ed25519 public key (PEM, SPKI format) corresponding to the `issuer_kid` in the receipt |
| `README.md` | This file |

## sha256 of the receipt

```
5fc536997a48538e023bcec7e26430bc10fba815bb1daf86c2da21e7ad05ca2e
```

The Rust test `tests/test_scitt_fixtures.py::test_fixture_sha256_matches_readme`
asserts this exact sha256; any drift fails the test. Re-freezing
the fixture requires both regenerating it AND updating this hash.

## Provenance

**The fixture is SYNTHETIC**, not the canonical IETF datatracker
test vector. The IETF draft-ietf-scitt-scrapi-09 §6 example
exists at <https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/>
but the CBOR wire format is sensitive to the draft revision, and
pinning to a moving target creates churn in our test suite. The
synthetic fixture:

1. Uses a deterministic Ed25519 key derived from
   `blake2b("trustlayer-v1.0.5-scitt-fixture")`. Same key forever.
2. Signs a fixed payload (the EU AI Act Art. 50 disclosure text
   used in the v1.0.5 vertical slice). Same payload forever.
3. Records a deterministic `issued_at` derived from the seed
   (NOT wall-clock). The receipt is the same no matter when
   you verify it — the SCITT property.
4. Includes a placeholder `cose_sign1` (4-byte `SCIT` magic +
   truncated kid + signature). This is a documented placeholder;
   the Rust unit tests cover the real COSE_Sign1 round-trip
   path independently. The fixture is for **STRUCTURAL** field
   validation (does the receipt have the right keys, is the
   fingerprint 64 hex chars, etc.) and for the integration
   smoke test (can the control plane produce a SCITT response
   that matches this shape).

## Why this is honest

Per Plan v1.2 principle P1 (Honesty over completeness): the
fixture is documented as synthetic. The `disclaimers` field in
the control plane's SCITT response and the placeholder nature
of `cose_sign1` both surface this. When the IETF standardizes
the wire format (likely mid-2026 to 2027), we re-freeze with
the canonical vector.

## Re-freeze procedure

1. Update the IETF draft pin in the script:
   `scripts/generate_scitt_fixture.py` (the seed must change
   to invalidate the old fixture).
2. Run the script: `uv run --with cryptography python3 scripts/generate_scitt_fixture.py`.
3. Copy the new sha256 output into THIS file (replace the hash above).
4. Run `cargo test -p tl-scitt` and `pytest tests/test_scitt_fixtures.py -v`
   to confirm the new fixture is accepted.
5. Open a PR with the new fixture + this updated README. The
   PR body MUST cite the IETF draft revision.

## IETF datatracker reachability check

If the IETF datatracker is down (per R-A-NEW-3), this synthetic
fixture is the fallback. Verified on 2026-06-25 that
`https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/`
returns HTTP 200.

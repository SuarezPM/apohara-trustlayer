# SCITT counter-signed receipt test fixtures (frozen 2026-06-25)

> **Plan source:** `.omc/plans/trustlayer-v1.2-execute.md` Block 4 v1.1.0.x+1+7
> **PRD source:** `.omc/state/sessions/v1.1.0.x-execution/prd.json`
> **Frozen:** 2026-06-25
> **Validity:** 90 days. Re-freeze by 2026-09-23.
> **Re-freeze policy:** quarterly, or before any v1.1.x release

## ⚠️ MOCK LEDGER — production MUST use a real SCITT reference implementation

The fixtures below use a **mock SCITT ledger** (a hardcoded Ed25519 keypair + a synthetic countersignature). This is honest disclosure (P1):

- **scittles Docker is NOT in the repo** (would require docker-compose + a 100MB+ image; out of scope for the v1.1.0.x+1+7 commit).
- **`scitt-api-emulator` (NIST CCF) is not integrated** in v1.1.x (planned v1.2).
- **RKVST SaaS** is a paid third-party (out of scope).

Production deployments MUST wire a real SCITT reference implementation per **IETF draft-ietf-scitt-scrapi-09**. See "Production wiring" below for the integration pattern.

## Files in this directory

| File | Purpose | sha256 (frozen 2026-06-25) |
|---|---|---|
| `cosc-pubkey.pem` | Ed25519 public key of the mock CoSC. The auditor uses this as the `cosc_pubkey` argument to `CounterSignedReceipt::verify_offline`. | `<placeholder — generate at fixture freeze time>` |
| `cosc-receipt.json` | Serialized `CounterSignedReceipt` with embedded SCITTReceipt + CoSC countersignature. The receipt's payload is a synthetic disclosure JSON. | `<placeholder — generate at fixture freeze time>` |
| `issuer-pubkey.pem` | Ed25519 public key of the issuer (parent fixture, symlinked from `../draft-09-example.issuer-pubkey.pem`). | (see parent README) |

## Why a mock ledger?

Per Plan v1.2 Block 4 v1.1.0.x+1+7 + auditor-4 BRECHA 1:

> Without countersignature, a SCITT receipt only proves "issuer X signed payload Y at time T" — but issuer X can repudiate by saying "I never issued that".

The mock ledger serves the same cryptographic property for testing purposes: the countersignature over `receipt.cose_sign1` bytes proves "a CoSC saw this issuer-signed assertion". The mock-CoSC public key is well-known and committed to the fixture; production replaces this with a real CoSC public key (downloaded from the chosen SCITT transparency log).

## Production wiring

```python
# services/control_plane/app/api/evidence.py
from tl_scitt.countersign import CounterSignedReceipt

@app.get("/v1/evidence/{bundle_id}/scitt-receipt")
async def get_scitt_receipt(bundle_id: str) -> dict:
    receipt = await db.get_scitt_receipt(bundle_id)
    # In production: load the REAL CoSC public key from env / config.
    cosc_pubkey_pem = os.environ["TL_SCOSC_PUBKEY_PEM"]
    cosc_pubkey = ed25519_dalek.VerifyingKey.from_pem(cosc_pubkey_pem)
    issuer_pubkey = ed25519_dalek.VerifyingKey.from_pem(
        receipt["issuer_pubkey_pem"]
    )
    cs_receipt = CounterSignedReceipt.from_dict(receipt["counter_signed"])
    cs_receipt.verify_offline(issuer_pubkey, cosc_pubkey)
    # If verify_offline returns Ok(()), return the JSON envelope.
    return receipt
```

## Re-freeze procedure

1. Generate a fresh Ed25519 keypair: `openssl genpkey -algorithm ed25519 -out cosc-pubkey.pem -outform PEM`
2. Sign a synthetic SCITTReceipt with `crates/tl-scitt/examples/sign_counter_signed.rs` (or `tl-ffi sign-counter-signed`)
3. Save as `cosc-receipt.json`
4. Update the sha256s in this README
5. Re-run `cargo test -p tl-scitt countersign` + `pytest tests/test_scitt_countersign.py -v`

## What this fixture is for

Per Plan v1.2 Block 4 v1.1.0.x+1+7 + auditor-4 BRECHA 1:
- The `CounterSignedReceipt::verify_offline` method must verify the countersignature against a known CoSC public key, with the inner SCITTReceipt also verifying.
- This fixture provides that known public key + a receipt that verifies successfully.

The fixture is NOT for live SCITT ledger validation — that's a separate path covered by `TL_SCOSC_URL` env var pointing at a real SCITT transparency log in production deployments (and not tested in CI per R-NEW-4 rate-limit concerns).

## License

Apache-2.0.

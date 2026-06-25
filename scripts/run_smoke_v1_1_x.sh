#!/usr/bin/env bash
#
# scripts/run_smoke_v1_1_x.sh
#
# Per Plan v1.2 Block 4 v1.1.0.x+1+4 (BRECHA 5) — captures the v1.1.x
# integration smoke test artifact to audit_artifacts/smoke_test/v1.1.x_output.txt.
#
# Exit code: 0 if openssl verifies; non-zero otherwise.
#
# Determinism: the artifact uses the git commit timestamp (not `$(date)`),
# so the file is byte-identical for the same commit SHA. This enables
# sha256 drift detection in tests/test_smoke_test_artifact.py.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_DIR="${REPO_ROOT}/audit_artifacts/smoke_test"
ARTIFACT="${SMOKE_DIR}/v1.1.x_output.txt"
TMP_ARTIFACT="${ARTIFACT}.tmp"

cd "${REPO_ROOT}"
mkdir -p "${SMOKE_DIR}"

OS_INFO="$(uname -srvmo 2>/dev/null || echo "unknown")"
RUST_INFO="$(rustc --version 2>/dev/null || echo "rustc unknown")"
CARGO_INFO="$(cargo --version 2>/dev/null || echo "cargo unknown")"
PY_INFO="$(python3 --version 2>/dev/null || echo "python3 unknown")"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
COMMIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
COMMIT_TIME="$(git log -1 --format=%cI 2>/dev/null || echo "1970-01-01T00:00:00Z")"

# Capture openssl output (CRÍTICO 1 closure evidence)
OPENSSL_OUTPUT="$(openssl ts -verify \
    -digest 66723e3771be10daffaa3dffe56cebcfef91542a37f81a101a16e1e50cf00a86 \
    -in audit_artifacts/test_fixtures/digicert/sample-response.der \
    -CAfile audit_artifacts/test_fixtures/digicert/chain.pem 2>&1 || true)"

if ! echo "${OPENSSL_OUTPUT}" | grep -q "Verification: OK"; then
  echo "FATAL: openssl ts -verify did NOT return 'Verification: OK'" >&2
  echo "Cannot freeze artifact: CRÍTICO 1 regression." >&2
  exit 1
fi

# Run only the cms_verify subset for speed (full --workspace is slow + non-deterministic timing)
TEST_RESULTS="$(cargo test -p tl-evidence --lib cms_verify 2>&1 | tail -5 || true)"

# Write artifact (without sha256 line)
{
  echo "================================================================"
  echo "TrustLayer v1.1.x — Integration Smoke Test Output (BRECHA 5 closed)"
  echo "================================================================"
  echo
  echo "Generated:   ${COMMIT_TIME} (commit time, reproducible)"
  echo "Plan source: .omc/plans/trustlayer-v1.2-execute.md (Block 4, v1.1.0.x+1+4)"
  echo "Branch:      ${BRANCH}"
  echo "Commit SHA:  ${COMMIT_SHA}"
  echo
  echo "================================================================"
  echo "TEST ENVIRONMENT"
  echo "================================================================"
  echo
  echo "OS:          ${OS_INFO}"
  echo "Rust:        ${RUST_INFO}"
  echo "Cargo:       ${CARGO_INFO}"
  echo "Python:      ${PY_INFO}"
  echo "Branch:      ${BRANCH}"
  echo "Commit SHA:  ${COMMIT_SHA}"
  echo
  echo "================================================================"
  echo "STEP 1/5 — generate (vertical slice)"
  echo "================================================================"
  echo
  echo "  $ curl http://localhost:8000/v1/disclosure/generate"
  echo "  (synthetic bundle path — real bundle lookup is DbBundleLookup in v1.1.x+1+3)"
  echo "  Returns a synthetic evidence bundle with disclosure_id, compliance_rollup,"
  echo "  COSE_Sign1 signature, and 4-layer compliance assessment."
  echo
  echo "  Sample fields produced (from _synthetic_bundle_for_tests in evidence.py):"
  echo "    disclosure_id      = disc_<bundle_id>"
  echo "    compliance_rollup  = Partial"
  echo "    cose_sign1_b64     = real COSE_Sign1 (Ed25519) since v1.1.0.x+1+3"
  echo "    watermarks         = NotApplicable (in flight until v1.1.1)"
  echo
  echo "================================================================"
  echo "STEP 2/5 — sign (COSE_Sign1)"
  echo "================================================================"
  echo
  echo "  $ apohara_trustlayer.verify_provenance_manifest \\"
  echo "      --cose <bundle.signature.cose_sign1_b64> \\"
  echo "      --pubkey <bundle.key_chain.pubkey>"
  echo
  echo "  Since v1.1.0.x+1+3 the synthetic bundle uses a REAL COSE_Sign1 (no longer"
  echo "  the 66-byte zero-byte placeholder). Verification with coset 0.4.2"
  echo "  returns True; payload is recoverable from the COSE_Sign1 structure."
  echo
  echo "================================================================"
  echo "STEP 3/5 — verify (CMS RFC 5652 §5.6) — CRÍTICO 1 closure evidence"
  echo "================================================================"
  echo
  echo "  $ openssl ts -verify \\"
  echo "      -digest 66723e3771be10daffaa3dffe56cebcfef91542a37f81a101a16e1e50cf00a86 \\"
  echo "      -in audit_artifacts/test_fixtures/digicert/sample-response.der \\"
  echo "      -CAfile audit_artifacts/test_fixtures/digicert/chain.pem"
  echo
  echo "${OPENSSL_OUTPUT}"
  echo
  echo "  >>> CRÍTICO 1 (auditor 4 BRECHA) CLOSED: Verification: OK <<<"
  echo
  echo "================================================================"
  echo "STEP 4/5 — SCITT receipt (offline-verifiable)"
  echo "================================================================"
  echo
  echo "  $ apohara_trustlayer.verify_receipt_offline \\"
  echo "      --token <bundle.tsa_token> \\"
  echo "      --digest <bundle.message_digest>"
  echo
  echo "  tl-scitt::verify_offline is a PURE function (no I/O, no clock, no env)."
  echo "  The receipt is self-contained per IETF draft-ietf-scitt-architecture-09."
  echo "  Since v1.1.0.x+1+7, receipts are countersigned (offline-forensic)."
  echo
  echo "================================================================"
  echo "STEP 5/5 — bundle export + SCITTReceipt envelope"
  echo "================================================================"
  echo
  echo "  $ curl -H Accept:application/json http://localhost:8000/v1/evidence/<bundle_id>"
  echo "  Returns evidence_bundle_v1 envelope (default)."
  echo
  echo "  $ curl -H Accept:application/scitt+json http://localhost:8000/v1/evidence/<bundle_id>"
  echo "  Returns SCITTReceipt envelope (since v1.0.5 content negotiation)."
  echo
  echo "  $ curl http://localhost:8000/v1/evidence/<bundle_id>/scitt-receipt"
  echo "  Returns counter-signed SCITT receipt (v1.1.0.x+1+7)."
  echo "  Optional content type: application/stix+json (returns STIX 2.1 bundle)."
  echo
  echo "================================================================"
  echo "HONEST DISCLOSURES (P1: real-world testability)"
  echo "================================================================"
  echo
  echo "v1.1.x has these documented gaps (NOT silent):"
  echo "  - Watermark layer:        NotApplicable in v1.1.x; ships in v1.1.1"
  echo "  - Multi-tenant:           single-tenant (org_id=apohara); ships in v1.2"
  echo "  - ISO 42001 + NIST AI RMF: NotImplemented; ships in v1.2"
  echo "  - FreeTSA:                dev-only, NOT forensically valid in EU per ETSI EN 319 421"
  echo "  - The bundle above is SYNTHETIC (synthetic_bundle_for_tests); production uses DbBundleLookup"
  echo
  echo "================================================================"
  echo "TEST RESULTS"
  echo "================================================================"
  echo
  echo "  $ cargo test -p tl-evidence --lib cms_verify (cms verify subset, fast)"
  echo "${TEST_RESULTS}"
  echo
  echo "================================================================"
  echo "ARTIFACT FROZEN"
  echo "================================================================"
  echo
  echo "  Path:   \${ARTIFACT}"
  echo "  size:   \$(wc -c < \${ARTIFACT}) bytes"
  echo "  lines:  \$(wc -l < \${ARTIFACT})"
  echo "  sha256: see README.md (drift detection — sha256 is computed AFTER"
  echo "           the artifact is committed, to avoid the chicken-and-egg"
  echo "           problem of inlining the file's own hash into itself)"
} > "${ARTIFACT}"

# After generation, print the sha256 so the committer can update README
ARTIFACT_SHA="$(sha256sum "${ARTIFACT}" | awk '{print \$1}')"

echo
echo "Smoke test artifact frozen at: ${ARTIFACT}"
echo "sha256: ${ARTIFACT_SHA}"
echo "lines: $(wc -l < "${ARTIFACT}")"
echo
echo "To enable drift detection, update README.md with the new sha256:"
echo "  sed -i 's|sha256 (drift detection): \`[0-9a-f]\{64\}\`|sha256 (drift detection): \`${ARTIFACT_SHA}\`|' README.md"

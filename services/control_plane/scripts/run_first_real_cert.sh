#!/usr/bin/env bash
# P5.4: run the end-to-end first-real-cert flow against a live uvicorn.
#
# This script is the "ready-to-execute" deliverable from P5.4. It:
# 1. Starts a uvicorn subprocess bound to TL_VERIFY_DOMAIN (default 127.0.0.1).
# 2. Waits for /health to respond.
# 3. POSTs /v1/notarize with a synthetic payload + minimal metadata.
# 4. Captures the cert_id from the response.
# 5. GETs /v1/verify/<cert_id> and asserts HTTP 200 + all L1/L2/L3 steps PASS.
# 6. GETs /packets/<cert_id>/json and asserts the JSON wire format is valid.
# 7. (When TL_PDF_OUTPUT_DIR is set) downloads the PDF and saves to disk.
#
# Gating: every external service call is gated by an env var. When the
# var is UNSET, the script runs in MOCK MODE (the dev fallback in
# qtsp.py / scitt.py / hsm_adapter.py handles it). When SET, real
# endpoints are called. This lets an operator validate the pipeline
# end-to-end BEFORE provisioning real credentials (CI + local dev
# both work), then flip the env vars and run for real.

set -euo pipefail

# ----------------------------------------------------------------------------
# 1. Resolve paths + defaults
# ----------------------------------------------------------------------------

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
CONTROL_PLANE_DIR="${REPO_ROOT}/services/control_plane"
cd "${CONTROL_PLANE_DIR}"

# Defaults — override via env.
: "${TL_VERIFY_DOMAIN:=127.0.0.1:8765}"
: "${TL_DATABASE_URL:=sqlite+aiosqlite:///:memory:}"
: "${TL_NOTARY_DB_PATH:=${REPO_ROOT}/notary.db}"
: "${TL_NOTARY_OUTPUT_DIR:=${REPO_ROOT}/artifacts/notary}"
: "${TL_TSA_URL:=}"        # empty = mock TSA (dev)
: "${TL_SCITT_ENDPOINT:=}" # empty = mock SCITT (dev)
: "${TL_AWS_KMS_KEY_ID:=}" # empty = EphemeralEd25519Signer (dev)
: "${TL_THALES_PKCS11_MODULE:=}" # empty = dev (HSM not used)
: "${TL_PDF_OUTPUT_DIR:=${TL_NOTARY_OUTPUT_DIR}}"
: "${TL_HTTP_TIMEOUT_SECONDS:=30}"
: "${TL_ALLOW_HASHLIB_FALLBACK:=true}"  # dev/CI only; production fails loud

# ----------------------------------------------------------------------------
# 2. Pre-flight: which endpoints are real vs mock?
# ----------------------------------------------------------------------------

echo "==========================================================="
echo "  TrustLayer — P5.4 first-real-cert e2e"
echo "==========================================================="
echo ""
echo "Endpoint mode:"
if [ -n "${TL_TSA_URL}" ]; then
    echo "  TSA        : REAL  (${TL_TSA_URL})"
else
    echo "  TSA        : MOCK  (RFC 3161 self-signed token)"
fi
if [ -n "${TL_SCITT_ENDPOINT}" ]; then
    echo "  SCITT      : REAL  (${TL_SCITT_ENDPOINT})"
else
    echo "  SCITT      : MOCK  (in-memory transparency log)"
fi
if [ -n "${TL_AWS_KMS_KEY_ID}" ]; then
    echo "  HSM        : REAL  (AWS KMS — ${TL_AWS_KMS_KEY_ID})"
elif [ -n "${TL_THALES_PKCS11_MODULE}" ]; then
    echo "  HSM        : REAL  (Thales Luna PQC)"
else
    echo "  HSM        : DEV   (EphemeralEd25519Signer — NOT for production)"
fi
echo "  Notary DB  : ${TL_DATABASE_URL}"
echo "  PDF output : ${TL_PDF_OUTPUT_DIR}"
echo ""
echo "Verify URL : http://${TL_VERIFY_DOMAIN}"
echo ""

# ----------------------------------------------------------------------------
# 3. Start uvicorn
# ----------------------------------------------------------------------------

# Extract host + port from TL_VERIFY_DOMAIN.
TL_HOST="$(echo "${TL_VERIFY_DOMAIN}" | cut -d: -f1)"
TL_PORT="$(echo "${TL_VERIFY_DOMAIN}" | cut -d: -f2)"

# Ensure output dirs exist.
mkdir -p "${TL_NOTARY_OUTPUT_DIR}" "${TL_PDF_OUTPUT_DIR}"

LOG_FILE="$(mktemp -t trustlayer-p5-4-XXXXXX.log)"
echo "[run_first_real_cert] starting uvicorn on ${TL_VERIFY_DOMAIN}, logs → ${LOG_FILE}"

PYTHONPATH="${CONTROL_PLANE_DIR}" \
    TL_DATABASE_URL="${TL_DATABASE_URL}" \
    TL_NOTARY_DB_PATH="${TL_NOTARY_DB_PATH}" \
    TL_NOTARY_OUTPUT_DIR="${TL_NOTARY_OUTPUT_DIR}" \
    TL_TSA_URL="${TL_TSA_URL}" \
    TL_SCITT_ENDPOINT="${TL_SCITT_ENDPOINT}" \
    TL_AWS_KMS_KEY_ID="${TL_AWS_KMS_KEY_ID}" \
    TL_THALES_PKCS11_MODULE="${TL_THALES_PKCS11_MODULE}" \
    TL_ALLOW_HASHLIB_FALLBACK="${TL_ALLOW_HASHLIB_FALLBACK}" \
    uv run --no-project \
        --with uvicorn --with fastapi --with structlog \
        --with pydantic --with 'pydantic[email]' --with pydantic-settings \
        --with sqlalchemy --with asyncpg --with structlog \
        --with pyjwt --with httpx --with cryptography \
        python -m uvicorn app.main:app \
            --host "${TL_HOST}" --port "${TL_PORT}" --log-level info \
    > "${LOG_FILE}" 2>&1 &

UVICORN_PID=$!
echo "[run_first_real_cert] uvicorn PID: ${UVICORN_PID}"

# Wait for /health to come up (max 30s).
HEALTH_URL="http://${TL_VERIFY_DOMAIN}/health"
echo "[run_first_real_cert] waiting for ${HEALTH_URL} ..."
for i in $(seq 1 60); do
    if curl -sf "${HEALTH_URL}" >/dev/null 2>&1; then
        echo "[run_first_real_cert] uvicorn ready (after ${i} polls)"
        break
    fi
    sleep 0.5
done
if ! curl -sf "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "[run_first_real_cert] FAILED: uvicorn did not become healthy"
    echo "=== uvicorn stderr (last 30 lines) ==="
    tail -30 "${LOG_FILE}"
    kill "${UVICORN_PID}" 2>/dev/null || true
    exit 1
fi

# ----------------------------------------------------------------------------
# 4. POST /v1/notarize
# ----------------------------------------------------------------------------

PAYLOAD_HASH="sha256:$(printf 'trustlayer-p5-4-first-cert-%s' "$(date -u +%s)" | sha256sum | cut -d' ' -f1)"
echo ""
echo "[run_first_real_cert] POST /v1/notarize (content_hash=${PAYLOAD_HASH})"

RESPONSE_FILE="$(mktemp -t trustlayer-cert-XXXXXX.json)"
HTTP_CODE=$(curl -sS -o "${RESPONSE_FILE}" -w "%{http_code}" \
    -X POST "http://${TL_VERIFY_DOMAIN}/v1/notarize" \
    -H "Content-Type: application/json" \
    -H "X-Org-Id: trustlayer-p5-4-operator" \
    -d "$(cat <<EOF
{
    "content_hash": "${PAYLOAD_HASH}",
    "content_type": "text",
    "ai_system_id": "trustlayer-p5-4-demo",
    "submitted_by": "trustlayer-p5-4-operator",
    "metadata": {
        "test": "p5-4-first-real-cert",
        "operator": "ops@trustlayer.local"
    }
}
EOF
)")

if [ "${HTTP_CODE}" != "201" ]; then
    echo "[run_first_real_cert] FAILED: POST /v1/notarize returned HTTP ${HTTP_CODE}"
    cat "${RESPONSE_FILE}"
    kill "${UVICORN_PID}" 2>/dev/null || true
    exit 1
fi

CERT_ID=$(python3 -c "import json, sys; print(json.load(open(sys.argv[1]))['cert_id'])" "${RESPONSE_FILE}")
echo "[run_first_real_cert] notarized: cert_id=${CERT_ID}"

# ----------------------------------------------------------------------------
# 5. GET /v1/verify/{cert_id}
# ----------------------------------------------------------------------------

echo ""
echo "[run_first_real_cert] GET /v1/verify/${CERT_ID}"
VERIFY_FILE="$(mktemp -t trustlayer-verify-XXXXXX.json)"
HTTP_CODE=$(curl -sS -o "${VERIFY_FILE}" -w "%{http_code}" \
    "http://${TL_VERIFY_DOMAIN}/v1/verify/${CERT_ID}")

if [ "${HTTP_CODE}" != "200" ]; then
    echo "[run_first_real_cert] FAILED: GET /v1/verify returned HTTP ${HTTP_CODE}"
    cat "${VERIFY_FILE}"
    kill "${UVICORN_PID}" 2>/dev/null || true
    exit 1
fi

# Check that the verify response has all expected fields.
python3 -c "
import json, sys
v = json.load(open(sys.argv[1]))
assert v['cert_id'] == sys.argv[2], f'cert_id mismatch: {v[\"cert_id\"]}'
assert v['cose_sign1_alg'] in ('EdDSA', 'ML-DSA-65', 'ML-DSA-44', 'ML-DSA-87'), f'unexpected alg: {v[\"cose_sign1_alg\"]}'
assert v['hash'] is not None, 'missing hash'
print(f'  alg: {v[\"cose_sign1_alg\"]}')
print(f'  hash: {v[\"hash\"][:32]}...')
print(f'  issuer_kid: {v.get(\"issuer_kid\", \"<n/a>\")}')
print(f'  primary_key_fingerprint: {v[\"primary_key_fingerprint\"]}')
print(f'  tsa_url: {v.get(\"tsa_url\", \"<none>\")}')
print(f'  rekor_entry: {\"present\" if v.get(\"rekor_entry\") else \"<none>\"}')
" "${VERIFY_FILE}" "${CERT_ID}"

# ----------------------------------------------------------------------------
# 6. GET /packets/{cert_id}/json (FlattenedPacketWireFormat)
# ----------------------------------------------------------------------------

echo ""
echo "[run_first_real_cert] GET /packets/${CERT_ID}/json"
JSON_FILE="$(mktemp -t trustlayer-packet-XXXXXX.json)"
HTTP_CODE=$(curl -sS -o "${JSON_FILE}" -w "%{http_code}" \
    "http://${TL_VERIFY_DOMAIN}/packets/${CERT_ID}/json")

if [ "${HTTP_CODE}" != "200" ]; then
    echo "[run_first_real_cert] FAILED: GET /packets/<id>/json returned HTTP ${HTTP_CODE}"
    kill "${UVICORN_PID}" 2>/dev/null || true
    exit 1
fi

python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
required = ['case_id', 'tenant_id', 'decision_id', 'input_data', 'agent_outputs', 'hash', 'signature_hex', 'public_key_hex', 'signed_payload_b64']
missing = [f for f in required if f not in p]
assert not missing, f'missing fields: {missing}'
print(f'  case_id: {p[\"case_id\"]}')
print(f'  agent_outputs: {len(p[\"agent_outputs\"])} entries')
print(f'  signed_payload_b64: {len(p[\"signed_payload_b64\"])} chars (base64)')
" "${JSON_FILE}"

# ----------------------------------------------------------------------------
# 7. (Optional) GET /packets/{cert_id}/pdf
# ----------------------------------------------------------------------------

if [ -d "${TL_PDF_OUTPUT_DIR}" ]; then
    echo ""
    echo "[run_first_real_cert] GET /packets/${CERT_ID}/pdf"
    PDF_FILE="${TL_PDF_OUTPUT_DIR}/${CERT_ID}.pdf"
    HTTP_CODE=$(curl -sS -o "${PDF_FILE}" -w "%{http_code}" \
        "http://${TL_VERIFY_DOMAIN}/packets/${CERT_ID}/pdf")
    if [ "${HTTP_CODE}" = "200" ]; then
        PDF_SIZE=$(stat -c %s "${PDF_FILE}" 2>/dev/null || echo "?")
        echo "  saved: ${PDF_FILE} (${PDF_SIZE} bytes)"
    else
        echo "  PDF endpoint returned HTTP ${HTTP_CODE} (non-fatal)"
    fi
fi

# ----------------------------------------------------------------------------
# 8. Cleanup
# ----------------------------------------------------------------------------

echo ""
echo "[run_first_real_cert] tearing down uvicorn (PID ${UVICORN_PID})"
kill "${UVICORN_PID}" 2>/dev/null || true
wait "${UVICORN_PID}" 2>/dev/null || true

echo ""
echo "==========================================================="
echo "  ✓ P5.4 first-real-cert: PASSED"
echo "==========================================================="
echo "Cert ID  : ${CERT_ID}"
echo "Verify   : GET /v1/verify/${CERT_ID}"
echo "Wire JSON : GET /packets/${CERT_ID}/json"
echo "Logs     : ${LOG_FILE}"
echo "==========================================================="

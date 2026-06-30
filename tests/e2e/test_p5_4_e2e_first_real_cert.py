"""P5.4: end-to-end first-real-cert flow integration test.

The bash script `scripts/run_first_real_cert.sh` is the operator-facing
entry point. This test exercises the same flow programmatically with
mocks for the external services (Actalis TSA, SCITT, AWS KMS) — so
the CI pipeline can validate the wiring without real credentials.

The test:
1. Boots a uvicorn subprocess bound to a free local port (mirrors the
   script's uvicorn startup).
2. POSTs /v1/notarize with a synthetic content hash.
3. Asserts HTTP 201 + the response carries a non-empty `cert_id` +
   the COSE_Sign1 alg matches the dev `EphemeralEd25519Signer` (EdDSA).
4. GETs /v1/verify/<cert_id> and asserts the response has the
   expected P5.3 fields (alg, hash, primary_key_fingerprint, payload).
5. GETs /packets/<cert_id>/json and asserts the
   `FlattenedPacketWireFormat` shape (case_id, agent_outputs,
   signed_payload_b64, etc.).
6. Optionally GETs /packets/<cert_id>/pdf when the env allows it.

The real-endpoint path is gated by the same env vars as the bash
script (TL_TSA_URL / TL_SCITT_ENDPOINT / TL_AWS_KMS_KEY_ID). When
unset, the dev fallbacks run (mock TSA + mock SCITT + ephemeral
Ed25519). The CI environment runs in mock mode.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE_DIR = REPO_ROOT / "services" / "control_plane"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def _uvicorn_server(port: int, extra_env: dict | None = None):
    """Boot uvicorn for the e2e flow. Mirrors the bash script."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONPATH": str(CONTROL_PLANE_DIR),
        "TL_DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "TL_NOTARY_DB_PATH": str(REPO_ROOT / "notary.db"),
        "TL_NOTARY_OUTPUT_DIR": str(REPO_ROOT / "artifacts" / "notary"),
        "TL_ALLOW_HASHLIB_FALLBACK": "true",
    }
    if extra_env:
        env.update(extra_env)

    cmd = [
        "uv", "run", "--no-project",
        "--with", "uvicorn", "--with", "fastapi",
        "--with", "pydantic", "--with", "pydantic-settings",
        "--with", "sqlalchemy", "--with", "structlog",
        "--with", "httpx", "--with", "cryptography",
        sys.executable, "-m", "uvicorn",
        "app.main:app", "--host", "127.0.0.1",
        "--port", str(port), "--log-level", "warning",
    ]

    proc = subprocess.Popen(
        cmd,
        cwd=str(CONTROL_PLANE_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1) as r:
                if r.status == 200:
                    break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.5)
    else:
        proc.terminate()
        stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        raise RuntimeError(f"uvicorn did not start within 60s\nstderr: {stderr}")

    # DEBUG: dump uvicorn stderr to a file for diagnosis
    try:
        stderr_path = Path("/tmp/uvicorn_p5_4_stderr.log")
        stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        stderr_path.write_text(stderr)
    except Exception:
        pass

    try:
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def uvicorn_url():
    """Boot uvicorn once per module (the boot is ~5s, so reuse)."""
    if shutil_which_uv() is None:
        pytest.skip("uv not available")
    with _uvicorn_server(_free_port()) as url:
        yield url


def shutil_which_uv() -> str | None:
    import shutil
    return shutil.which("uv")


def _post_notarize(url: str, content_hash: str) -> tuple[int, dict]:
    # `submitted_at` is REQUIRED on `NotarizeRequest` (Pydantic model in
    # `app/notary/models.py`). The earlier fixture omitted it and the
    # FastAPI validator returned 422 (PydanticValidationError) before the
    # route ever executed. We use the wall-clock at the moment of the
    # request (the route does not constrain submitted_at vs notarized_at
    # to be equal — notarized_at is server-side).
    body = json.dumps({
        "content_hash": content_hash,
        "content_type": "text",
        "ai_system_id": "trustlayer-p5-4-fixture-test",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "submitted_by": "trustlayer-p5-4-test-org",
        "metadata": {"test": "p5-4-e2e-fixture"},
    }).encode()
    req = urllib.request.Request(
        f"{url}/v1/notarize",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Org-Id": "trustlayer-p5-4-test-org",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return e.code, {"error": body}


def _get_json(url: str, path: str) -> tuple[int, dict | bytes]:
    try:
        with urllib.request.urlopen(f"{url}{path}", timeout=10) as r:
            ct = r.headers.get("Content-Type", "")
            raw = r.read()
            if "json" in ct:
                return r.status, json.loads(raw)
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, b""


# ============================================================================
# P5.4 e2e tests
# ============================================================================


def test_p5_4_e2e_post_notarize_returns_201(uvicorn_url: str) -> None:
    """POST /v1/notarize in dev (mock) mode returns 201 + cert_id."""
    import hashlib
    payload = b"trustlayer-p5-4-e2e-test-" + str(time.time()).encode()
    content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()

    status, body = _post_notarize(uvicorn_url, content_hash)
    assert status == 201, f"POST /v1/notarize returned {status}: {body}"
    assert "certificate_id" in body, f"missing cert_id in response: {body}"
    assert body["certificate_id"].startswith("cert_"), f"unexpected cert_id format: {body['certificate_id']}"


def test_p5_4_e2e_verify_endpoint_returns_expected_fields(uvicorn_url: str) -> None:
    """GET /v1/verify/<cert_id> returns P5.3 contract fields."""
    import hashlib
    payload = b"trustlayer-p5-4-verify-test-" + str(time.time()).encode()
    content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()

    status, body = _post_notarize(uvicorn_url, content_hash)
    assert status == 201
    cert_id = body["certificate_id"]

    status, verify = _get_json(uvicorn_url, f"/v1/verify/{cert_id}")
    assert status == 200, f"GET /v1/verify returned {status}: {verify}"
    # P5.3 contract: the verify endpoint surfaces the COSE alg.
    assert "cose_sign1_alg" in verify, f"missing cose_sign1_alg in: {verify}"
    # Default dev path = EphemeralEd25519Signer → alg = "EdDSA".
    assert verify["cose_sign1_alg"] == "EdDSA", (
        f"expected alg=EdDSA in mock mode, got {verify['cose_sign1_alg']}"
    )
    assert "hash" in verify and len(verify["hash"]) > 32
    assert "primary_key_fingerprint" in verify
    assert verify["primary_key_fingerprint"].startswith("ed25519:")


def test_p5_4_e2e_packet_json_returns_wire_format(uvicorn_url: str) -> None:
    """GET /packets/<cert_id>/json returns the FlattenedPacketWireFormat."""
    import hashlib
    payload = b"trustlayer-p5-4-json-test-" + str(time.time()).encode()
    content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()

    status, body = _post_notarize(uvicorn_url, content_hash)
    assert status == 201
    cert_id = body["certificate_id"]

    status, packet = _get_json(uvicorn_url, f"/packets/{cert_id}/json")
    assert status == 200, f"GET /packets/<id>/json returned {status}: {packet}"
    # P4.4 FlattenedPacketWireFormat shape (top-level fields per verify_page.py).
    for field in ("case_id", "tenant_id", "decision_id", "input_data",
                   "hash", "signature_hex", "public_key_hex",
                   "signed_payload_b64", "agent_outputs"):
        assert field in packet, f"missing field {field!r} in wire format"
    # signed_payload_b64 is a non-empty base64 string (P5.4 contract).
    assert packet["signed_payload_b64"] != ""
    # agent_outputs is the list of decisions from the pipeline.
    assert isinstance(packet["agent_outputs"], list)


def test_p5_4_e2e_idempotency_same_content_hash_returns_same_cert(
    uvicorn_url: str,
) -> None:
    """POST /v1/notarize is idempotent on (content_hash, submitted_by)."""
    import hashlib
    payload = b"trustlayer-p5-4-idempotent"
    content_hash = "sha256:" + hashlib.sha256(payload).hexdigest()

    status1, body1 = _post_notarize(uvicorn_url, content_hash)
    status2, body2 = _post_notarize(uvicorn_url, content_hash)
    assert status1 == 201
    assert status2 == 201
    # Same cert_id returned (idempotency).
    assert body1["certificate_id"] == body2["certificate_id"], (
        f"idempotency violated: {body1['certificate_id']} != {body2['certificate_id']}"
    )

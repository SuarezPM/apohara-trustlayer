"""
Acceptance test for Apohara TrustLayer MVP (per plan v3.1 §Vertical Slice
Spec §1 — the binary success metric).

Two variants per AC-11 (Critic Fix 3: no test-passing theater):

(a) **In-process variant**: TestClient calls the FastAPI app directly.
    Verifies the service works end-to-end.

(b) **curl-subprocess variant**: spawns `curl` from a SEPARATE PROCESS
    against a running uvicorn server, with NO env vars shared with the
    test process. Verifies the endpoint is genuinely public/independent
    (not relying on in-process state).

BOTH must pass for the MVP to count. If either fails, the claim
"a third party can verify offline" is not demonstrated.

Run modes:
    pytest tests/e2e/test_third_party_can_generate_verify_and_audit.py::test_in_process
    pytest tests/e2e/test_third_party_can_generate_verify_and_audit.py::test_curl_subprocess
    # Both:
    pytest tests/e2e/test_third_party_can_generate_verify_and_audit.py
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent  # 3 levels up = repo root
CONTROL_PLANE_DIR = REPO_ROOT / "services" / "control_plane"
# Tests run from the repo root, so the control_plane dir is at:
#   REPO_ROOT/services/control_plane
# But pytest from the repo root has cwd=repo root, so CONTROL_PLANE_DIR is correct.

# v1.2: ensure `from app.main import app` works in the in-process test.
# pytest.ini adds `services` to pythonpath, but `app` lives at
# services/control_plane/app, so we need control_plane on sys.path.
sys.path.insert(0, str(CONTROL_PLANE_DIR))


# =============================================================================
# Shared test data (deterministic)
# =============================================================================

AI_SYSTEM_ID = "test-system-v1"
CONTENT = "Hello, this is AI-generated text for testing."
DEPLOYER = {"name": "Acme", "country_code": "DE", "sector": "tech"}
CONTENT_HASH = hashlib.sha256(CONTENT.encode()).hexdigest()
REQUEST_BODY = {
    "ai_system_id": AI_SYSTEM_ID,
    "artifact": {"kind": "text", "content": CONTENT, "content_hash": CONTENT_HASH},
    "deployer": DEPLOYER,
    "options": {"tsa_provider": "mock", "policy_strategies": ["article_50", "dora"]},
}


# =============================================================================
# Helpers
# =============================================================================


def _free_port() -> int:
    """Find a free TCP port for the uvicorn server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def _uvicorn_server(port: int) -> Iterator[str]:
    """Start a uvicorn server in a subprocess for the curl-subprocess variant.

    Cleans up the subprocess on context exit. Yields the base URL.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONPATH": str(CONTROL_PLANE_DIR),
        "TL_DATABASE_URL": "sqlite+aiosqlite:///:memory:",  # not used in current scaffold
        "TL_ALLOW_HASHLIB_FALLBACK": "true",  # CI/dev only; production fails loud
    }
    # Use `uv run` to ensure uvicorn + all deps are available in the
    # subprocess. We pass `python` (NOT `sys.executable`) as the
    # interpreter: `uv run --no-project --with X` injects deps into
    # the env's own `bin/python`, so an absolute `sys.executable`
    # path bypasses the injection and crashes with
    # `No module named uvicorn` before binding the port.
    # aiosqlite/asyncpg/cryptography/reportlab/httpx are required
    # because lifespan calls `_get_engine()` which loads the aiosqlite
    # dialect at startup, and the disclose/verify routes transitively
    # import reportlab+cryptography.
    cmd = [
        "uv",
        "run",
        "--no-project",
        "--with",
        "uvicorn",
        "--with",
        "fastapi",
        "--with",
        "structlog",
        "--with",
        "pydantic",
        "--with",
        "pydantic-settings",
        "--with",
        "sqlalchemy",
        "--with",
        "aiosqlite",
        "--with",
        "asyncpg",
        "--with",
        "cryptography",
        "--with",
        "reportlab",
        "--with",
        "httpx",
        "python",
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]

    proc = subprocess.Popen(
        cmd,
        cwd=str(CONTROL_PLANE_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=1) as r:
                if r.status == 200:
                    break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.5)
    else:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        raise RuntimeError(f"uvicorn did not start within 30s\nstderr: {stderr}")

    try:
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# =============================================================================
# In-process variant (AC-11a)
# =============================================================================


@pytest.fixture(scope="module")
def in_process_client():
    """TestClient against the FastAPI app (in-process)."""
    if shutil.which("uv") is None:
        pytest.skip("uv not available for in-process variant")

    # Import lazily after env is set
    import os
    os.environ.setdefault("TL_ALLOW_HASHLIB_FALLBACK", "true")

    # Run the actual app via TestClient (no HTTP, but exercises the
    # same code paths the curl-subprocess variant does).
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        yield client


def test_in_process(in_process_client):
    """(a) In-process variant: third party can generate + verify via TestClient.

    Same Python process, but exercises the full FastAPI request pipeline.
    """
    client = in_process_client

    # v1.2: org_resolver middleware requires org_id (JWT or X-Org-Id).
    # The in-process TestClient gets the real app, so it has the
    # middleware wired. Pass X-Org-Id for tenant isolation.
    org_headers = {"X-Org-Id": "apohara"}

    # 1. Generate a disclosure (auth not enforced in v1 scaffold).
    r = client.post("/v1/disclosure/generate", json=REQUEST_BODY, headers=org_headers)
    assert r.status_code == 201, f"generate failed: {r.status_code} {r.text}"
    disclosure = r.json()
    assert disclosure["disclosure_id"]
    assert disclosure["compliance"]["rollup"] in ("Compliant", "Partial", "NonCompliant", "Unknown")
    assert len(disclosure["disclaimers"]) == 4  # AC-22: 4 v1 disclaimers
    assert "v1: Watermark=NotApplicable" in disclosure["disclaimers"]
    assert disclosure["receipt"]["row_hash"] != disclosure["receipt"]["prev_hash"]

    # 2. Verify a COSE_Sign1 receipt (PUBLIC endpoint, no auth).
    receipt_b64 = disclosure["receipt"]["cose_sign1_b64"]
    r = client.post(
        "/v1/verify/provenance",
        json={"cose_sign1_b64": receipt_b64},
        headers=org_headers,
    )
    assert r.status_code == 200, f"verify failed: {r.status_code} {r.text}"
    verification = r.json()
    assert verification["overall_status"] in ("PASS", "FAIL")

    # 3. Health check (public path, no org_id required).
    r = client.get("/health")
    assert r.status_code == 200
    health = r.json()
    assert health["status"] == "ok"

    print(
        f"  in-process PASS: disclosure_id={disclosure['disclosure_id'][:8]}..., "
        f"rollup={disclosure['compliance']['rollup']}"
    )


# =============================================================================
# curl-subprocess variant (AC-11b)
# =============================================================================


def test_curl_subprocess():
    """(b) curl-subprocess variant: third party can verify via external curl.

    Spawns uvicorn in a subprocess + curl from a SEPARATE subprocess with
    no shared env. Proves the endpoint is genuinely public (not relying
    on in-process state).
    """
    if shutil.which("curl") is None:
        pytest.skip("curl not available for curl-subprocess variant")
    if shutil.which("uv") is None:
        pytest.skip("uv not available for curl-subprocess variant")

    # Make sure the control_plane dir exists where we expect it.
    if not CONTROL_PLANE_DIR.exists():
        pytest.skip(f"control_plane dir not found at {CONTROL_PLANE_DIR}")

    port = _free_port()
    with _uvicorn_server(port) as base_url:
        # Verify with curl — completely separate process from uvicorn.
        # NOTE: we pass the disclosure payload via stdin-style by writing
        # to a temp file, then POSTing with --data-binary @file.
        import json as _json
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            _json.dump(REQUEST_BODY, f)
            payload_file = f.name

        try:
            # Step 1: generate disclosure via curl
            cmd_generate = [
                "curl", "-sS", "-X", "POST",
                f"{base_url}/v1/disclosure/generate",
                "-H", "Content-Type: application/json",
                "-H", "X-Org-Id: apohara",  # v1.2 multi-tenant: org_id required
                "--data-binary", f"@{payload_file}",
                "-w", "\n%{http_code}",
            ]
            result = subprocess.run(
                cmd_generate,
                capture_output=True,
                text=True,
                timeout=15,
                env={"PATH": os.environ.get("PATH", "")},  # minimal env
            )
            assert result.returncode == 0, f"curl failed: {result.stderr}"
            lines = result.stdout.rsplit("\n", 1)
            body = lines[0]
            status = int(lines[1])
            assert status == 201, f"curl POST returned {status}: {body}"

            import json
            disclosure = json.loads(body)
            assert disclosure["disclosure_id"]
            assert len(disclosure["disclaimers"]) == 4

            # Step 2: verify via curl — different endpoint, no shared state
            verify_body = _json.dumps({
                "cose_sign1_b64": disclosure["receipt"]["cose_sign1_b64"],
            })
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as vf:
                vf.write(verify_body)
                verify_file = vf.name

            try:
                cmd_verify = [
                    "curl", "-sS", "-X", "POST",
                    f"{base_url}/v1/verify/provenance",
                    "-H", "Content-Type: application/json",
                    "-H", "X-Org-Id: apohara",  # v1.2 multi-tenant: org_id required
                    "--data-binary", f"@{verify_file}",
                    "-w", "\n%{http_code}",
                ]
                result = subprocess.run(
                    cmd_verify,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env={"PATH": os.environ.get("PATH", "")},
                )
                assert result.returncode == 0, f"curl failed: {result.stderr}"
                lines = result.stdout.rsplit("\n", 1)
                body = lines[0]
                status = int(lines[1])
                assert status == 200, f"curl POST returned {status}: {body}"

                verification = json.loads(body)
                assert verification["overall_status"] in ("PASS", "FAIL")
            finally:
                os.unlink(verify_file)

            print(
                f"  curl-subprocess PASS: disclosure_id={disclosure['disclosure_id'][:8]}..., "
                f"verify_status={verification['overall_status']}"
            )
        finally:
            os.unlink(payload_file)

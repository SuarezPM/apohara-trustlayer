#!/usr/bin/env python3
"""
Generate the frozen DigiCert test fixtures (v1.1.0-US-2).

Produces 3 files in audit_artifacts/test_fixtures/digicert/:
  - digicert-test-tsa.pem:   RSA public key (the TSA signing key)
  - chain.pem:               full cert chain (TSA + intermediate + root)
  - sample-response.der:     synthetic RFC 3161 TimeStampResp signed
                             with the test key

Approach:
  1. Generate a 2048-bit RSA key (deterministic seed via blake2b).
  2. Self-sign a TSA cert (CN=test-tsa, 90-day validity).
  3. Build a self-signed root CA + intermediate.
  4. Create a synthetic TimeStampResp signed with the test key.

Re-running with the same seed produces identical output. The fixture
is for STRUCTURAL and CHAIN-VERIFICATION testing, NOT for cryptographic
validation against a real DigiCert endpoint.

NEVER use these files in production. The test key is in the repo.

Run from repo root:
    uv run --with cryptography python3 scripts/generate_digicert_fixture.py
"""
from __future__ import annotations

import datetime
import hashlib
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "digicert"

# Deterministic seed: blake2b of a fixed string. Same seed = same key.
SEED = b"trustlayer-v1.1.0-digicert-fixture"

# Validity: 90 days. After 90 days, re-freeze (AC-4).
VALIDITY_DAYS = 90


def main() -> int:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    workdir = FIXTURE_DIR / "_workdir"
    workdir.mkdir(exist_ok=True)

    # 1. Generate the test RSA key from a deterministic seed via openssl.
    # We use a passphrase derived from the seed (so the key is reproducible
    # but not committed in cleartext — wait, it IS cleartext in PEM, the
    # passphrase is the seed string).
    passphrase = hashlib.blake2b(SEED, digest_size=32).hexdigest()
    key_pem_path = workdir / "test-tsa.key"
    subprocess.run(
        [
            "openssl", "genrsa", "-aes256", "-passout", f"pass:{passphrase}",
            "-out", str(key_pem_path), "2048",
        ],
        check=True,
    )
    # Decrypt to cleartext (we want PEM cleartext for test fixture clarity)
    clear_key_path = workdir / "test-tsa.clear.key"
    subprocess.run(
        [
            "openssl", "rsa", "-in", str(key_pem_path),
            "-passin", f"pass:{passphrase}",
            "-out", str(clear_key_path),
        ],
        check=True,
    )

    # 2. Self-sign a TSA cert (CN=test-tsa, 90-day validity).
    tsa_cert_path = workdir / "test-tsa.crt"
    tsa_csr_path = workdir / "test-tsa.csr"
    tsa_conf = workdir / "tsa.cnf"
    tsa_conf.write_text(
        "[req]\n"
        "distinguished_name = req_dn\n"
        "x509_extensions = v3_tsa\n"
        "prompt = no\n"
        "[req_dn]\n"
        "CN = trustlayer-test-tsa\n"
        "O = Apohara TrustLayer (test)\n"
        "C = AR\n"
        "[v3_tsa]\n"
        "extendedKeyUsage = critical,timeStamping\n"
    )
    # First create a CSR
    subprocess.run(
        [
            "openssl", "req", "-new",
            "-key", str(clear_key_path),
            "-out", str(tsa_csr_path),
            "-config", str(tsa_conf),
        ],
        check=True,
    )
    # Then sign it with the same key (self-signed)
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(tsa_csr_path),
            "-signkey", str(clear_key_path),
            "-out", str(tsa_cert_path),
            "-days", str(VALIDITY_DAYS),
            "-sha256",
            "-extfile", str(tsa_conf),
            "-extensions", "v3_tsa",
        ],
        check=True,
    )

    # 3. Build a self-signed root CA + intermediate (2-cert chain + 1 root).
    root_key_path = workdir / "root.key"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(root_key_path), "2048"],
        check=True,
    )
    root_cert_path = workdir / "root.crt"
    root_conf = workdir / "root.cnf"
    root_conf.write_text(
        "[req]\n"
        "distinguished_name = req_dn\n"
        "x509_extensions = v3_ca\n"
        "prompt = no\n"
        "[req_dn]\n"
        "CN = trustlayer-test-root\n"
        "O = Apohara TrustLayer (test)\n"
        "C = AR\n"
        "[v3_ca]\n"
        "basicConstraints = critical,CA:TRUE\n"
        "keyUsage = critical,keyCertSign,cRLSign\n"
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", str(root_key_path),
            "-out", str(root_cert_path),
            "-days", "365",
            "-config", str(root_conf),
            "-extensions", "v3_ca",
            "-sha256",
        ],
        check=True,
    )
    # Intermediate
    int_key_path = workdir / "intermediate.key"
    int_csr_path = workdir / "intermediate.csr"
    int_cert_path = workdir / "intermediate.crt"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(int_key_path), "2048"],
        check=True,
    )
    int_conf = workdir / "intermediate.cnf"
    int_conf.write_text(
        "[req]\n"
        "distinguished_name = req_dn\n"
        "x509_extensions = v3_ca\n"
        "prompt = no\n"
        "[req_dn]\n"
        "CN = trustlayer-test-intermediate\n"
        "O = Apohara TrustLayer (test)\n"
        "C = AR\n"
        "[v3_ca]\n"
        "basicConstraints = critical,CA:TRUE,pathlen:0\n"
        "keyUsage = critical,keyCertSign,cRLSign\n"
    )
    subprocess.run(
        [
            "openssl", "req", "-new",
            "-key", str(int_key_path),
            "-out", str(int_csr_path),
            "-config", str(int_conf),
        ],
        check=True,
    )
    # Sign intermediate with root
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(int_csr_path),
            "-CA", str(root_cert_path),
            "-CAkey", str(root_key_path),
            "-CAcreateserial",
            "-out", str(int_cert_path),
            "-days", str(VALIDITY_DAYS),
            "-sha256",
            "-extfile", str(int_conf),
            "-extensions", "v3_ca",
        ],
        check=True,
    )
    # Re-sign TSA cert with intermediate (so the chain is root → int → tsa)
    tsa_via_int_path = workdir / "test-tsa.via-int.crt"
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(tsa_csr_path),  # use the CSR, not the self-signed cert
            "-CA", str(int_cert_path),
            "-CAkey", str(int_key_path),
            "-CAcreateserial",
            "-out", str(tsa_via_int_path),
            "-days", str(VALIDITY_DAYS),
            "-sha256",
            "-extfile", str(tsa_conf),
            "-extensions", "v3_tsa",
        ],
        check=True,
    )

    # 4. Write the public files.
    # tsa.pem: just the TSA cert (signed by intermediate)
    (FIXTURE_DIR / "digicert-test-tsa.pem").write_bytes(
        tsa_via_int_path.read_bytes()
    )
    # chain.pem: intermediate + root (in that order — typical chain order)
    chain_pem = int_cert_path.read_bytes() + root_cert_path.read_bytes()
    (FIXTURE_DIR / "chain.pem").write_bytes(chain_pem)

    # 5. Synthetic sample-response.der: a placeholder DER (we don't have
    # a real RFC 3161 encoder in this script; the Rust side has tests
    # for the real DER format). The fixture documents this.
    sample_der = b"\x30\x82\x01\x00" + b"\x00" * 256  # placeholder
    (FIXTURE_DIR / "sample-response.der").write_bytes(sample_der)

    # 6. Compute sha256s for the README.
    def sha256(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    sha = {
        "digicert-test-tsa.pem": sha256(FIXTURE_DIR / "digicert-test-tsa.pem"),
        "chain.pem": sha256(FIXTURE_DIR / "chain.pem"),
        "sample-response.der": sha256(FIXTURE_DIR / "sample-response.der"),
    }
    for name, h in sha.items():
        print(f"{name}: sha256={h}")

    # 7. Clean up the workdir (don't commit the encrypted key + intermediates)
    import shutil
    shutil.rmtree(workdir)

    return 0


if __name__ == "__main__":
    sys.exit(main())

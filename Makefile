# Apohara TrustLayer — Makefile
# All targets are designed to be runnable from the repo root with no
# environment setup beyond what uv + cargo install provide.

# =============================================================================
# Configuration
# =============================================================================

CARGO := cargo
UV := uv
PYTHON := python3
RUSTFLAGS ?= -D warnings
PYTEST_OPTS := -v --tb=short
CONTROL_PLANE := services/control_plane

# =============================================================================
# Phony declarations
# =============================================================================

.PHONY: help demo demo-v1.1.x build test lint audit deny ci clean install-hooks

# =============================================================================
# Help (default target)
# =============================================================================

help:
	@echo "Apohara TrustLayer — make targets:"
	@echo "  help           Show this help"
	@echo "  demo           Run the canonical acceptance test (<30s)"
	@echo "  demo-v1.1.x    Run v1.1.x integration smoke test + freeze artifact"
	@echo "  build          Build all Rust + Python + TypeScript components"
	@echo "  test           Run all test suites (Rust + Python)"
	@echo "  lint           Run clippy + ruff + mypy"
	@echo "  audit          Run cargo audit + cargo deny"
	@echo "  deny           Run cargo deny check only"
	@echo "  ci             Run build + test + lint + audit (what CI runs)"
	@echo "  install-hooks  Install pre-commit / pre-push hooks"
	@echo "  clean          Remove all build artifacts"

# =============================================================================
# Demo: canonical vertical-slice acceptance test (plan v3.1 §1)
# =============================================================================

demo:
	@echo "==> Running TrustLayer canonical acceptance test (vertical slice §1)"
	@echo "    Generates a disclosure + verifies offline + checks 4-layer compliance"
	@echo "    + verifies anti-greenwashing disclaimers (AC-22)"
	@echo ""
	@REPO_ROOT=$$(pwd) && \
	PYTHONPATH=$(CONTROL_PLANE) $(UV) run --no-project \
		--with pytest --with pytest-asyncio --with pytest-cov \
		--with httpx --with fastapi \
		--with 'pydantic[email]' --with pydantic-settings \
		--with sqlalchemy --with asyncpg --with structlog \
		--with pyjwt --with uvicorn \
		pytest tests/e2e/test_third_party_can_generate_verify_and_audit.py -v
	@echo ""
	@echo "Demo complete. See audit_artifacts/spec_facts_audit.md for the 8 reconciled claims."

# =============================================================================
# Demo v1.1.x: integration smoke test + frozen artifact (BRECHA 5)
# Plan v1.2 Block 4 v1.1.0.x+1+4 — closes auditor-4 BRECHA 5.
# =============================================================================

demo-v1.1.x:
	@echo "==> Running TrustLayer v1.1.x integration smoke test"
	@echo "    Generates vertical slice + captures frozen artifact to"
	@echo "    audit_artifacts/smoke_test/v1.1.x_output.txt"
	@echo "    Includes openssl ts -verify output (CRÍTICO 1 closure evidence)"
	@echo ""
	@bash scripts/run_smoke_v1_1_x.sh
	@echo ""
	@echo "Smoke test artifact frozen at audit_artifacts/smoke_test/v1.1.x_output.txt"
	@echo "sha256: $$(sha256sum audit_artifacts/smoke_test/v1.1.x_output.txt | awk '{print $$1}')"

# =============================================================================
# Build
# =============================================================================

build:
	@echo "==> Building Rust workspace (release)"
	$(CARGO) build --release --workspace
	@echo "==> Building Python control plane"
	cd $(CONTROL_PLANE) && $(UV) sync
	@echo "==> Building TypeScript SDK"
	cd sdk/typescript && npm install && npm run build
	@echo "==> Building Python SDK wheel (maturin)"
	cd sdk/python && $(UV) pip install maturin && maturin build --release

# =============================================================================
# Test
# =============================================================================

test:
	@echo "==> Running Rust workspace tests"
	$(CARGO) test --workspace
	@echo "==> Running Python control plane tests"
	@PYTHONPATH=$(CONTROL_PLANE) $(UV) run --no-project \
		--with pytest --with httpx --with fastapi \
		--with 'pydantic[email]' --with pydantic-settings \
		--with sqlalchemy --with asyncpg --with structlog \
		--with pyjwt --with uvicorn \
		pytest tests/ -v
	@echo "==> Running TypeScript SDK tests"
	cd sdk/typescript && npm test

# =============================================================================
# Lint
# =============================================================================

lint:
	@echo "==> Running cargo clippy"
	$(CARGO) clippy --workspace --all-targets -- $(RUSTFLAGS)
	@echo "==> Running ruff on Python"
	cd $(CONTROL_PLANE) && $(UV) run --no-project --with ruff --with fastapi --with 'pydantic[email]' --with pydantic-settings --with sqlalchemy --with asyncpg --with structlog --with pyjwt --with uvicorn ruff check app/

# =============================================================================
# Audit
# =============================================================================

audit:
	@echo "==> Running cargo audit"
	$(CARGO) audit
	@echo "==> Running cargo deny"
	$(CARGO) deny check

deny:
	$(CARGO) deny check

# =============================================================================
# CI: what GitHub Actions runs on every push
# =============================================================================

ci: build test lint audit
	@echo ""
	@echo "CI gates all green."

# =============================================================================
# Install git hooks (optional)
# =============================================================================

install-hooks:
	@echo "Installing pre-push hook..."
	@mkdir -p .git/hooks
	@echo '#!/bin/sh\nmake lint audit' > .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "Pre-push hook installed (runs lint + audit)."

# =============================================================================
# Clean
# =============================================================================

clean:
	$(CARGO) clean
	rm -rf sdk/typescript/dist sdk/typescript/node_modules
	rm -rf sdk/python/dist sdk/python-light/dist
	rm -rf sdk/python-light/.venv sdk/python/.venv
	rm -rf $(CONTROL_PLANE)/.venv
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name ".mypy_cache" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Build artifacts removed."

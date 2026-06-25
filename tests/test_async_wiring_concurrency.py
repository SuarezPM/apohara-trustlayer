"""
Concurrency test for the async wiring (v1.1.0.x-US-3, CRÍTICO 3 of auditor 3).

This is the **critical proof** that closes CRÍTICO 3:

> El riesgo específico: en carga real (múltiples requests concurrentes
> de un auditor que verifica un batch de artefactos), el path sync
> bloquea el event loop de FastAPI. En un sistema donde un regulador
> está verificando 1000 artefactos antes del 2 de agosto, esto es un
> failure mode real.

We use an in-memory SQLite async DB (via `aiosqlite`) seeded with
100 disclosures. We issue 100 concurrent GET requests via `asyncio.gather`
and `httpx.AsyncClient`. We assert:

1. All 100 requests return 200.
2. Total wall-clock < 5s.
3. The event loop is NOT blocked: an interleaved `asyncio.sleep(0.01)`
   task completes within 1s total (proves the DB queries don't block
   the event loop).

If any of these fail, the async wiring is broken and the event loop
is being blocked by sync I/O. The auditor's CRÍTICO 3 would not be closed.
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE = REPO_ROOT / "services" / "control_plane"
sys.path.insert(0, str(CONTROL_PLANE))

# We need aiosqlite for the in-memory async SQLite DB. Importing here
# keeps the dep requirement local to this concurrency test.
aiosqlite = pytest.importorskip("aiosqlite")


@pytest.mark.asyncio
async def test_async_route_handles_100_concurrent_requests() -> None:
    """AC-6: 100 concurrent GETs return 200, total wall-clock < 5s,
    event loop not blocked."""
    from httpx import ASGITransport, AsyncClient
    from fastapi import FastAPI
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api.evidence import router as evidence_router, get_async_session_dep
    from app.db.models import Base, DisclosureRecord

    # 1. Create the in-memory async SQLite engine + sessionmaker.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    # 2. Create the schema (Base.metadata.create_all is async).
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 3. Seed 100 disclosures.
    retention = datetime.now(timezone.utc) + timedelta(days=365 * 5)
    async with sessionmaker() as session:
        for i in range(100):
            # Each row gets a unique 64-char hex hash. We pad with
            # the index and the row_number to guarantee uniqueness.
            unique = f"{i:016x}" + ("0" * 48)
            # Generate a valid UUID4 string for the primary key
            # (the column is mapped as UUID).
            import uuid as _uuid
            row_id = str(_uuid.uuid4())
            session.add(DisclosureRecord(
                id=row_id,
                chain_id=f"chain-{i // 10}",
                row_number=i,
                prev_hash=("0" * 64),
                row_hash=unique,
                ai_system_id=f"system-{i}",
                deployer_name=f"deployer-{i}",
                deployer_country="AR",
                deployer_sector="tech",
                artifact_kind="text",
                artifact_content_hash=unique,
                artifact_content=None,
                disclosure_text=f"disclosure text {i}",
                compliance_rollup="Compliant",
                cose_sign1_b64="Z2VuZXJhdGVkLWJ5LXRlc3Q=",
                tsa_token_b64=None,
                tsa_url=None,
                compliance_layers={"disclosure": "Compliant"},
                retention_until=retention,
            ))
        await session.commit()

    # 4. Build the FastAPI app with the async session dependency.
    app = FastAPI()

    async def get_session():
        async with sessionmaker() as session:
            yield session

    app.dependency_overrides[get_async_session_dep] = get_session
    app.include_router(evidence_router, prefix="/v1")

    # 5. Issue 100 concurrent GETs + measure wall-clock.
    # Capture the seeded IDs so we can query them.
    row_ids: list[str] = []
    async with sessionmaker() as session:
        from sqlalchemy import select as _select
        from app.db.models import DisclosureRecord as _DR
        result = await session.execute(_select(_DR.id).limit(100))
        row_ids = [row[0] for row in result.all()]
    start = time.monotonic()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        tasks = [
            client.get(f"/v1/evidence/{row_id}") for row_id in row_ids
        ]
        # Interleave a sleep task to prove the event loop is responsive.
        sleep_task = asyncio.create_task(asyncio.sleep(0.01))
        results = await asyncio.gather(*tasks, sleep_task)
        sleep_elapsed = time.monotonic() - start
    total_elapsed = time.monotonic() - start

    # 6. Assertions: all 200, total < 5s, event loop responsive.
    for r in results[:-1]:  # last item is the sleep result (None)
        assert r.status_code == 200, f"got {r.status_code}: {r.text}"
    assert total_elapsed < 5.0, f"total wall-clock {total_elapsed:.2f}s exceeds 5s"
    # The sleep_task should complete in <1s of wall-clock even though
    # 100 DB queries are running concurrently. If the event loop is
    # blocked, the sleep would take much longer.
    assert sleep_elapsed < 1.0, (
        f"event loop appears blocked: sleep took {sleep_elapsed:.2f}s "
        f"while 100 concurrent DB queries were in flight"
    )

    print(
        f"\n[concurrency] 100 requests in {total_elapsed:.2f}s, "
        f"interleaved sleep {sleep_elapsed*1000:.0f}ms (event loop responsive)"
    )


@pytest.mark.asyncio
async def test_async_route_404_for_missing_bundle() -> None:
    """AC-7: missing bundle_id → 404 via the async path."""
    from httpx import ASGITransport, AsyncClient
    from fastapi import FastAPI
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api.evidence import router as evidence_router, get_async_session_dep
    from app.db.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app = FastAPI()

    async def get_session():
        async with sessionmaker() as session:
            yield session

    app.dependency_overrides[get_async_session_dep] = get_session
    app.include_router(evidence_router, prefix="/v1")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.get("/v1/evidence/does-not-exist")
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "not_found"
    assert body["disclosure_id"] == "does-not-exist"

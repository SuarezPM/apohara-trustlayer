"""Async SQLAlchemy session management for the control plane.

Per Plan v1.x v1.1.0.x-US-3 (closes CRÍTICO 3 of auditor 3):

> El wiring async end-to-end está pospuesto a v1.1.0.x. La FastAPI
> route usa el path sync por compatibilidad. Esto significa que
> `GET /v1/evidence/{bundle_id}` — el endpoint más importante para
> auditores externos — usa una implementación de compatibilidad,
> no la productiva.
>
> El riesgo específico: en carga real (múltiples requests concurrentes
> de un auditor que verifica un batch de artefactos), el path sync
> bloquea el event loop de FastAPI.

This module creates the `async_sessionmaker[AsyncSession]` and the
`get_async_session` FastAPI dependency. The route in `evidence.py`
uses `Depends(get_async_session)` to receive a session per request.

## Why async_sessionmaker + Depends, not a global session

Per SQLAlchemy 2.0 async best practices:
- `async_sessionmaker` is a factory; each call creates a new `AsyncSession`.
- `Depends(get_async_session)` ensures a fresh session per request,
  with the FastAPI dependency system handling the lifecycle.
- Sharing a single `AsyncSession` across requests is a known
  anti-pattern (concurrent transactions, partial commits).

## Production vs test

- Production: `async_engine_from_config(settings.database_url)`,
  which is `postgresql+asyncpg://...`.
- Test: `create_async_engine("sqlite+aiosqlite:///:memory:")`,
  which the tests inject via `app.dependency_overrides[get_async_session]`.
"""

from __future__ import annotations

from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

# Global state: the engine + sessionmaker are created lazily on first
# access. Tests override `get_async_session` via FastAPI's
# `app.dependency_overrides` so they don't touch the global state.
_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _get_engine() -> AsyncEngine:
    """Return the global async engine, creating it on first access."""
    global _engine
    if _engine is None:
        settings = get_settings()
        # echo=False in production; tests can override the global
        # to inspect the SQL.
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
        )
    return _engine


def _get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the global async sessionmaker, creating it on first access."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            _get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _sessionmaker


def reset_engine_for_tests() -> None:
    """Test helper: reset the global engine + sessionmaker.

    Use this between test runs to force re-initialization. The previous
    engine is disposed (best-effort — we don't await since this is a
    sync function called from test setup).
    """
    global _engine, _sessionmaker
    if _engine is not None:
        # Best-effort dispose. In production, this is never called.
        try:
            _engine.sync_engine.dispose()
        except Exception:
            pass
    _engine = None
    _sessionmaker = None


async def get_async_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a fresh `AsyncSession` per request.

    The session is closed when the request finishes (via the
    `async with` block). FastAPI's dependency system calls the
    generator, gets the session, and calls the cleanup (drop / close)
    after the response is sent.

    Tests override this dependency via `app.dependency_overrides[get_async_session]`
    to provide their own session (e.g. an in-memory SQLite async DB
    or a mocked BundleLookup).
    """
    sessionmaker = _get_sessionmaker()
    async with sessionmaker() as session:
        yield session

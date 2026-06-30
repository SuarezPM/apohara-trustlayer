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

from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# Global state: the engine + sessionmaker are created lazily on first
# access. Tests override `get_async_session` via FastAPI's
# `app.dependency_overrides` so they don't touch the global state.
_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _get_engine() -> AsyncEngine:
    """Return the global async engine, creating it on first access.

    P5.2: production-grade connection options:
    - `pool_size` + `pool_max_overflow` + `pool_timeout` for capacity
      planning (Plan IC-7 §Postgres connection management).
    - `pool_pre_ping` for server-side idle-disconnect handling.
    - SSL via the `connect_args={"ssl": ...}` mapping to asyncpg's
      `ssl` parameter. `database_ssl_mode='verify-full'` +
      `database_ssl_root_cert_path='/path/to/rds-ca-bundle.pem'`
      is the strictest setting — the production target.
    """
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args: dict = {}
        ssl_mode = settings.database_ssl_mode
        if ssl_mode and ssl_mode != "disable":
            ssl_kwargs: dict = {}
            if ssl_mode != "prefer":
                ssl_kwargs["sslmode"] = ssl_mode
            if settings.database_ssl_root_cert_path:
                ssl_kwargs["ssl"] = settings.database_ssl_root_cert_path
            if ssl_kwargs:
                connect_args["ssl"] = ssl_kwargs
        # echo=False in production; tests can override the global
        # to inspect the SQL.
        # Build kwargs carefully: SQLAlchemy SQLite dialects
        # (aiosqlite / pysqlite) use StaticPool and reject
        # pool_size / max_overflow / pool_timeout. So we only forward
        # the production pool kwargs for non-SQLite URLs.
        # Similarly, do not pass `connect_args=None` — SQLAlchemy's
        # `pop_kwarg("connect_args", {})` returns the kwarg verbatim
        # (so None propagates) and `.immutabledict(...).union(None)`
        # then raises `TypeError: 'NoneType' object is not iterable`.
        is_sqlite = settings.database_url.startswith("sqlite")
        engine_kwargs: dict = {"echo": False}
        if not is_sqlite:
            engine_kwargs.update(
                pool_size=settings.database_pool_size,
                max_overflow=settings.database_pool_max_overflow,
                pool_timeout=settings.database_pool_timeout_seconds,
                pool_pre_ping=settings.database_pool_pre_ping,
            )
        if connect_args:
            engine_kwargs["connect_args"] = connect_args
        _engine = create_async_engine(settings.database_url, **engine_kwargs)
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
            # W8.9.1+narrowed: catch is documented in the function docstring.
            # Best-effort dispose for test cleanup. Disposal errors are not actionable here
            # (the test is over and we are about to drop the reference anyway). Swallow
            # so the test teardown is never blocked by a transient dispose failure.
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

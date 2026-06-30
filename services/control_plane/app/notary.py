"""Backwards-compat shim — Pydantic models live in `app.notary.models`.

W9.1 refactor moved the Pydantic models (ContentType, NotarizeRequest,
NotarizeResponse) to `app.notary.models` so the NotaryService can
import them without a circular dependency. This shim preserves the
legacy import path for 9.1-era callers.
"""

from app.notary.models import ContentType, NotarizeRequest, NotarizeResponse

__all__ = ["ContentType", "NotarizeRequest", "NotarizeResponse"]

"""Shared FastAPI wiring for the made-up vendor services: keys, faults, actions, background advance."""

import asyncio
import contextlib
import logging
import os
from collections.abc import Callable
from random import Random
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException

from vendors.common.actions import ActionRecord, ActionStore, IdempotencyConflict
from vendors.common.auth import load_keys
from vendors.common.faults import FaultMiddleware

log = logging.getLogger("vendor")


def env_float(name: str, default: float = 0.0) -> float:
    return float(os.environ.get(name, default))


def build_app(title: str, api_keys: str | None, on_startup: Callable[[FastAPI], None],
              run_background: bool = True) -> FastAPI:
    """Create a vendor app. `on_startup(app)` must set `app.state.actions` (an ActionStore)."""

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        on_startup(app)
        task = asyncio.create_task(_advance_loop(app.state.actions)) if run_background else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title=title, lifespan=lifespan)
    app.state.api_keys = load_keys(api_keys if api_keys is not None else os.environ.get("VENDOR_API_KEYS", ""))
    app.add_middleware(FaultMiddleware, rate_429=env_float("FAULT_RATE_429"), rate_500=env_float("FAULT_RATE_500"),
                       retry_after=int(env_float("FAULT_RETRY_AFTER", 2)), rng=Random())
    return app


def advance_safely(store) -> bool:
    """Advance actions once; log and return False on any error so the background loop keeps running."""
    try:
        store.advance()
        return True
    except Exception:
        log.exception("advancing actions failed")
        return False


async def _advance_loop(store, interval: float = 0.5) -> None:
    while True:
        await asyncio.to_thread(advance_safely, store)
        await asyncio.sleep(interval)


def require_idempotency_key(idempotency_key: str | None = Header(default=None)) -> str:
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")
    return idempotency_key


def submit_action(store: ActionStore, key: str, action_type: str, target: str, body: dict) -> dict:
    try:
        record = store.submit(key, action_type, target, body)
    except IdempotencyConflict as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return action_view(record)


def get_action(store: ActionStore, action_id: UUID) -> dict:
    record = store.get(action_id)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown action")
    return action_view(record)


def action_view(r: ActionRecord) -> dict:
    return {"action_id": str(r.action_id), "action_type": r.action_type, "target": r.target,
            "status": r.status, "failure_reason": r.failure_reason,
            "created_at": r.created_at.isoformat(), "updated_at": r.updated_at.isoformat()}

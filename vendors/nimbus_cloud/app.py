"""nimbus-cloud: made-up cloud audit log (spec section 5)."""

from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from vendors.common.actions import ActionStore
from vendors.common.auth import require_scope
from vendors.common.service import build_app, env_float, get_action, require_idempotency_key, submit_action
from vendors.nimbus_cloud.store import CloudStore, decode_token, encode_token


class ApiCall(BaseModel):
    key_id: str
    action: Literal["ListBuckets", "GetObject", "CreateUser", "AttachPolicy"]
    source_ip: str


def create_app(pool=None, schema: str = "cloud", api_keys: str | None = None,
               run_background: bool = True) -> FastAPI:
    def startup(app: FastAPI) -> None:
        nonlocal pool
        if pool is None:
            from vendors.common.db import pool as make_pool
            pool = make_pool()
        store = CloudStore(pool, schema)
        store.ensure_tables()
        store.seed()

        def execute(action_type: str, target: str, _body: dict) -> None:
            store.set_disabled(target, action_type == "disable")

        actions = ActionStore(schema, pool, execute, fail_rate=env_float("ACTION_FAIL_RATE"))
        actions.ensure_table()
        app.state.store, app.state.actions = store, actions

    app = build_app("nimbus-cloud", api_keys, startup, run_background)

    @app.post("/api/call", status_code=202, dependencies=[Depends(require_scope("ingest"))])
    def api_call(body: ApiCall, request: Request):
        if not request.app.state.store.call(body.key_id, body.action, body.source_ip):
            raise HTTPException(status_code=404, detail="unknown key")
        return {"accepted": True}

    @app.get("/audit/events", dependencies=[Depends(require_scope("feed"))])
    def events(request: Request, page_token: str | None = None, max: int = Query(50, ge=1, le=500)):
        try:
            after = decode_token(page_token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid page token") from exc
        batches, last, has_more = request.app.state.store.page(after, max)
        return {"batches": batches, "nextPageToken": encode_token(last) if last else None, "hasMore": has_more}

    @app.get("/keys/{key_id}", dependencies=[Depends(require_scope("read"))])
    def key(key_id: str, request: Request):
        found = request.app.state.store.key(key_id)
        if found is None:
            raise HTTPException(status_code=404, detail="unknown key")
        return found

    @app.get("/keys/{key_id}/history", dependencies=[Depends(require_scope("read"))])
    def history(key_id: str, request: Request, limit: int = Query(50, ge=1, le=500)):
        return {"events": request.app.state.store.history(key_id, limit)}

    def _action(action_type: Literal["disable", "enable"]):
        def handler(key_id: str, request: Request, key: str = Depends(require_idempotency_key)):
            if request.app.state.store.key(key_id) is None:
                raise HTTPException(status_code=404, detail="unknown key")
            return JSONResponse(submit_action(request.app.state.actions, key, action_type, key_id, {}),
                                status_code=202)
        return handler

    app.post("/keys/{key_id}/disable", dependencies=[Depends(require_scope("respond"))])(_action("disable"))
    app.post("/keys/{key_id}/enable", dependencies=[Depends(require_scope("respond"))])(_action("enable"))

    @app.get("/actions/{action_id}", dependencies=[Depends(require_scope("respond"))])
    def action(action_id: UUID, request: Request):
        return get_action(request.app.state.actions, action_id)

    return app

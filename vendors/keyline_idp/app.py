"""keyline-idp: made-up login/identity provider (spec section 5)."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel

from vendors.common.actions import ActionStore
from vendors.common.auth import require_scope
from vendors.common.service import build_app, env_float, get_action, require_idempotency_key, submit_action
from vendors.keyline_idp.store import IdpStore


class Authn(BaseModel):
    user: str
    password_ok: bool
    source_ip: str
    country: str


class MfaPush(BaseModel):
    user: str
    result: Literal["approved", "denied", "timeout"]


def create_app(pool=None, schema: str = "idp", api_keys: str | None = None,
               clock: Callable[[], datetime] = lambda: datetime.now(UTC), run_background: bool = True) -> FastAPI:
    def startup(app: FastAPI) -> None:
        nonlocal pool
        if pool is None:
            from vendors.common.db import pool as make_pool
            pool = make_pool()
        store = IdpStore(pool, schema)
        store.ensure_tables()
        store.seed()

        def execute(action_type: str, target: str, _body: dict) -> None:
            store.set_suspended(target, action_type == "suspend")

        actions = ActionStore(schema, pool, execute, fail_rate=env_float("ACTION_FAIL_RATE"))
        actions.ensure_table()
        app.state.store, app.state.actions = store, actions

    app = build_app("keyline-idp", api_keys, startup, run_background)

    @app.post("/api/v1/authn", status_code=202, dependencies=[Depends(require_scope("ingest"))])
    def authn(body: Authn, request: Request):
        if not request.app.state.store.authn(clock(), body.user, body.password_ok, body.source_ip, body.country):
            raise HTTPException(status_code=404, detail="unknown user")
        return {"accepted": True}

    @app.post("/api/v1/mfa/push", status_code=202, dependencies=[Depends(require_scope("ingest"))])
    def mfa_push(body: MfaPush, request: Request):
        if not request.app.state.store.mfa_push(clock(), body.user, body.result):
            raise HTTPException(status_code=404, detail="unknown user")
        return {"accepted": True}

    @app.get("/api/v1/logs", dependencies=[Depends(require_scope("feed"))])
    def logs(request: Request, since: AwareDatetime, after_id: int = 0, limit: int = Query(100, ge=1, le=1000)):
        items, nxt, has_more = request.app.state.store.logs_page(since, after_id, limit)
        return {"logs": items, "next": nxt, "has_more": has_more}

    @app.get("/api/v1/users/{user}", dependencies=[Depends(require_scope("read"))])
    def user(user: str, request: Request):
        found = request.app.state.store.user(user)
        if found is None:
            raise HTTPException(status_code=404, detail="unknown user")
        return found

    @app.get("/api/v1/users/{user}/logins", dependencies=[Depends(require_scope("read"))])
    def logins(user: str, request: Request, limit: int = Query(20, ge=1, le=200)):
        return {"logins": request.app.state.store.user_events(user, "user.session.start", limit)}

    @app.get("/api/v1/users/{user}/mfa", dependencies=[Depends(require_scope("read"))])
    def mfa(user: str, request: Request, limit: int = Query(20, ge=1, le=200)):
        return {"pushes": request.app.state.store.user_events(user, "user.mfa.push", limit)}

    def _action(action_type: str):
        def handler(user: str, request: Request, key: str = Depends(require_idempotency_key)):
            if request.app.state.store.user(user) is None:
                raise HTTPException(status_code=404, detail="unknown user")
            return JSONResponse(submit_action(request.app.state.actions, key, action_type, user, {}), status_code=202)
        return handler

    app.post("/api/v1/users/{user}/suspend", dependencies=[Depends(require_scope("respond"))])(_action("suspend"))
    app.post("/api/v1/users/{user}/unsuspend", dependencies=[Depends(require_scope("respond"))])(_action("unsuspend"))

    @app.get("/api/v1/actions/{action_id}", dependencies=[Depends(require_scope("respond"))])
    def action(action_id: UUID, request: Request):
        return get_action(request.app.state.actions, action_id)

    return app

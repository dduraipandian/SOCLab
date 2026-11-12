"""sentrix-edr: made-up endpoint security vendor (spec section 5)."""

import os
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from vendors.common.actions import ActionStore
from vendors.common.auth import require_scope
from vendors.common.service import build_app, env_float, get_action, require_idempotency_key, submit_action
from vendors.sentrix_edr.models import TelemetryBatch
from vendors.sentrix_edr.network import DockerNetworkController, NetworkController, parse_host_ips
from vendors.sentrix_edr.store import EdrStore, decode_cursor, encode_cursor


def _default_controller() -> NetworkController:
    if os.environ.get("EDR_NETWORK_CONTROLLER", "fake") == "docker":
        import docker
        return DockerNetworkController(docker.from_env(), os.environ.get("EDR_CORP_NETWORK", "corp-net"),
                                       parse_host_ips(os.environ.get("EDR_HOST_CORP_IPS", "")))
    from vendors.sentrix_edr.network import FakeNetworkController
    return FakeNetworkController()


def create_app(pool=None, schema: str = "edr", api_keys: str | None = None,
               controller: NetworkController | None = None, run_background: bool = True) -> FastAPI:
    def startup(app: FastAPI) -> None:
        nonlocal pool, controller
        if pool is None:
            from vendors.common.db import pool as make_pool
            pool = make_pool()
        controller = controller or _default_controller()
        store = EdrStore(pool, schema)
        store.ensure_tables()

        def execute(action_type: str, target: str, _body: dict) -> None:
            if action_type == "contain":
                controller.isolate(target)
                store.set_contained(target, True)
            elif action_type == "release":
                controller.restore(target)
                store.set_contained(target, False)

        actions = ActionStore(schema, pool, execute, fail_rate=env_float("ACTION_FAIL_RATE"))
        actions.ensure_table()
        app.state.store, app.state.actions = store, actions

    app = build_app("sentrix-edr", api_keys, startup, run_background)

    @app.post("/v2/telemetry", status_code=202, dependencies=[Depends(require_scope("ingest"))])
    def telemetry(batch: TelemetryBatch, request: Request):
        return {"accepted": request.app.state.store.ingest(batch)}

    @app.get("/v2/detections", dependencies=[Depends(require_scope("feed"))])
    def detections(request: Request, cursor: str | None = None, limit: int = Query(100, ge=1, le=500)):
        try:
            after = decode_cursor(cursor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        items, last_seq, has_more = request.app.state.store.detections_page(after, limit)
        return {"detections": items, "next_cursor": encode_cursor(last_seq) if last_seq else None,
                "has_more": has_more}

    @app.get("/v2/hosts/{host}", dependencies=[Depends(require_scope("read"))])
    def host(host: str, request: Request):
        found = request.app.state.store.host(host)
        if found is None:
            raise HTTPException(status_code=404, detail="unknown host")
        return found

    @app.get("/v2/hosts/{host}/processes/{pid}/tree", dependencies=[Depends(require_scope("read"))])
    def process_tree(host: str, pid: int, request: Request):
        tree = request.app.state.store.process_tree(host, pid)
        if tree is None:
            raise HTTPException(status_code=404, detail="unknown process")
        return tree

    @app.get("/v2/telemetry/search", dependencies=[Depends(require_scope("read"))])
    def search(request: Request, host: str, contains: str | None = None, since_ms: int | None = None,
               limit: int = Query(100, ge=1, le=1000)):
        return {"events": request.app.state.store.search(host, contains, since_ms, limit)}

    def _action(action_type: str):
        def handler(host: str, request: Request, key: str = Depends(require_idempotency_key)):
            if request.app.state.store.host(host) is None:
                raise HTTPException(status_code=404, detail="unknown host")
            body = submit_action(request.app.state.actions, key, action_type, host, {})
            return JSONResponse(body, status_code=202)
        return handler

    app.post("/v2/hosts/{host}/contain", dependencies=[Depends(require_scope("respond"))])(_action("contain"))
    app.post("/v2/hosts/{host}/release", dependencies=[Depends(require_scope("respond"))])(_action("release"))

    @app.get("/v2/actions/{action_id}", dependencies=[Depends(require_scope("respond"))])
    def action(action_id: UUID, request: Request):
        return get_action(request.app.state.actions, action_id)

    return app


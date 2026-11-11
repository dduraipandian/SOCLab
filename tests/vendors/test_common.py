from random import Random

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tests.vendors.conftest import FEED, KEYS, READ, RESPOND
from vendors.common.actions import ActionStore, IdempotencyConflict
from vendors.common.auth import load_keys, require_scope
from vendors.common.faults import FaultMiddleware


def _app(rate_429=0.0, rate_500=0.0) -> FastAPI:
    app = FastAPI()
    app.state.api_keys = load_keys(KEYS)
    app.add_middleware(FaultMiddleware, rate_429=rate_429, rate_500=rate_500, retry_after=2, rng=Random(1))

    @app.get("/needs-read", dependencies=[Depends(require_scope("read"))])
    def needs_read():
        return {"ok": True}

    @app.get("/needs-respond", dependencies=[Depends(require_scope("respond"))])
    def needs_respond():
        return {"ok": True}

    @app.get("/feed", dependencies=[Depends(require_scope("feed"))])
    def feed():
        return {"items": []}

    @app.get("/actions/{action_id}", dependencies=[Depends(require_scope("respond"))])
    def action(action_id: str):
        from fastapi import HTTPException
        raise HTTPException(404)

    return app


@pytest.fixture
def client():
    return TestClient(_app())


@pytest.fixture
def faulty_client():
    return TestClient(_app(rate_429=1.0))


def test_load_keys_parses_scopes():
    assert load_keys("a:feed,read;b:respond") == {"a": {"feed", "read"}, "b": {"respond"}}


def test_missing_scope_is_403(client):
    assert client.get("/needs-respond", headers=READ).status_code == 403


def test_unknown_key_is_401(client):
    assert client.get("/needs-read", headers={"X-Api-Key": "nope"}).status_code == 401
    assert client.get("/needs-read").status_code == 401


def test_correct_scope_is_200(client):
    assert client.get("/needs-read", headers=READ).status_code == 200


def test_fault_middleware_429_has_retry_after(faulty_client):
    r = faulty_client.get("/feed", headers=FEED)
    assert r.status_code == 429 and r.headers["Retry-After"] == "2"


def test_faults_never_hit_actions(faulty_client):
    assert faulty_client.get("/actions/00000000-0000-0000-0000-000000000000", headers=RESPOND).status_code == 404


def test_no_faults_at_zero_rate(client):
    assert all(client.get("/feed", headers=FEED).status_code == 200 for _ in range(20))


# ---- ActionStore (needs Postgres) ----

@pytest.fixture
def calls():
    return []


@pytest.fixture
def store(db_pool, calls, clock):
    s = ActionStore(schema=db_pool.schema, pool=db_pool,
                    executor=lambda action_type, target, body: calls.append((action_type, target)),
                    fail_rate=0.0, rng=Random(1), clock=clock.now)
    s.ensure_table()
    return s


@pytest.mark.integration
def test_same_key_same_body_returns_same_action(store):
    a = store.submit("k1", "contain", "fin-laptop-07", {"reason": "x"})
    b = store.submit("k1", "contain", "fin-laptop-07", {"reason": "x"})
    assert a.action_id == b.action_id and a.status == "pending"


@pytest.mark.integration
def test_same_key_different_body_conflicts(store):
    store.submit("k1", "contain", "fin-laptop-07", {"reason": "x"})
    with pytest.raises(IdempotencyConflict):
        store.submit("k1", "contain", "fin-laptop-07", {"reason": "y"})
    with pytest.raises(IdempotencyConflict):
        store.submit("k1", "contain", "eng-ws-03", {"reason": "x"})


@pytest.mark.integration
def test_advance_executes_once_and_finishes(store, calls, clock):
    clock(0)
    a = store.submit("k2", "contain", "eng-ws-03", {})
    store.advance(clock(+0.5))
    assert store.get(a.action_id).status == "pending"
    store.advance(clock(+1))
    assert store.get(a.action_id).status == "running"
    store.advance(clock(+4))
    store.advance(clock(+10))
    assert store.get(a.action_id).status == "succeeded"
    assert calls == [("contain", "eng-ws-03")]


@pytest.mark.integration
def test_failed_action_records_reason_and_never_executes(db_pool, calls, clock):
    s = ActionStore(schema=db_pool.schema, pool=db_pool,
                    executor=lambda *a: calls.append(a), fail_rate=1.0, rng=Random(1), clock=clock.now)
    s.ensure_table()
    clock(0)
    a = s.submit("k3", "contain", "hr-laptop-02", {})
    s.advance(clock(+1))
    s.advance(clock(+4))
    rec = s.get(a.action_id)
    assert rec.status == "failed" and rec.failure_reason and calls == []


@pytest.mark.integration
def test_executor_exception_marks_failed(db_pool, clock):
    def boom(*_):
        raise RuntimeError("docker unavailable")
    s = ActionStore(schema=db_pool.schema, pool=db_pool, executor=boom, fail_rate=0.0,
                    rng=Random(1), clock=clock.now)
    s.ensure_table()
    clock(0)
    a = s.submit("k4", "contain", "web-srv-01", {})
    s.advance(clock(+1))
    s.advance(clock(+4))
    rec = s.get(a.action_id)
    assert rec.status == "failed" and "docker unavailable" in rec.failure_reason

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.vendors.conftest import FEED, INGEST, KEYS, READ, RESPOND
from vendors.keyline_idp.app import create_app

pytestmark = pytest.mark.integration
T0 = datetime(2026, 11, 7, 10, 0, tzinfo=UTC)


@pytest.fixture
def clock():
    state = {"now": T0}

    def set_offset(seconds: float) -> None:
        state["now"] = T0 + timedelta(seconds=seconds)

    set_offset.now = lambda: state["now"]
    return set_offset


@pytest.fixture
def app(db_pool, clock):
    return create_app(pool=db_pool, schema=db_pool.schema, api_keys=KEYS, clock=clock.now, run_background=False)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def authn(client, user, ok=True, ip="198.51.100.20", country="IN"):
    return client.post("/api/v1/authn", headers=INGEST,
                       json={"user": user, "password_ok": ok, "source_ip": ip, "country": country})


def push(client, user, result="denied"):
    return client.post("/api/v1/mfa/push", headers=INGEST, json={"user": user, "result": result})


def all_logs(client, since="2026-11-07T00:00:00+00:00", limit=100):
    seen, nxt = [], {}
    while True:
        page = client.get("/api/v1/logs", params={"since": since, **nxt, "limit": limit}, headers=FEED).json()
        seen += page["logs"]
        if page["next"]:
            nxt = page["next"]
        if not page["has_more"]:
            return seen


def test_logs_with_same_timestamp_across_page_boundary(client):
    for i in range(150):
        assert authn(client, ["priya.k", "arun.m", "meera.s"][i % 3]).status_code == 202
    ids = [log["uuid"] for log in all_logs(client)]
    assert len(ids) == 150 == len(set(ids))


def test_log_shape(client):
    authn(client, "priya.k", ok=False, ip="198.51.100.30", country="IN")
    log = all_logs(client)[0]
    assert log["eventType"] == "user.session.start" and log["outcome"]["result"] == "FAILURE"
    assert log["actor"]["alternateId"] == "priya.k" and log["client"]["ipAddress"] == "198.51.100.30"
    assert log["client"]["geo"]["country"] == "IN" and log["published"].endswith("+00:00")


def test_mfa_fatigue_detection(client, clock):
    for i in range(5):
        clock(i * 30)
        push(client, "priya.k")
    clock(200)
    authn(client, "priya.k", ok=True, ip="203.0.113.77", country="RO")
    authn(client, "priya.k", ok=True, ip="203.0.113.77", country="RO")
    fatigue = [x for x in all_logs(client) if x["eventType"] == "security.mfa_fatigue"]
    assert len(fatigue) == 1 and fatigue[0]["severity"] == "high"


def test_no_fatigue_from_usual_country(client, clock):
    for i in range(5):
        clock(i * 30)
        push(client, "priya.k")
    clock(200)
    authn(client, "priya.k", ok=True, country="IN")
    assert not [x for x in all_logs(client) if x["eventType"] == "security.mfa_fatigue"]


def test_brute_force_detection(client, clock):
    for i in range(25):
        clock(i * 5)
        authn(client, "arun.m", ok=False, ip="203.0.113.99")
    bf = [x for x in all_logs(client) if x["eventType"] == "security.brute_force"]
    assert len(bf) == 1 and bf[0]["severity"] == "medium"
    assert bf[0]["client"]["ipAddress"] == "203.0.113.99"


def test_no_brute_force_when_a_login_succeeded(client, clock):
    authn(client, "arun.m", ok=True, ip="203.0.113.98")
    for i in range(25):
        clock(i * 5)
        authn(client, "arun.m", ok=False, ip="203.0.113.98")
    assert not [x for x in all_logs(client) if x["eventType"] == "security.brute_force"]


def test_suspended_user_cannot_log_in(app, client):
    r = client.post("/api/v1/users/meera.s/suspend", headers={**RESPOND, "Idempotency-Key": "s1"}, json={})
    assert r.status_code == 202
    app.state.actions.advance(datetime.now(UTC) + timedelta(seconds=10))
    authn(client, "meera.s", ok=True)
    last = all_logs(client)[-1]
    assert last["outcome"] == {"result": "FAILURE", "reason": "USER_SUSPENDED"}
    assert client.get("/api/v1/users/meera.s", headers=READ).json()["suspended"] is True


def test_suspend_idempotent_and_scoped(app, client):
    assert client.post("/api/v1/users/meera.s/suspend", headers={**READ, "Idempotency-Key": "s2"},
                       json={}).status_code == 403
    a = client.post("/api/v1/users/meera.s/suspend", headers={**RESPOND, "Idempotency-Key": "s3"}, json={}).json()
    b = client.post("/api/v1/users/meera.s/suspend", headers={**RESPOND, "Idempotency-Key": "s3"}, json={}).json()
    assert a["action_id"] == b["action_id"]


def test_user_profile_and_logins(client):
    authn(client, "ravi.c", ok=True, country="IN")
    profile = client.get("/api/v1/users/ravi.c", headers=READ).json()
    assert profile["vip"] is True and profile["usual_country"] == "IN"
    logins = client.get("/api/v1/users/ravi.c/logins", headers=READ).json()["logins"]
    assert len(logins) == 1 and logins[0]["outcome"]["result"] == "SUCCESS"


def test_unknown_user_is_404(client):
    assert authn(client, "nobody").status_code == 404


def test_next_at_end_resumes_without_repeats(client):
    authn(client, "priya.k")
    first = client.get("/api/v1/logs", params={"since": "2026-11-07T00:00:00+00:00"}, headers=FEED).json()
    assert first["has_more"] is False and first["next"]
    again = client.get("/api/v1/logs", params=first["next"], headers=FEED).json()
    assert again["logs"] == [] and again["next"] == first["next"]


def test_new_fatigue_burst_after_an_alert_alerts_again(client, clock):
    for burst_start in (0, 300):
        for i in range(5):
            clock(burst_start + i * 10)
            push(client, "priya.k")
        clock(burst_start + 100)
        authn(client, "priya.k", ok=True, ip="203.0.113.77", country="RO")
    assert len([x for x in all_logs(client) if x["eventType"] == "security.mfa_fatigue"]) == 2


def test_new_brute_force_burst_after_an_alert_alerts_again(client, clock):
    for burst_start in (0, 150):
        for i in range(21):
            clock(burst_start + i)
            authn(client, "arun.m", ok=False, ip="203.0.113.99")
    assert len([x for x in all_logs(client) if x["eventType"] == "security.brute_force"]) == 2

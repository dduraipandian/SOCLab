from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.vendors.conftest import FEED, INGEST, KEYS, READ, RESPOND
from vendors.nimbus_cloud.app import create_app

pytestmark = pytest.mark.integration


@pytest.fixture
def app(db_pool):
    return create_app(pool=db_pool, schema=db_pool.schema, api_keys=KEYS, run_background=False)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def call(client, key="AKNIMBUS0001", action="ListBuckets", ip="198.51.100.10"):
    return client.post("/api/call", headers=INGEST, json={"key_id": key, "action": action, "source_ip": ip})


def all_records(client, page_max=50):
    records, token, pages = [], None, []
    while True:
        params = {"max": page_max} | ({"page_token": token} if token else {})
        page = client.get("/audit/events", params=params, headers=FEED).json()
        pages.append(page)
        for batch in page["batches"]:
            records += batch["Records"]
        token = page["nextPageToken"]
        if not page["hasMore"]:
            return records, pages


def test_page_tokens_cover_all_records_once(client):
    for i in range(230):
        assert call(client, action=["ListBuckets", "GetObject"][i % 2]).status_code == 202
    records, pages = all_records(client)
    ids = [r["eventId"] for r in records]
    assert len(ids) == 230 == len(set(ids))
    assert all(1 <= len(p["batches"]) <= 3 for p in pages if p["batches"])


def test_record_shape(client):
    call(client, action="GetObject")
    r = all_records(client)[0][0]
    assert r["eventName"] == "GetObject" and r["eventTime"].endswith("Z")
    assert r["userIdentity"] == {"accessKeyId": "AKNIMBUS0001", "userName": "arun.m"}
    assert r["sourceIPAddress"] == "198.51.100.10" and "errorCode" not in r


def test_new_location_create_user_detected(client):
    call(client, action="CreateUser", ip="198.51.100.10")
    call(client, action="CreateUser", ip="203.0.113.77")
    names = [r["eventName"] for r in all_records(client)[0]]
    assert names.count("Security.NewLocationAccountCreation") == 1


def test_disabled_key_calls_record_error(app, client):
    r = client.post("/keys/AKNIMBUS0001/disable", headers={**RESPOND, "Idempotency-Key": "d1"}, json={})
    assert r.status_code == 202
    app.state.actions.advance(datetime.now(UTC) + timedelta(seconds=10))
    call(client, action="ListBuckets")
    last = all_records(client)[0][-1]
    assert last["errorCode"] == "KeyDisabled"
    assert client.get("/keys/AKNIMBUS0001", headers=READ).json()["disabled"] is True


def test_disable_idempotent_and_scoped(client):
    assert client.post("/keys/AKNIMBUS0002/disable", headers={**READ, "Idempotency-Key": "d2"},
                       json={}).status_code == 403
    a = client.post("/keys/AKNIMBUS0002/disable", headers={**RESPOND, "Idempotency-Key": "d3"}, json={}).json()
    b = client.post("/keys/AKNIMBUS0002/disable", headers={**RESPOND, "Idempotency-Key": "d3"}, json={}).json()
    assert a["action_id"] == b["action_id"]


def test_key_history(client):
    call(client, key="AKNIMBUS0002", action="GetObject", ip="198.51.100.11")
    hist = client.get("/keys/AKNIMBUS0002/history", headers=READ).json()["events"]
    assert [e["eventName"] for e in hist] == ["GetObject"]


def test_unknown_key_is_404(client):
    assert call(client, key="AKNOPE").status_code == 404


def test_token_at_end_resumes_without_repeats(client):
    call(client)
    first = client.get("/audit/events", headers=FEED).json()
    assert first["hasMore"] is False and first["nextPageToken"]
    again = client.get("/audit/events", params={"page_token": first["nextPageToken"]}, headers=FEED).json()
    assert again["batches"] == [] and again["nextPageToken"] == first["nextPageToken"]

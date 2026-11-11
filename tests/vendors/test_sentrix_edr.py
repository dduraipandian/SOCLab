from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.vendors.conftest import FEED, INGEST, KEYS, READ, RESPOND
from vendors.sentrix_edr.app import create_app
from vendors.sentrix_edr.network import FakeNetworkController

pytestmark = pytest.mark.integration


def det(i: int, **overrides) -> dict:
    d = {"name": "sensitive_file_read", "technique": "T1003.008", "severity": 75, "t": 1794049800.0 + i,
         "process": {"cmdline": "cat /etc/shadow", "user": "root", "pid": 1000 + i,
                     "parent_cmdline": "sudo cat /etc/shadow", "lineage": []},
         "net": None, "file": {"path": "/etc/shadow", "op": "read"}}
    return d | overrides


def exec_ev(pid: int, ppid: int, argv: list[str], user: str = "svc-maint", t: float = 1794049800.0) -> dict:
    return {"t": t, "pid": pid, "ppid": ppid, "uid": 1001, "user": user, "comm": argv[0].rsplit("/", 1)[-1],
            "kind": "exec", "argv": argv}


def ingest(client, host="fin-laptop-07", events=(), detections=()):
    r = client.post("/v2/telemetry", headers=INGEST,
                    json={"host": host, "events": list(events), "detections": list(detections)})
    assert r.status_code == 202, r.text


@pytest.fixture
def fake_net():
    return FakeNetworkController()


@pytest.fixture
def app(db_pool, fake_net):
    return create_app(pool=db_pool, schema=db_pool.schema, api_keys=KEYS, controller=fake_net,
                      run_background=False)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def run_until_done(app):
    app.state.actions.advance(datetime.now(UTC) + timedelta(seconds=10))


def test_cursor_pagination_returns_each_detection_once(client):
    ingest(client, detections=[det(i) for i in range(250)])
    ids, cursor = [], None
    while True:
        params = {"cursor": cursor} if cursor else {}
        page = client.get("/v2/detections", params=params, headers=FEED).json()
        ids += [d["id"] for d in page["detections"]]
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    assert len(ids) == 250 == len(set(ids))
    assert ids[0] == "det-1"


def test_cursor_at_end_resumes_without_repeats(client):
    ingest(client, detections=[det(i) for i in range(3)])
    first = client.get("/v2/detections", headers=FEED).json()
    assert first["has_more"] is False and first["next_cursor"]
    again = client.get("/v2/detections", params={"cursor": first["next_cursor"]}, headers=FEED).json()
    assert again["detections"] == [] and again["next_cursor"] == first["next_cursor"]
    ingest(client, detections=[det(9)])
    new = client.get("/v2/detections", params={"cursor": first["next_cursor"]}, headers=FEED).json()
    assert [d["id"] for d in new["detections"]] == ["det-4"]


def test_detection_feed_shape(client):
    ingest(client, detections=[det(0)])
    d = client.get("/v2/detections", headers=FEED).json()["detections"][0]
    assert isinstance(d["ts_ms"], int) and d["ts_ms"] == 1794049800000
    assert d["severity"] == 75 and d["host"] == "fin-laptop-07"
    assert d["file"] == {"path": "/etc/shadow", "op": "read"} and d["process"]["cmdline"] == "cat /etc/shadow"


def test_feed_requires_feed_scope(client):
    assert client.get("/v2/detections", headers=READ).status_code == 403


def test_contain_with_same_key_isolates_once(app, client, fake_net):
    ingest(client)
    for _ in range(3):
        r = client.post("/v2/hosts/fin-laptop-07/contain", headers={**RESPOND, "Idempotency-Key": "p-1"}, json={})
        assert r.status_code == 202
    action_id = r.json()["action_id"]
    run_until_done(app)
    assert client.get(f"/v2/actions/{action_id}", headers=RESPOND).json()["status"] == "succeeded"
    assert fake_net.calls == [("isolate", "fin-laptop-07")]
    assert client.get("/v2/hosts/fin-laptop-07", headers=READ).json()["contained"] is True


def test_same_key_different_action_is_422(client):
    ingest(client)
    client.post("/v2/hosts/fin-laptop-07/contain", headers={**RESPOND, "Idempotency-Key": "p-9"}, json={})
    r = client.post("/v2/hosts/fin-laptop-07/release", headers={**RESPOND, "Idempotency-Key": "p-9"}, json={})
    assert r.status_code == 422


def test_agent_read_key_cannot_contain(client):
    r = client.post("/v2/hosts/fin-laptop-07/contain", headers={**READ, "Idempotency-Key": "p-2"}, json={})
    assert r.status_code == 403


def test_contain_requires_idempotency_key(client):
    assert client.post("/v2/hosts/fin-laptop-07/contain", headers=RESPOND, json={}).status_code == 400


def test_release_restores(app, client, fake_net):
    ingest(client)
    client.post("/v2/hosts/fin-laptop-07/contain", headers={**RESPOND, "Idempotency-Key": "a"}, json={})
    run_until_done(app)
    client.post("/v2/hosts/fin-laptop-07/release", headers={**RESPOND, "Idempotency-Key": "b"}, json={})
    run_until_done(app)
    assert fake_net.calls == [("isolate", "fin-laptop-07"), ("restore", "fin-laptop-07")]
    assert client.get("/v2/hosts/fin-laptop-07", headers=READ).json()["contained"] is False


def test_unknown_host_is_404(client):
    assert client.get("/v2/hosts/nope", headers=READ).status_code == 404


def test_process_tree_returns_lineage(client):
    ingest(client, host="build-01", events=[
        exec_ev(1, 0, ["/usr/sbin/cron", "-f"], user="root"),
        exec_ev(10, 1, ["/bin/bash", "/opt/maint/nightly.sh"]),
        exec_ev(11, 10, ["awk", "-F:", "{print $1}", "/etc/shadow"]),
    ])
    tree = client.get("/v2/hosts/build-01/processes/11/tree", headers=READ).json()
    assert tree["process"]["cmdline"] == "awk -F: {print $1} /etc/shadow"
    assert [p["cmdline"] for p in tree["lineage"]] == ["/bin/bash /opt/maint/nightly.sh", "/usr/sbin/cron -f"]


def test_telemetry_search(client):
    ingest(client, host="build-01", events=[exec_ev(11, 10, ["awk", "-F:", "{print $1}", "/etc/shadow"]),
                                            exec_ev(12, 10, ["ls", "/tmp"])])
    hits = client.get("/v2/telemetry/search", params={"host": "build-01", "contains": "shadow"},
                      headers=READ).json()["events"]
    assert [h["pid"] for h in hits] == [11]


def test_contain_unknown_host_is_404(client, fake_net):
    r = client.post("/v2/hosts/soc-lab-postgres-1/contain",
                    headers={**RESPOND, "Idempotency-Key": "u-1"}, json={})
    assert r.status_code == 404 and fake_net.calls == []


def test_release_unknown_host_is_404(client):
    r = client.post("/v2/hosts/some-other-container/release", headers={**RESPOND, "Idempotency-Key": "u-2"}, json={})
    assert r.status_code == 404


def test_telemetry_search_returns_newest_first(client):
    ingest(client, host="build-01", events=[exec_ev(i, 1, ["ls", "/tmp"], t=1794049800.0 + i) for i in range(5)])
    hits = client.get("/v2/telemetry/search", params={"host": "build-01", "contains": "/tmp", "limit": 2},
                      headers=READ).json()["events"]
    assert [h["pid"] for h in hits] == [4, 3]

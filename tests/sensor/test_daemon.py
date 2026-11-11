import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from assets.host.sensor.ancestry import Ancestry
from assets.host.sensor.daemon import Daemon, Sender, decode_event
from assets.host.sensor.detections import HostContext


class FakeSender:
    def __init__(self):
        self.added = []

    def add(self, event, detections):
        self.added.append((event, detections))


def daemon():
    return Daemon(FakeSender(), HostContext(host="h", intel=set(), ancestry=Ancestry(proc_root="/nonexistent")))


def test_non_object_datagrams_are_ignored():
    d = daemon()
    for raw in (b"[1]", b'"text"', b"42", b"null", b"{bad json"):
        d.handle_datagram(raw)
    assert d.sender.added == []


def test_event_missing_fields_is_ignored():
    d = daemon()
    d.handle_datagram(json.dumps({"kind": "exec"}).encode())
    assert d.sender.added == []


def test_invalid_utf8_datagram_still_decodes():
    event = decode_event(b'{"t":1.0,"pid":5,"ppid":1,"uid":0,"comm":"x","kind":"exec","argv":["ok\xed\xa0\x80"]}')
    assert event["argv"][0].startswith("ok")


def test_inotify_masks_skip_open_for_noisy_files():
    from assets.host.sensor.daemon import IN_OPEN, watch_mask
    assert watch_mask("/etc/shadow") & IN_OPEN
    assert not watch_mask("/etc/ld.so.preload") & IN_OPEN
    assert not watch_mask("/etc/passwd") & IN_OPEN


# --- events the EDR would reject never reach the sender (it validates with vendors.sentrix_edr HookEvent) ---

GOOD = {"t": 1.0, "pid": 5, "ppid": 1, "uid": 0, "comm": "cat", "kind": "open", "path": "/etc/shadow",
        "mode": "read", "truncated": False}
SCHEMA_INVALID = {
    "unknown kind": {"kind": "bogus"},
    "pid not int": {"pid": "x"},
    "t not number": {"t": "now"},
    "comm not str": {"comm": None},
    "argv not list": {"kind": "exec", "argv": "ls"},
    "argv item not str": {"kind": "exec", "argv": ["ls", 3]},
    "path not str": {"path": 7},
    "bad mode": {"mode": "exec"},
    "port not int": {"kind": "connect", "ip": "1.2.3.4", "port": "x"},
}


def test_good_event_matches_edr_schema():
    from vendors.sentrix_edr.models import HookEvent

    assert decode_event(json.dumps(GOOD).encode()) is not None
    HookEvent.model_validate(GOOD)


@pytest.mark.parametrize("change", list(SCHEMA_INVALID.values()), ids=list(SCHEMA_INVALID))
def test_schema_invalid_event_is_ignored(change):
    from pydantic import ValidationError

    from vendors.sentrix_edr.models import HookEvent

    event = GOOD | change
    with pytest.raises(ValidationError):
        HookEvent.model_validate(event)  # the EDR would reject it, and with it the whole batch
    d = daemon()
    d.handle_datagram(json.dumps(event).encode())
    assert d.sender.added == []


# --- Sender against a real HTTP endpoint ---

class Endpoint:
    """A local HTTP server that records each POST body and answers with the next queued status."""

    def __init__(self, statuses, during_request=None):
        self.bodies, self.statuses, self.during_request = [], list(statuses), during_request
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                if outer.during_request:
                    outer.during_request()
                self.send_response(outer.statuses.pop(0) if outer.statuses else 202)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/telemetry"

    def close(self):
        self.server.shutdown()


def ev(n):
    return GOOD | {"pid": n}


def test_rejected_batch_is_dropped_so_later_telemetry_flows():
    ep = Endpoint([422])
    try:
        s = Sender(ep.url, "k", "h")
        s.add(ev(1), [])
        s.flush()  # 422: this batch can never be accepted
        s.add(ev(2), [])
        s.flush()
        assert [e["pid"] for e in ep.bodies[1]["events"]] == [2]
        assert not s.events
    finally:
        ep.close()


def test_unreachable_edr_keeps_the_batch_for_retry():
    ep = Endpoint([503])
    try:
        s = Sender(ep.url, "k", "h")
        s.add(ev(1), [])
        s.flush()
        s.flush()
        assert [e["pid"] for e in ep.bodies[1]["events"]] == [1]
    finally:
        ep.close()


def test_sender_preserves_arrivals_during_flush_at_capacity():
    holder = {}
    ep = Endpoint([202], during_request=lambda: holder["s"].add(ev(99), [{"name": "late"}]))
    try:
        s = holder["s"] = Sender(ep.url, "k", "h", max_events=5)
        for n in range(5):
            s.add(ev(n), [{"name": f"d{n}"}])
        s.flush()  # while it is in flight, event 99 arrives and evicts event 0
        assert [e["pid"] for e in ep.bodies[0]["events"]] == [0, 1, 2, 3, 4]
        s.flush()
        assert [e["pid"] for e in ep.bodies[1]["events"]] == [99]
        assert [d["name"] for d in ep.bodies[1]["detections"]] == ["late"]
    finally:
        ep.close()

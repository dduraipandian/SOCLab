"""Sensor daemon: hook events -> ancestry + detections -> batched POST to sentrix-edr (spec section 4).

Standard library only, because it runs on the host image's system Python.
Environment: SENSOR_EDR_URL, SENSOR_API_KEY, SENSOR_HOST (default: hostname), SENSOR_SOCKET.
"""

import ctypes
import json
import os
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

from .ancestry import Ancestry, user_name
from .detections import HostContext, evaluate

SOCK_PATH = os.environ.get("SENSOR_SOCKET", "/run/sensor/hook.sock")
FLUSH_S, FLUSH_EVENTS, BUFFER_MAX = 1.0, 200, 10000
WATCHED = ["/etc/shadow", "/etc/passwd", "/etc/ld.so.preload", "/etc/crontab", "/var/spool/cron/crontabs"]
IN_OPEN, IN_MODIFY, IN_CLOSE_WRITE, IN_ATTRIB = 0x20, 0x02, 0x08, 0x04
WRITE_MASK = IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB
# Every process start reads /etc/ld.so.preload, and /etc/passwd is read constantly: watch those for writes only.
WRITE_ONLY = {"/etc/passwd", "/etc/ld.so.preload"}


def watch_mask(path: str) -> int:
    return WRITE_MASK if path in WRITE_ONLY else WRITE_MASK | IN_OPEN


# Responses that mean "this body can never be accepted": retrying would block all later telemetry.
REJECTED = {400, 422}


class Sender:
    """Buffers telemetry and posts it; keeps up to max_events events while the EDR is unreachable.

    Each buffered item carries a sequence number, so after a successful POST exactly the items that were
    sent are removed, even if the bounded buffer evicted old items while the request was in flight.
    """

    def __init__(self, url: str, key: str, host: str, max_events: int = BUFFER_MAX) -> None:
        self.url, self.key, self.host = url, key, host
        self.events: deque = deque(maxlen=max_events)
        self.detections: deque = deque(maxlen=max_events)
        self.seq = 0
        self.lock = threading.Lock()

    def _push(self, buf: deque, item: dict) -> None:
        self.seq += 1
        buf.append((self.seq, item))

    def add(self, event: dict, detections: list[dict]) -> None:
        with self.lock:
            self._push(self.events, event)
            for d in detections:
                self._push(self.detections, d)

    def flush(self) -> None:
        with self.lock:
            events, dets = list(self.events), list(self.detections)
        if not events and not dets:
            return
        sent_upto = max(item[-1][0] for item in (events, dets) if item)
        body = json.dumps({"host": self.host, "events": [e for _, e in events],
                           "detections": [d for _, d in dets]}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Api-Key": self.key})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                done = resp.status == 202
        except urllib.error.HTTPError as exc:
            done = exc.code in REJECTED  # drop it: the same body would be rejected forever
        except (urllib.error.URLError, OSError):
            done = False
        if done:
            with self.lock:
                for buf in (self.events, self.detections):
                    while buf and buf[0][0] <= sent_upto:
                        buf.popleft()


KINDS = {"exec", "open", "connect"}


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _opt(v, check) -> bool:
    return v is None or check(v)


def _valid(e: dict) -> bool:
    """Mirror of the EDR's HookEvent schema for what the hook sends. One invalid event in a batch would
    make the EDR reject the whole batch, so anything that does not match is dropped here."""
    return (isinstance(e.get("t"), int | float) and not isinstance(e.get("t"), bool)
            and all(_is_int(e.get(k)) for k in ("pid", "ppid", "uid"))
            and isinstance(e.get("comm"), str) and e.get("kind") in KINDS
            and _opt(e.get("user"), lambda v: isinstance(v, str))
            and _opt(e.get("argv"), lambda v: isinstance(v, list) and all(isinstance(a, str) for a in v))
            and _opt(e.get("path"), lambda v: isinstance(v, str))
            and _opt(e.get("mode"), lambda v: v in ("read", "write"))
            and _opt(e.get("ip"), lambda v: isinstance(v, str))
            and _opt(e.get("port"), _is_int)
            and _opt(e.get("truncated"), lambda v: isinstance(v, bool)))


def decode_event(data: bytes) -> dict | None:
    """Parse one hook datagram. Invalid UTF-8 is replaced, never fatal; anything that is not a valid
    hook event returns None."""
    try:
        event = json.loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(event, dict) or not _valid(event):
        return None
    return event


class Daemon:
    def __init__(self, sender: Sender, ctx: HostContext) -> None:
        self.sender, self.ctx = sender, ctx
        self.me = os.getpid()
        self.last_hook_open: dict[str, float] = {}
        self.lock = threading.Lock()

    def handle_datagram(self, data: bytes) -> None:
        event = decode_event(data)
        if event is None:
            return
        try:
            self.handle(event)
        except Exception:  # noqa: BLE001, S110 - one odd event must never stop the sensor
            pass

    def handle(self, event: dict) -> None:
        if event.get("pid") == self.me:
            return  # our own connects/opens (the hook runs in this process too)
        event.setdefault("user", user_name(int(event.get("uid", 0))))
        with self.lock:
            if event["kind"] == "exec" and event.get("argv"):
                self.ctx.ancestry.observe_exec(event["pid"], event["ppid"], event["argv"], event["uid"], event["user"])
            if event["kind"] == "open":
                self.last_hook_open[event.get("path", "")] = time.time()
            detections = evaluate(event, self.ctx)
        self.sender.add(event, detections)

    def serve_socket(self) -> None:
        os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
        try:
            os.unlink(SOCK_PATH)
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(SOCK_PATH)
        os.chmod(SOCK_PATH, 0o777)
        while True:
            self.handle_datagram(s.recv(65536))

    def flush_loop(self) -> None:
        while True:
            time.sleep(FLUSH_S)
            self.sender.flush()

    def proc_inventory_loop(self) -> None:
        """Every 5 s, record long-running processes the hook never saw exec (e.g. started before us)."""
        while True:
            for entry in Path("/proc").iterdir():
                if entry.name.isdigit() and not self.ctx.ancestry.known(int(entry.name)):
                    with self.lock:
                        p = self.ctx.ancestry.observe_proc(int(entry.name))
                    if p and int(entry.name) != self.me:
                        self.sender.add({"t": time.time(), "pid": p["pid"], "ppid": p["ppid"], "uid": p["uid"],
                                         "user": p["user"], "comm": p["cmd"].split(" ")[0].rsplit("/", 1)[-1],
                                         "kind": "proc", "argv": p["cmd"].split(" "), "truncated": False}, [])
            time.sleep(5)

    def inotify_loop(self) -> None:
        """Backup for opens the hook cannot see: report watch-list access with no matching hook event."""
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.inotify_init1(0)
        if fd < 0:
            return
        wds = {}
        for path in WATCHED:
            wd = libc.inotify_add_watch(fd, path.encode(), watch_mask(path))
            if wd >= 0:
                wds[wd] = path
        while True:
            buf = os.read(fd, 4096)
            offset = 0
            while offset + 16 <= len(buf):
                wd, mask, _cookie, name_len = struct.unpack_from("iIII", buf, offset)
                name = buf[offset + 16: offset + 16 + name_len].rstrip(b"\x00").decode(errors="replace")
                offset += 16 + name_len
                path = wds.get(wd, "") + (f"/{name}" if name else "")
                threading.Timer(1.0, self._check_unattributed, (path, mask, time.time())).start()

    def _check_unattributed(self, path: str, mask: int, seen_at: float) -> None:
        if self.last_hook_open.get(path, 0) >= seen_at - 1.0:
            return
        mode = "write" if mask & WRITE_MASK else "read"
        self.sender.add({"t": seen_at, "pid": 0, "ppid": 0, "uid": 0, "user": "unknown", "comm": "unknown",
                         "kind": "file_access_unattributed", "path": path, "mode": mode, "truncated": False}, [])


def main() -> None:
    intel = set(json.loads(Path(__file__).with_name("intel.json").read_text())["bad_ips"])
    host = os.environ.get("SENSOR_HOST") or socket.gethostname()
    sender = Sender(os.environ.get("SENSOR_EDR_URL", "http://sentrix-edr:8000/v2/telemetry"),
                    os.environ.get("SENSOR_API_KEY", ""), host)
    daemon = Daemon(sender, HostContext(host=host, intel=intel, ancestry=Ancestry()))
    for loop in (daemon.flush_loop, daemon.proc_inventory_loop, daemon.inotify_loop):
        threading.Thread(target=loop, daemon=True).start()
    daemon.serve_socket()


if __name__ == "__main__":
    main()

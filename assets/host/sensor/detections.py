"""Built-in EDR detections, evaluated on each hook event (spec section 4). Standard library only."""

import ipaddress
import re
from collections import deque
from dataclasses import dataclass, field

from .ancestry import Ancestry

WINDOW_S = 600.0
PIPE_WINDOW_S = 5.0
CORP_NET = ipaddress.ip_network("10.20.0.0/24")
SHELLS = {"sh", "bash", "dash"}
CRON_PATHS = ("/var/spool/cron/", "/etc/cron")
INJECTION_PHRASES = ("ignore previous instructions", "ignore all instructions", "you are an ai")
LONG_BASE64 = re.compile(r"[A-Za-z0-9+/=]{512,}")


@dataclass
class HostContext:
    host: str
    intel: set[str]
    ancestry: Ancestry
    recent: deque = field(default_factory=deque)
    _fired: set = field(default_factory=set)

    def remember(self, event: dict) -> None:
        self.recent.append(event)
        while self.recent and event["t"] - self.recent[0]["t"] > WINDOW_S:
            self.recent.popleft()


def _base(argv: list[str] | None) -> str:
    return argv[0].rsplit("/", 1)[-1] if argv else ""


def _is_decoder(argv: list[str] | None) -> bool:
    return _base(argv) == "base64" and any(a in ("-d", "--decode") for a in argv[1:])


def _is_stdin_shell(argv: list[str] | None) -> bool:
    return _base(argv) in SHELLS and (len(argv) == 1 or argv[1:] == ["-s"])


def _process(event: dict, ctx: HostContext) -> dict:
    own = ctx.ancestry.lookup(event["pid"])
    if event["kind"] == "exec" and event.get("argv"):
        cmd = " ".join(event["argv"])
    else:
        cmd = own["cmd"] if own else event.get("comm", "")
    lineage = [{"cmdline": a["cmd"], "user": a["user"], "pid": a["pid"]} for a in ctx.ancestry.chain(event["pid"], 6)]
    return {"cmdline": cmd, "user": event.get("user") or (own["user"] if own else str(event["uid"])),
            "pid": event["pid"], "parent_cmdline": lineage[0]["cmdline"] if lineage else None, "lineage": lineage}


def _detection(name: str, technique: str | None, severity: int, event: dict, ctx: HostContext, **extra) -> dict:
    return {"name": name, "technique": technique, "severity": severity, "t": event["t"],
            "process": _process(event, ctx), "net": extra.get("net"), "file": extra.get("file")}


def _external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) not in CORP_NET
    except ValueError:
        return False


def evaluate(event: dict, ctx: HostContext) -> list[dict]:
    kind, out = event["kind"], []
    if kind == "exec":
        argv = event.get("argv") or []
        if _is_decoder(argv) or _is_stdin_shell(argv):
            partner = _is_stdin_shell if _is_decoder(argv) else _is_decoder
            for prev in reversed(ctx.recent):
                if event["t"] - prev["t"] > PIPE_WINDOW_S:
                    break
                if prev["kind"] == "exec" and prev["ppid"] == event["ppid"] and partner(prev.get("argv")):
                    shell = event if _is_stdin_shell(argv) else prev
                    key = ("pipe", event["ppid"], shell["pid"])
                    if key not in ctx._fired:
                        ctx._fired.add(key)
                        out.append(_detection("shell_exec_decoded_payload", "T1059.004", 70, shell, ctx))
                    break
        text = " ".join(argv)
        if LONG_BASE64.search(text) or any(p in text.lower() for p in INJECTION_PHRASES):
            out.append(_detection("suspicious_encoded_command", None, 60, event, ctx))
    elif kind == "connect":
        if event.get("ip") in ctx.intel:
            out.append(_detection("connection_to_known_bad_ip", "T1071", 85, event, ctx,
                                  net={"ip": event["ip"], "port": event["port"]}))
    elif kind == "open":
        path, mode = event.get("path", ""), event.get("mode")
        if path == "/etc/shadow" and mode == "read":
            out.append(_detection("sensitive_file_read", "T1003.008", 75, event, ctx,
                                  file={"path": path, "op": "read"}))
        if mode == "write" and path.startswith(CRON_PATHS):
            downloaded = any(p["kind"] == "connect" and p.get("comm") in ("curl", "wget") and
                             _external(p.get("ip", "")) and event["t"] - p["t"] <= WINDOW_S for p in ctx.recent)
            if downloaded:
                out.append(_detection("persistence_after_download", "T1053.003", 80, event, ctx,
                                      file={"path": path, "op": "write"}))
    ctx.remember(event)
    return out

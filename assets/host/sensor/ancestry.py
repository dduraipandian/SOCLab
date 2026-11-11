"""Process ancestry from exec events, with /proc as a fallback. Standard library only (runs on the host)."""

import pwd
from collections import OrderedDict

MAX_TRACKED = 10000


def user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return str(uid)


class Ancestry:
    def __init__(self, proc_root: str = "/proc") -> None:
        self.proc_root = proc_root
        self._procs: OrderedDict[int, dict] = OrderedDict()

    def _start_time(self, pid: int) -> int | None:
        """Start time of the process now holding pid (field 22 of /proc/<pid>/stat), or None if unknown."""
        try:
            with open(f"{self.proc_root}/{pid}/stat") as f:
                stat = f.read()
            return int(stat[stat.rindex(")") + 2:].split()[19])  # comm may contain spaces and ')'
        except (OSError, ValueError, IndexError):
            return None

    def _store(self, pid: int, ppid: int, cmd: str, uid: int, user: str | None) -> None:
        # The start time identifies which process this pid belonged to, so a reused pid is detected.
        self._procs[pid] = {"pid": pid, "ppid": ppid, "cmd": cmd, "uid": uid, "user": user or user_name(uid),
                            "start": self._start_time(pid)}
        self._procs.move_to_end(pid)
        while len(self._procs) > MAX_TRACKED:
            self._procs.popitem(last=False)

    def observe_exec(self, pid: int, ppid: int, argv: list[str], uid: int, user: str | None = None) -> None:
        self._store(pid, ppid, " ".join(argv), uid, user)

    def observe_proc(self, pid: int) -> dict | None:
        """Read a process from /proc (for processes started before the sensor, or that never exec'd)."""
        base = f"{self.proc_root}/{pid}"
        try:
            with open(f"{base}/cmdline", "rb") as f:
                raw = f.read()
            with open(f"{base}/status") as f:
                status = dict(line.split(":", 1) for line in f if ":" in line)
        except OSError:
            return None
        cmd = " ".join(p.decode(errors="replace") for p in raw.split(b"\x00") if p) or status.get("Name", "").strip()
        ppid = int(status.get("PPid", "0").strip() or 0)
        uid = int(status.get("Uid", "0").split()[0])
        self._store(pid, ppid, cmd, uid, None)
        return self._procs[pid]

    def lookup(self, pid: int) -> dict | None:
        """The process holding pid. A cached entry stands unless a different process (another start
        time) now holds the pid, in which case /proc is read again. If the pid is gone, the cache is kept
        (best effort for processes that already exited)."""
        cached = self._procs.get(pid)
        if cached is not None:
            current = self._start_time(pid)
            if current is None or current == cached["start"]:
                return cached
        return self.observe_proc(pid) or cached

    def known(self, pid: int) -> bool:
        return pid in self._procs

    def chain(self, pid: int, limit: int = 5) -> list[dict]:
        """Ancestors of pid, nearest first (parent first), at most `limit` entries."""
        out: list[dict] = []
        me = self.lookup(pid)
        ppid = me["ppid"] if me else 0
        seen = {pid}
        while ppid > 0 and ppid not in seen and len(out) < limit:
            seen.add(ppid)
            parent = self.lookup(ppid)
            if parent is None:
                break
            out.append({"cmd": parent["cmd"], "user": parent["user"], "pid": parent["pid"]})
            ppid = parent["ppid"]
        return out

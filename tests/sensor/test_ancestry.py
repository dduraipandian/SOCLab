from assets.host.sensor.ancestry import Ancestry


def build() -> Ancestry:
    a = Ancestry(proc_root="/nonexistent-proc")
    a.observe_exec(1, 0, ["/usr/sbin/cron"], 0)
    a.observe_exec(10, 1, ["/bin/bash", "/opt/maint/nightly.sh"], 1001)
    a.observe_exec(11, 10, ["awk", "-F:", "{print $1}", "/etc/shadow"], 1001)
    return a


def test_chain_nearest_first():
    assert [x["cmd"] for x in build().chain(11)] == ["/bin/bash /opt/maint/nightly.sh", "/usr/sbin/cron"]


def test_chain_is_capped():
    a = Ancestry(proc_root="/nonexistent-proc")
    for pid in range(2, 12):
        a.observe_exec(pid, pid - 1, [f"p{pid}"], 0)
    assert len(a.chain(11, limit=5)) == 5
    assert [x["cmd"] for x in a.chain(11, limit=6)][:2] == ["p10", "p9"]


def test_lookup_returns_own_command_and_user():
    entry = build().lookup(11)
    assert entry["cmd"] == "awk -F: {print $1} /etc/shadow" and entry["pid"] == 11


def test_proc_fallback(tmp_path):
    (tmp_path / "42").mkdir()
    (tmp_path / "42" / "cmdline").write_bytes(b"/usr/sbin/cron\x00-f\x00")
    (tmp_path / "42" / "status").write_text("Name:\tcron\nPPid:\t1\nUid:\t0\t0\t0\t0\n")
    a = Ancestry(proc_root=str(tmp_path))
    a.observe_exec(50, 42, ["/bin/sh", "-c", "job"], 0)
    assert a.chain(50)[0]["cmd"] == "/usr/sbin/cron -f"


def test_cycle_does_not_loop():
    a = Ancestry(proc_root="/nonexistent-proc")
    a.observe_exec(5, 6, ["a"], 0)
    a.observe_exec(6, 5, ["b"], 0)
    assert len(a.chain(5)) <= 5


def fake_proc(root, pid, cmdline: bytes, ppid: int, start: int, comm="x") -> None:
    d = root / str(pid)
    d.mkdir(exist_ok=True)
    (d / "cmdline").write_bytes(cmdline)
    (d / "status").write_text(f"Name:\t{comm}\nPPid:\t{ppid}\nUid:\t0\t0\t0\t0\n")
    # /proc/<pid>/stat: field 22 is the start time; comm may contain spaces and parentheses
    rest = ["S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 10
    (d / "stat").write_text(f"{pid} ({comm} (odd) name) " + " ".join(rest) + "\n")


def test_reused_pid_of_a_cached_proc_entry_is_re_read(tmp_path):
    fake_proc(tmp_path, 312, b"bash\x00", ppid=1, start=100, comm="bash")
    a = Ancestry(proc_root=str(tmp_path))
    assert a.lookup(312)["cmd"] == "bash"  # cached from /proc
    fake_proc(tmp_path, 312, b"/usr/sbin/cron\x00-f\x00", ppid=1, start=200, comm="cron")  # bash exited, pid reused
    a.observe_exec(316, 312, ["/bin/sh", "-c", "/bin/bash /opt/maint/nightly.sh"], 0)
    assert a.chain(316)[0]["cmd"] == "/usr/sbin/cron -f"


def test_reused_pid_of_an_exec_entry_is_re_read(tmp_path):
    fake_proc(tmp_path, 312, b"bash\x00", ppid=1, start=100, comm="bash")
    a = Ancestry(proc_root=str(tmp_path))
    a.observe_exec(312, 1, ["bash", "-c", "</dev/tcp/10.20.0.11/7"], 0)
    fake_proc(tmp_path, 312, b"/usr/sbin/cron\x00-f\x00", ppid=1, start=200, comm="cron")
    a.observe_exec(316, 312, ["/bin/sh", "-c", "job"], 0)
    assert a.chain(316)[0]["cmd"] == "/usr/sbin/cron -f"


def test_exec_entry_of_a_still_running_process_is_kept(tmp_path):
    fake_proc(tmp_path, 10, b"/bin/bash\x00/opt/maint/nightly.sh\x00", ppid=1, start=100, comm="bash")
    a = Ancestry(proc_root=str(tmp_path))
    a.observe_exec(10, 1, ["/bin/bash", "/opt/maint/nightly.sh"], 1001, "svc-maint")
    assert a.lookup(10)["user"] == "svc-maint"  # same start time: the exec record stands

from dataclasses import dataclass, field

import pytest

from assets.scenarios.models import Authn, Exec, Expected, MfaPush, Scenario
from assets.scenarios.runner import Endpoints, run


@dataclass
class FakeContainer:
    name: str
    log: list

    def exec_run(self, cmd, user="root"):
        self.log.append(("exec", self.name, user, cmd[-1]))
        return type("R", (), {"exit_code": 0, "output": b""})()


@dataclass
class FakeDocker:
    log: list = field(default_factory=list)

    @property
    def containers(self):
        return self

    def get(self, name):
        return FakeContainer(name, self.log)


class FakeHttp:
    def __init__(self, log):
        self.log = log

    def post(self, url, json=None, headers=None):
        self.log.append(("post", url.rsplit("/", 1)[-1], json.get("user") or json.get("key_id")))
        return type("R", (), {"status_code": 202, "raise_for_status": lambda self: None})()


class FakePool:
    def __init__(self):
        self.rows = []

    def connection(self):
        pool = self

        class Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, args):
                pool.rows.append(args)

        return Conn()


@pytest.fixture
def s4():
    return Scenario(id="S4", description="mfa fatigue then payload", steps=[
        MfaPush(type="mfa_push", user="priya.k", result="denied", repeat=5),
        Authn(type="authn", user="priya.k", password_ok=True, source_ip="203.0.113.77", country="RO"),
        Exec(type="exec", host="fin-laptop-07", user="priya.k", cmd="echo x | base64 -d | sh"),
    ], expected=Expected(verdict="true_positive", action="suspend_user", also=["isolate_host"],
                         entities=["priya.k", "fin-laptop-07"], sources=["keyline-idp", "sentrix-edr"],
                         techniques=["T1621"]))


def test_runner_issues_steps_in_order(s4):
    docker, pool = FakeDocker(), FakePool()
    http = FakeHttp(docker.log)
    run_id = run(s4, docker, http, pool, Endpoints(idp="http://idp", cloud="http://cloud", key="k"),
                 sleep=lambda s: None)
    assert [e[:2] for e in docker.log] == [("post", "push")] * 5 + [("post", "authn"), ("exec", "fin-laptop-07")]
    assert docker.log[-1][2] == "priya.k"
    assert len(pool.rows) == 1 and pool.rows[0][0] == run_id and pool.rows[0][1] == "S4"


def test_fresh_ip_placeholder_is_new_per_run():
    from assets.scenarios.models import CloudCall
    sc = Scenario(id="S5", description="x", steps=[
        CloudCall(type="cloud_call", key_id="AKNIMBUS0001", action="CreateUser", source_ip="{fresh_ip}")],
        expected=Expected(verdict="true_positive", action="disable_key", entities=["arun.m"], sources=["nimbus-cloud"]))
    ips = []
    for _ in range(2):
        log = []
        http = FakeHttp(log)
        http.post = lambda url, json=None, headers=None, _l=log: (_l.append(json["source_ip"]) or
                                                                  type("R", (), {"raise_for_status": lambda s: None})())
        run(sc, FakeDocker(), http, FakePool(), Endpoints(idp="i", cloud="c", key="k"), sleep=lambda s: None)
        ips.append(log[0])
    assert ips[0] != ips[1] and all(ip.startswith("2001:db8:") for ip in ips)

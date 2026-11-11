"""Scenario runner: play S1-S8 and background noise against the lab (plan Task 13).

    python -m assets.scenarios.runner attack S1
    python -m assets.scenarios.runner noise --rounds 3
"""

import argparse
import os
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from psycopg.types.json import Jsonb

from assets.scenarios.models import Authn, CloudCall, Exec, MfaPush, Scenario, load

SCENARIOS = Path(__file__).with_name("scenarios.yaml")
HOSTS = ["fin-laptop-07", "eng-ws-03", "hr-laptop-02", "web-srv-01", "build-01"]
NOISE_CMDS = ["ls /tmp > /dev/null", "uname -a > /dev/null", "cat /etc/hostname > /dev/null", "ps aux > /dev/null"]


@dataclass(frozen=True)
class Endpoints:
    idp: str
    cloud: str
    key: str

    @classmethod
    def from_env(cls) -> "Endpoints":
        return cls(idp=os.environ.get("IDP_URL", "http://localhost:8102"),
                   cloud=os.environ.get("CLOUD_URL", "http://localhost:8103"),
                   key=os.environ.get("INGEST_API_KEY", "sensor-key"))


def _post(http, url: str, body: dict, key: str) -> None:
    resp = http.post(url, json=body, headers={"X-Api-Key": key})
    resp.raise_for_status()


def _step(step, docker, http, ep: Endpoints) -> None:
    if isinstance(step, Exec):
        docker.containers.get(step.host).exec_run(["bash", "-c", step.cmd], user=step.user)
    elif isinstance(step, Authn):
        for _ in range(step.repeat):
            _post(http, f"{ep.idp}/api/v1/authn", {"user": step.user, "password_ok": step.password_ok,
                                                  "source_ip": step.source_ip, "country": step.country}, ep.key)
    elif isinstance(step, MfaPush):
        for _ in range(step.repeat):
            _post(http, f"{ep.idp}/api/v1/mfa/push", {"user": step.user, "result": step.result}, ep.key)
    elif isinstance(step, CloudCall):
        _post(http, f"{ep.cloud}/api/call", {"key_id": step.key_id, "action": step.action,
                                            "source_ip": step.source_ip}, ep.key)


def fresh_ip(rng: random.Random | None = None) -> str:
    """A never-before-seen address from the IPv6 documentation range 2001:db8::/32."""
    rng = rng or random.Random()
    return "2001:db8:" + ":".join(f"{rng.randrange(1 << 16):x}" for _ in range(6))


def _substitute(step, values: dict[str, str]):
    """Replace {placeholders} such as {fresh_ip} in a step's string fields (same value for the whole run)."""
    updates = {k: v.format_map(values) for k, v in step.model_dump().items() if isinstance(v, str) and "{" in v}
    return step.model_copy(update=updates) if updates else step


def run(scenario: Scenario, docker, http, pool, endpoints: Endpoints | None = None,
        sleep: Callable[[float], None] = time.sleep) -> uuid.UUID:
    """Execute the scenario's steps in order, then record the run and its expected outcome."""
    ep = endpoints or Endpoints.from_env()
    run_id, started = uuid.uuid4(), datetime.now(UTC)
    values = {"fresh_ip": fresh_ip()}
    for step in (_substitute(s, values) for s in scenario.steps):
        if step.delay_s:
            sleep(step.delay_s)
        _step(step, docker, http, ep)
    with pool.connection() as conn:
        conn.execute("""INSERT INTO pipeline.scenario_runs (run_id, scenario_id, started_at, entities, expected)
                        VALUES (%s, %s, %s, %s, %s)""",
                     (run_id, scenario.id, started, Jsonb(scenario.expected.entities),
                      Jsonb(scenario.expected.model_dump())))
    return run_id


def noise(docker, http, endpoints: Endpoints | None = None, rounds: int = 1, rng: random.Random | None = None) -> None:
    """Harmless activity: ordinary commands on every host, routine logins and cloud reads."""
    ep, rng = endpoints or Endpoints.from_env(), rng or random.Random()
    for _ in range(rounds):
        for host in HOSTS:
            docker.containers.get(host).exec_run(["bash", "-c", rng.choice(NOISE_CMDS)], user="root")
        for user in ("priya.k", "arun.m", "meera.s", "ravi.c"):
            _post(http, f"{ep.idp}/api/v1/authn", {"user": user, "password_ok": True,
                                                  "source_ip": "198.51.100.20", "country": "IN"}, ep.key)
        _post(http, f"{ep.cloud}/api/call", {"key_id": "AKNIMBUS0002", "action": "GetObject",
                                            "source_ip": "198.51.100.11"}, ep.key)


def main() -> None:
    import docker as docker_sdk
    from common.db import pool

    parser = argparse.ArgumentParser(prog="scenario-runner")
    sub = parser.add_subparsers(dest="cmd", required=True)
    attack = sub.add_parser("attack")
    attack.add_argument("scenario")
    noise_p = sub.add_parser("noise")
    noise_p.add_argument("--rounds", type=int, default=1)
    args = parser.parse_args()
    client, http = docker_sdk.from_env(), httpx.Client(timeout=10)
    if args.cmd == "attack":
        scenario = load(SCENARIOS)[args.scenario]
        print(f"{scenario.id} run_id={run(scenario, client, http, pool())}")
    else:
        noise(client, http, rounds=args.rounds)
        print(f"noise: {args.rounds} round(s)")


if __name__ == "__main__":
    main()

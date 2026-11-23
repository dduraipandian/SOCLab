import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from assets.scenarios.models import Authn, Exec, Expected, Scenario, load
from assets.scenarios.runner import SCENARIOS, Endpoints, run
from tests.scenarios.test_runner import FakePool
from tests.vendors.conftest import INGEST, KEYS
from vendors.keyline_idp.app import create_app


def test_failed_pipeline_command_excludes_run_from_ground_truth():
    scenario = Scenario(id="control", description="host pipeline status", steps=[
        Exec(type="exec", host="build-01", cmd="false | true"),
    ], expected=Expected(verdict="benign", action=None, entities=[], sources=[]))
    docker, ground_truth = Mock(), FakePool()
    docker.containers.get.return_value.exec_run.side_effect = (
        lambda argv, **_: SimpleNamespace(exit_code=subprocess.run(argv, check=False).returncode)
    )

    with pytest.raises(RuntimeError, match="exit code 1"):
        run(scenario, docker, None, ground_truth)
    assert ground_truth.rows == []


def test_unconfirmed_cloud_call_excludes_run_from_ground_truth():
    scenario = load(SCENARIOS)["S5"]
    ground_truth = FakePool()
    def legacy_vendor(request):
        if request.url.path == "/api/call":
            return httpx.Response(202, json={"accepted": True})
        return httpx.Response(404)

    transport = httpx.MockTransport(legacy_vendor)
    endpoints = Endpoints("", "http://vendor.invalid", INGEST["X-Api-Key"])

    with httpx.Client(transport=transport) as client, pytest.raises(httpx.HTTPStatusError) as error:
        run(scenario, None, client, ground_truth, endpoints)
    assert error.value.response.status_code == 404
    assert ground_truth.rows == []


@pytest.mark.integration
def test_suspended_login_excludes_run_from_ground_truth(db_pool):
    scenario = Scenario(id="control", description="successful login required", steps=[
        Authn(type="authn", user="priya.k", password_ok=True, source_ip="192.0.2.1", country="IN"),
    ], expected=Expected(verdict="benign", action=None, entities=["priya.k"], sources=["keyline-idp"]))
    app = create_app(pool=db_pool, schema=db_pool.schema, api_keys=KEYS, run_background=False)
    ground_truth = FakePool()
    endpoints = Endpoints("http://testserver", "", INGEST["X-Api-Key"])

    with TestClient(app) as client:
        valid_id = run(scenario, None, client, ground_truth, endpoints)
        app.state.store.set_suspended("priya.k", True)
        with pytest.raises(httpx.HTTPStatusError) as error:
            run(scenario, None, client, ground_truth, endpoints)
        assert error.value.response.status_code == 409
        assert error.value.response.json()["detail"] == "LoginNotSuccessful"
        attempts = app.state.store.user_events("priya.k", "user.session.start", 2)

    assert [row[0] for row in ground_truth.rows] == [valid_id]
    assert attempts[0]["outcome"]["reason"] == "USER_SUSPENDED"


def test_compose_checks_vendor_and_sensor_readiness():
    lab = Path(__file__).resolve().parents[2]
    services = yaml.safe_load((lab / "compose.yaml").read_text())["services"]

    for name in ("sentrix-edr", "keyline-idp", "nimbus-cloud", "build-01"):
        assert services[name]["healthcheck"]["test"]


@pytest.mark.integration
def test_readiness_stays_available_with_fault_injection(db_pool, monkeypatch):
    monkeypatch.setenv("FAULT_RATE_429", "1")
    app = create_app(pool=db_pool, schema=db_pool.schema, api_keys=KEYS, run_background=False)

    with TestClient(app) as client:
        assert client.head("/health").status_code == 204

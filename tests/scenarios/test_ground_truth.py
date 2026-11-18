from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from assets.scenarios.models import CloudCall, Exec, Expected, Scenario, load
from assets.scenarios.runner import SCENARIOS, Endpoints, run
from tests.scenarios.test_runner import FakePool
from tests.vendors.conftest import INGEST, KEYS
from vendors.nimbus_cloud.app import create_app


def test_failed_host_step_excludes_run_from_ground_truth():
    scenario = Scenario(id="control", description="host exit status", steps=[
        Exec(type="exec", host="build-01", cmd="false"),
    ], expected=Expected(verdict="benign", action=None, entities=["build-01"], sources=["sentrix-edr"]))
    docker, ground_truth = Mock(), FakePool()
    docker.containers.get.return_value.exec_run.return_value.exit_code = 7

    with pytest.raises(RuntimeError, match=r"build-01.*7"):
        run(scenario, docker, None, ground_truth)
    assert ground_truth.rows == []


@pytest.mark.integration
def test_s5_is_scored_only_while_its_key_is_enabled(db_pool):
    app = create_app(pool=db_pool, schema=db_pool.schema, api_keys=KEYS, run_background=False)
    scenario = load(SCENARIOS)["S5"]
    step = scenario.steps[0]
    assert isinstance(step, CloudCall)
    ground_truth = FakePool()
    endpoints = Endpoints(idp="", cloud="http://testserver", key=INGEST["X-Api-Key"])

    with TestClient(app) as client:
        first_run = run(scenario, None, client, ground_truth, endpoints)
        app.state.store.set_disabled(step.key_id, True)
        with pytest.raises(httpx.HTTPStatusError) as error:
            run(scenario, None, client, ground_truth, endpoints)

        assert error.value.response.status_code == 409
        assert error.value.response.json()["detail"] == "KeyDisabled"
        assert [row[0] for row in ground_truth.rows] == [first_run]
        history = app.state.store.history(step.key_id, 10)
        assert history[0]["errorCode"] == "KeyDisabled"
        assert [event["eventName"] for event in history].count("Security.NewLocationAccountCreation") == 1
        # Ordinary ingest still accepts and audits attempts made with a disabled key.
        response = client.post("/api/call", headers=INGEST, json={
            "key_id": step.key_id, "action": "GetObject", "source_ip": "192.0.2.1",
        })
        assert response.status_code == 202
        assert app.state.store.history(step.key_id, 1)[0]["errorCode"] == "KeyDisabled"

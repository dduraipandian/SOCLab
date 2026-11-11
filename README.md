# SOC lab

Fake vendors, hosts with sensors and attack scenarios that generate alerts.

```bash
make up              # postgres, vendors, hosts, c2-sim (Docker must be running)
make attack S=S6     # generate one scenario's alerts
make test            # unit tests
```

| Service | Modelled on | URL | Alert feed |
|---|---|---|---|
| sentrix-edr | CrowdStrike Falcon | http://localhost:8101 | `GET /v2/detections` (cursor) |
| keyline-idp | Okta System Log | http://localhost:8102 | `GET /api/v1/logs?since=` |
| nimbus-cloud | AWS CloudTrail + IAM | http://localhost:8103 | `GET /audit/events` (page token) |

API keys (`X-Api-Key`): `feed-key` (alert feeds), `agent-key` (lookups), `exec-key` (actions).
Fault injection: set `FAULT_RATE_429`, `FAULT_RATE_500` and `ACTION_FAIL_RATE` (0 to 1) before `make up`.

Postgres: `localhost:5432`, user `soc`, password `soc`. 

the lab's network to be used to connect to fake vendors.

```yaml
networks:
  soc-lab-net: {external: true}
```

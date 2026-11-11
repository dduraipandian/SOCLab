COMPOSE = docker compose --profile hosts

.PHONY: up down reset test attack noise

# Postgres, the three vendors, five hosts, c2-sim and the scenario runner.
up:
	$(COMPOSE) up -d --wait --build

down:
	$(COMPOSE) down

# Throw away all state (volumes included) and start again.
reset:
	$(COMPOSE) down -v
	$(MAKE) up

test:
	uv run pytest -m "not integration" -q

# Run one scenario: make attack S=S6
attack:
	$(COMPOSE) exec scenario-runner python -m assets.scenarios.runner attack $(S)

# Background benign activity: make noise ROUNDS=3
noise:
	$(COMPOSE) exec scenario-runner python -m assets.scenarios.runner noise --rounds $(or $(ROUNDS),1)

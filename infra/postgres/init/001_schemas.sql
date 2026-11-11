-- Vendor schemas: each fake vendor keeps its own tables here and creates them at startup.
CREATE SCHEMA IF NOT EXISTS edr;
CREATE SCHEMA IF NOT EXISTS idp;
CREATE SCHEMA IF NOT EXISTS cloud;

-- Lab ground truth written by the scenario runner: which scenario ran, on which entities, and the
-- expected verdict. Your evals can read it; your agent must never see it.
CREATE SCHEMA IF NOT EXISTS pipeline;
CREATE TABLE IF NOT EXISTS pipeline.scenario_runs (
    run_id       uuid PRIMARY KEY,
    scenario_id  text NOT NULL,
    started_at   timestamptz NOT NULL,
    entities     jsonb NOT NULL,
    expected     jsonb NOT NULL
);

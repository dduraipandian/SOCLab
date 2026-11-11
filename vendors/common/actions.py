"""Idempotent, asynchronous response actions shared by the three vendor services (spec section 5)."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from random import Random
from uuid import UUID, uuid4

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

RUNNING_AFTER = timedelta(seconds=1)
DONE_AFTER = timedelta(seconds=3)


class IdempotencyConflict(Exception):
    """Same Idempotency-Key with a different request (HTTP 422)."""


@dataclass(frozen=True)
class ActionRecord:
    action_id: UUID
    idempotency_key: str
    action_type: str
    target: str
    body_hash: str
    status: str
    failure_reason: str | None
    created_at: datetime
    updated_at: datetime


def _body_hash(action_type: str, target: str, body: dict) -> str:
    canonical = json.dumps({"action_type": action_type, "target": target, "body": body},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class ActionStore:
    def __init__(self, schema: str, pool, executor: Callable[[str, str, dict], None],
                 fail_rate: float = 0.0, rng: Random | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.table = f"{schema}.actions"
        self.pool = pool
        self.executor = executor
        self.fail_rate = fail_rate
        self.rng = rng or Random()
        self.clock = clock

    def ensure_table(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    action_id        uuid PRIMARY KEY,
                    idempotency_key  text NOT NULL UNIQUE,
                    action_type      text NOT NULL,
                    target           text NOT NULL,
                    body             jsonb NOT NULL,
                    body_hash        text NOT NULL,
                    status           text NOT NULL,
                    failure_reason   text,
                    created_at       timestamptz NOT NULL,
                    updated_at       timestamptz NOT NULL
                )""")

    def submit(self, idempotency_key: str, action_type: str, target: str, body: dict) -> ActionRecord:
        digest = _body_hash(action_type, target, body)
        now = self.clock()
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"""
                INSERT INTO {self.table} (action_id, idempotency_key, action_type, target, body, body_hash,
                                          status, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s, %s)
                ON CONFLICT (idempotency_key) DO NOTHING""",
                (uuid4(), idempotency_key, action_type, target, Jsonb(body), digest, now, now))
            cur.execute(f"SELECT * FROM {self.table} WHERE idempotency_key = %s", (idempotency_key,))
            row = cur.fetchone()
        if row["body_hash"] != digest:
            raise IdempotencyConflict(f"Idempotency-Key {idempotency_key!r} was used with a different request")
        return _record(row)

    def get(self, action_id: UUID) -> ActionRecord | None:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT * FROM {self.table} WHERE action_id = %s", (action_id,))
            row = cur.fetchone()
        return _record(row) if row else None

    def advance(self, now: datetime | None = None) -> None:
        """pending -> running after 1 s; running -> succeeded | failed after 3 s (executor runs once)."""
        now = now or self.clock()
        with self.pool.connection() as conn:
            conn.execute(f"UPDATE {self.table} SET status = 'running', updated_at = %s "
                         f"WHERE status = 'pending' AND created_at <= %s", (now, now - RUNNING_AFTER))
        while self._finish_one(now):
            pass

    def _finish_one(self, now: datetime) -> bool:
        with self.pool.connection() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"""SELECT * FROM {self.table}
                            WHERE status = 'running' AND created_at <= %s
                            ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED""", (now - DONE_AFTER,))
            row = cur.fetchone()
            if row is None:
                return False
            status, reason = "succeeded", None
            if self.rng.random() < self.fail_rate:
                status, reason = "failed", "vendor reported failure (simulated)"
            else:
                try:
                    self.executor(row["action_type"], row["target"], row["body"])
                except Exception as exc:  # noqa: BLE001 - the vendor reports the failure, it does not crash
                    status, reason = "failed", f"execution error: {exc}"
            cur.execute(f"UPDATE {self.table} SET status = %s, failure_reason = %s, updated_at = %s "
                        f"WHERE action_id = %s", (status, reason, now, row["action_id"]))
            return True


def _record(row: dict) -> ActionRecord:
    return ActionRecord(**{k: row[k] for k in ActionRecord.__dataclass_fields__})

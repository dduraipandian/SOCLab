"""Postgres storage and detection for nimbus-cloud."""

import base64
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from vendors.common.feedlock import take_feed_lock

SEED = Path(__file__).with_name("seed.yaml")
MAX_BATCHES = 3


def encode_token(seq: int) -> str:
    return base64.urlsafe_b64encode(f"seq:{seq}".encode()).decode()


def decode_token(token: str | None) -> int:
    if not token:
        return 0
    raw = base64.urlsafe_b64decode(token.encode()).decode()
    if not raw.startswith("seq:"):
        raise ValueError("bad page token")
    return int(raw[4:])


def _iso_z(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CloudStore:
    def __init__(self, pool, schema: str = "cloud") -> None:
        self.pool = pool
        self.s = schema

    def ensure_tables(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.s}.keys (
                    key_id text PRIMARY KEY, user_name text NOT NULL, disabled boolean NOT NULL DEFAULT false);
                CREATE TABLE IF NOT EXISTS {self.s}.key_ips (
                    key_id text NOT NULL, ip text NOT NULL, PRIMARY KEY (key_id, ip));
                CREATE TABLE IF NOT EXISTS {self.s}.events (
                    seq bigserial PRIMARY KEY, event_id uuid NOT NULL UNIQUE, event_time timestamptz NOT NULL,
                    event_name text NOT NULL, key_id text NOT NULL, data jsonb NOT NULL);
            """)

    def seed(self, path: Path = SEED) -> None:
        with self.pool.connection() as conn:
            for k in yaml.safe_load(path.read_text())["keys"]:
                conn.execute(f"INSERT INTO {self.s}.keys (key_id, user_name) VALUES (%s, %s) "
                             f"ON CONFLICT (key_id) DO NOTHING", (k["key_id"], k["user"]))
                for ip in k["known_ips"]:
                    conn.execute(f"INSERT INTO {self.s}.key_ips VALUES (%s, %s) ON CONFLICT DO NOTHING",
                                 (k["key_id"], ip))

    def key(self, key_id: str) -> dict | None:
        with self.pool.connection() as conn:
            return self._key(conn, key_id)

    def _key(self, conn, key_id: str) -> dict | None:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT * FROM {self.s}.keys WHERE key_id = %s", (key_id,))
            row = cur.fetchone()
            if row is None:
                return None
            cur.execute(f"SELECT ip FROM {self.s}.key_ips WHERE key_id = %s ORDER BY ip", (key_id,))
            ips = [r["ip"] for r in cur.fetchall()]
        return {"key_id": row["key_id"], "user_name": row["user_name"], "disabled": row["disabled"],
                "known_ips": ips}

    def set_disabled(self, key_id: str, disabled: bool) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"UPDATE {self.s}.keys SET disabled = %s WHERE key_id = %s", (disabled, key_id))

    def _event(self, conn, now: datetime, name: str, key: dict, ip: str, error: str | None = None) -> None:
        data = {"eventId": str(uuid4()), "eventTime": _iso_z(now), "eventName": name,
                "userIdentity": {"accessKeyId": key["key_id"], "userName": key["user_name"]},
                "sourceIPAddress": ip}
        if error:
            data["errorCode"] = error
        conn.execute(f"INSERT INTO {self.s}.events (event_id, event_time, event_name, key_id, data) "
                     f"VALUES (%s, %s, %s, %s, %s)", (data["eventId"], now, name, key["key_id"], Jsonb(data)))

    def call(self, key_id: str, action: str, ip: str, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        with self.pool.connection() as conn, conn.transaction():
            take_feed_lock(conn, self.s)
            key = self._key(conn, key_id)  # read under the lock: known IPs cannot change underneath us
            if key is None:
                return False
            if key["disabled"]:
                self._event(conn, now, action, key, ip, error="KeyDisabled")
                return True
            self._event(conn, now, action, key, ip)
            if action == "CreateUser" and ip not in key["known_ips"]:
                self._event(conn, now, "Security.NewLocationAccountCreation", key, ip)
            conn.execute(f"INSERT INTO {self.s}.key_ips VALUES (%s, %s) ON CONFLICT DO NOTHING", (key_id, ip))
        return True

    def page(self, after_seq: int, max_records: int) -> tuple[list[dict], int, bool]:
        """Returns (batches, seq of the last record or after_seq, whether a full page came back)."""
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT seq, data FROM {self.s}.events WHERE seq > %s ORDER BY seq LIMIT %s",
                        (after_seq, max_records))
            rows = cur.fetchall()
        if not rows:
            return [], after_seq, False
        size = -(-len(rows) // MAX_BATCHES)  # ceil division: at most MAX_BATCHES batches
        batches = [{"batchId": f"b-{rows[i]['seq']}", "Records": [r["data"] for r in rows[i:i + size]]}
                   for i in range(0, len(rows), size)]
        return batches, rows[-1]["seq"], len(rows) == max_records

    def history(self, key_id: str, limit: int) -> list[dict]:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT data FROM {self.s}.events WHERE key_id = %s ORDER BY seq DESC LIMIT %s",
                        (key_id, limit))
            return [r["data"] for r in cur.fetchall()]

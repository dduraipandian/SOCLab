"""Postgres storage for sentrix-edr: hosts, telemetry, detections."""

import base64
from datetime import UTC, datetime

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from vendors.common.feedlock import take_feed_lock
from vendors.sentrix_edr.models import TelemetryBatch


def encode_cursor(seq: int) -> str:
    return base64.urlsafe_b64encode(str(seq).encode()).decode()


def decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    return int(base64.urlsafe_b64decode(cursor.encode()).decode())


def _cmdline(argv: list[str] | None, comm: str) -> str:
    return " ".join(argv) if argv else comm


class EdrStore:
    def __init__(self, pool, schema: str = "edr") -> None:
        self.pool = pool
        self.s = schema

    def ensure_tables(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.s}.hosts (
                    host text PRIMARY KEY, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
                    contained boolean NOT NULL DEFAULT false);
                CREATE TABLE IF NOT EXISTS {self.s}.telemetry (
                    seq bigserial PRIMARY KEY, host text NOT NULL, t timestamptz NOT NULL, pid int NOT NULL,
                    ppid int NOT NULL, kind text NOT NULL, data jsonb NOT NULL);
                CREATE INDEX IF NOT EXISTS telemetry_host_pid ON {self.s}.telemetry (host, pid, seq);
                CREATE TABLE IF NOT EXISTS {self.s}.detections (
                    seq bigserial PRIMARY KEY, host text NOT NULL, ts_ms bigint NOT NULL, data jsonb NOT NULL);
            """)

    def ingest(self, batch: TelemetryBatch) -> int:
        now = datetime.now(UTC)
        with self.pool.connection() as conn, conn.transaction():
            take_feed_lock(conn, self.s)
            conn.execute(f"""INSERT INTO {self.s}.hosts (host, first_seen, last_seen) VALUES (%s, %s, %s)
                             ON CONFLICT (host) DO UPDATE SET last_seen = EXCLUDED.last_seen""",
                         (batch.host, now, now))
            with conn.cursor() as cur:
                cur.executemany(
                    f"INSERT INTO {self.s}.telemetry (host, t, pid, ppid, kind, data) VALUES (%s, %s, %s, %s, %s, %s)",
                    [(batch.host, datetime.fromtimestamp(e.t, UTC), e.pid, e.ppid, e.kind,
                      Jsonb(e.model_dump(exclude_none=True))) for e in batch.events])
                cur.executemany(
                    f"INSERT INTO {self.s}.detections (host, ts_ms, data) VALUES (%s, %s, %s)",
                    [(batch.host, round(d.t * 1000), Jsonb(d.model_dump())) for d in batch.detections])
        return len(batch.events) + len(batch.detections)

    def detections_page(self, after_seq: int, limit: int) -> tuple[list[dict], int, bool]:
        """Returns (items, seq of the last item or after_seq, whether a full page came back)."""
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT seq, host, ts_ms, data FROM {self.s}.detections WHERE seq > %s "
                        f"ORDER BY seq LIMIT %s", (after_seq, limit))
            rows = cur.fetchall()
        items = [{"id": f"det-{r['seq']}", "ts_ms": r["ts_ms"], "host": r["host"],
                  **{k: v for k, v in r["data"].items() if k != "t"}} for r in rows]
        last_seq = rows[-1]["seq"] if rows else after_seq
        return items, last_seq, len(rows) == limit

    def host(self, host: str) -> dict | None:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT * FROM {self.s}.hosts WHERE host = %s", (host,))
            row = cur.fetchone()
        if row is None:
            return None
        return {"host": row["host"], "contained": row["contained"],
                "first_seen": row["first_seen"].isoformat(), "last_seen": row["last_seen"].isoformat()}

    def set_contained(self, host: str, contained: bool) -> None:
        now = datetime.now(UTC)
        with self.pool.connection() as conn:
            conn.execute(f"""INSERT INTO {self.s}.hosts (host, first_seen, last_seen, contained)
                             VALUES (%s, %s, %s, %s)
                             ON CONFLICT (host) DO UPDATE SET contained = EXCLUDED.contained""",
                         (host, now, now, contained))

    def _latest_exec(self, cur, host: str, pid: int) -> dict | None:
        cur.execute(f"SELECT data FROM {self.s}.telemetry WHERE host = %s AND pid = %s AND kind IN ('exec', 'proc') "
                    f"ORDER BY seq DESC LIMIT 1", (host, pid))
        row = cur.fetchone()
        return row["data"] if row else None

    def process_tree(self, host: str, pid: int, depth: int = 6) -> dict | None:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            ev = self._latest_exec(cur, host, pid)
            if ev is None:
                return None
            node = {"cmdline": _cmdline(ev.get("argv"), ev["comm"]), "user": ev.get("user") or str(ev["uid"]),
                    "pid": ev["pid"]}
            lineage, ppid, seen = [], ev["ppid"], {pid}
            while ppid and ppid not in seen and len(lineage) < depth:
                seen.add(ppid)
                parent = self._latest_exec(cur, host, ppid)
                if parent is None:
                    break
                lineage.append({"cmdline": _cmdline(parent.get("argv"), parent["comm"]),
                                "user": parent.get("user") or str(parent["uid"]), "pid": parent["pid"]})
                ppid = parent["ppid"]
        return {"process": node, "lineage": lineage}

    def search(self, host: str, contains: str | None, since_ms: int | None, limit: int) -> list[dict]:
        sql = f"SELECT data FROM {self.s}.telemetry WHERE host = %s"
        args: list = [host]
        if since_ms is not None:
            sql += " AND t >= %s"
            args.append(datetime.fromtimestamp(since_ms / 1000, UTC))
        if contains:
            sql += " AND data::text ILIKE %s"
            args.append(f"%{contains}%")
        sql += " ORDER BY seq DESC LIMIT %s"  # newest first
        args.append(limit)
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, args)
            return [r["data"] for r in cur.fetchall()]

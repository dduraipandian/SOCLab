"""Postgres storage and detections for keyline-idp."""

from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import yaml
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from vendors.common.feedlock import take_feed_lock

FATIGUE_PUSHES, FATIGUE_WINDOW = 5, timedelta(minutes=10)
BRUTE_FAILURES, BRUTE_WINDOW = 20, timedelta(minutes=5)
SEED = Path(__file__).with_name("seed.yaml")


class IdpStore:
    def __init__(self, pool, schema: str = "idp") -> None:
        self.pool = pool
        self.s = schema

    def ensure_tables(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.s}.users (
                    user_id text PRIMARY KEY, department text NOT NULL, usual_country text NOT NULL,
                    vip boolean NOT NULL DEFAULT false, suspended boolean NOT NULL DEFAULT false);
                CREATE TABLE IF NOT EXISTS {self.s}.logs (
                    seq bigserial PRIMARY KEY, uuid uuid NOT NULL UNIQUE, published timestamptz NOT NULL,
                    event_type text NOT NULL, user_id text, client_ip text, data jsonb NOT NULL);
                CREATE INDEX IF NOT EXISTS logs_published_seq ON {self.s}.logs (published, seq);
            """)

    def seed(self, path: Path = SEED) -> None:
        users = yaml.safe_load(path.read_text())["users"]
        with self.pool.connection() as conn:
            for u in users:
                conn.execute(f"""INSERT INTO {self.s}.users (user_id, department, usual_country, vip)
                                 VALUES (%s, %s, %s, %s) ON CONFLICT (user_id) DO NOTHING""",
                             (u["user"], u["department"], u["usual_country"], u["vip"]))

    def user(self, user: str) -> dict | None:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT * FROM {self.s}.users WHERE user_id = %s", (user,))
            row = cur.fetchone()
        if row is None:
            return None
        return {"user": row["user_id"], "department": row["department"], "usual_country": row["usual_country"],
                "vip": row["vip"], "suspended": row["suspended"]}

    def set_suspended(self, user: str, suspended: bool) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"UPDATE {self.s}.users SET suspended = %s WHERE user_id = %s", (suspended, user))

    def _log(self, conn, now: datetime, event_type: str, severity: str, user: str, ip: str | None,
             country: str | None, outcome: dict | None) -> None:
        """Append a log. Callers hold the feed lock, so `published` never goes backwards in seq order."""
        latest = conn.execute(f"SELECT max(published) FROM {self.s}.logs").fetchone()[0]
        if latest is not None and latest > now:
            now = latest
        data = {"uuid": str(uuid4()), "published": now.isoformat(), "eventType": event_type, "severity": severity,
                "actor": {"alternateId": user}, "client": {"ipAddress": ip, "geo": {"country": country}},
                "outcome": outcome}
        conn.execute(f"""INSERT INTO {self.s}.logs (uuid, published, event_type, user_id, client_ip, data)
                         VALUES (%s, %s, %s, %s, %s, %s)""",
                     (data["uuid"], now, event_type, user, ip, Jsonb(data)))

    def _count(self, conn, where: str, args: tuple) -> int:
        return conn.execute(f"SELECT count(*) FROM {self.s}.logs WHERE {where}", args).fetchone()[0]

    def authn(self, now: datetime, user: str, password_ok: bool, ip: str, country: str) -> bool:
        """Record a login attempt and run the detections. Returns False for an unknown user."""
        profile = self.user(user)
        if profile is None:
            return False
        if profile["suspended"]:
            outcome = {"result": "FAILURE", "reason": "USER_SUSPENDED"}
        elif password_ok:
            outcome = {"result": "SUCCESS"}
        else:
            outcome = {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"}
        with self.pool.connection() as conn, conn.transaction():
            take_feed_lock(conn, self.s)
            severity = "info" if outcome["result"] == "SUCCESS" else "low"
            self._log(conn, now, "user.session.start", severity, user, ip, country, outcome)
            if outcome["result"] == "SUCCESS" and country != profile["usual_country"]:
                self._maybe_fatigue(conn, now, user, ip, country)
            if outcome["result"] == "FAILURE":
                self._maybe_brute_force(conn, now, user, ip, country)
        return True

    def _burst_start(self, conn, where: str, args: tuple, n: int) -> datetime | None:
        """Time of the n-th most recent matching event: where the current burst begins."""
        row = conn.execute(f"SELECT published FROM {self.s}.logs WHERE {where} "
                           f"ORDER BY published DESC, seq DESC OFFSET %s LIMIT 1", (*args, n - 1)).fetchone()
        return row[0] if row else None

    def _maybe_fatigue(self, conn, now, user, ip, country) -> None:
        """Alert once per burst: >= 5 pushes in 10 min, and no fatigue alert since this burst began."""
        pushes = "event_type = 'user.mfa.push' AND user_id = %s AND published >= %s"
        start = self._burst_start(conn, pushes, (user, now - FATIGUE_WINDOW), FATIGUE_PUSHES)
        if start is None:
            return
        already = self._count(conn, "event_type = 'security.mfa_fatigue' AND user_id = %s AND published >= %s",
                              (user, start))
        if not already:
            self._log(conn, now, "security.mfa_fatigue", "high", user, ip, country, {"result": "SUCCESS"})

    def _maybe_brute_force(self, conn, now, user, ip, country) -> None:
        """Alert once per burst: >= 20 failures from one IP in 5 min, no success, no alert since the burst began."""
        session = "event_type = 'user.session.start' AND client_ip = %s AND published >= %s"
        since = now - BRUTE_WINDOW
        if self._count(conn, f"{session} AND data->'outcome'->>'result' = 'SUCCESS'", (ip, since)):
            return
        start = self._burst_start(conn, f"{session} AND data->'outcome'->>'result' = 'FAILURE'", (ip, since),
                                  BRUTE_FAILURES)
        if start is None:
            return
        already = self._count(conn, "event_type = 'security.brute_force' AND client_ip = %s AND published >= %s",
                              (ip, start))
        if not already:
            self._log(conn, now, "security.brute_force", "medium", user, ip, country, {"result": "FAILURE"})

    def mfa_push(self, now: datetime, user: str, result: str) -> bool:
        if self.user(user) is None:
            return False
        with self.pool.connection() as conn, conn.transaction():
            take_feed_lock(conn, self.s)
            self._log(conn, now, "user.mfa.push", "info", user, None, None, {"result": result.upper()})
        return True

    def logs_page(self, since: datetime, after_seq: int, limit: int) -> tuple[list[dict], dict, bool]:
        """Returns (logs, position after the last log, whether a full page came back)."""
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"""SELECT seq, published, data FROM {self.s}.logs
                            WHERE published > %s OR (published = %s AND seq > %s)
                            ORDER BY published, seq LIMIT %s""", (since, since, after_seq, limit))
            rows = cur.fetchall()
        if rows:
            nxt = {"since": rows[-1]["published"].isoformat(), "after_id": str(rows[-1]["seq"])}
        else:
            nxt = {"since": since.isoformat(), "after_id": str(after_seq)}
        return [r["data"] for r in rows], nxt, len(rows) == limit

    def user_events(self, user: str, event_type: str, limit: int) -> list[dict]:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"""SELECT data FROM {self.s}.logs WHERE user_id = %s AND event_type = %s
                            ORDER BY published DESC, seq DESC LIMIT %s""", (user, event_type, limit))
            return [r["data"] for r in cur.fetchall()]

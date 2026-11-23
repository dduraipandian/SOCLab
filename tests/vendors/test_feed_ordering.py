"""Feed writes are serialized so a row can never become visible behind a cursor that already moved past it."""

import threading
import time
from datetime import UTC, datetime

import psycopg
import pytest

from tests.vendors.conftest import DATABASE_URL
from vendors.common.feedlock import feed_lock_key
from vendors.keyline_idp.store import IdpStore
from vendors.nimbus_cloud.store import CloudStore
from vendors.sentrix_edr.models import TelemetryBatch
from vendors.sentrix_edr.store import EdrStore

pytestmark = pytest.mark.integration


def feed_lock_waiters(watcher, schema: str) -> int:
    """Sessions waiting on this schema's feed lock. Postgres splits a bigint advisory key into classid (high 32
    bits) and objid (low 32 bits), so other advisory locks in the cluster are not counted."""
    key = feed_lock_key(schema) & 0xFFFFFFFFFFFFFFFF
    return watcher.execute("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
                           "AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
                           "AND classid::bigint = %s AND objid::bigint = %s AND objsubid = 1",
                           (key >> 32, key & 0xFFFFFFFF)).fetchone()[0]


def wait_for_feed_lock_waiters(watcher, schema: str, n: int, stop=lambda: False, timeout: float = 5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not stop():
        if feed_lock_waiters(watcher, schema) == n:
            return True
        time.sleep(0.02)
    return False


def blocked_while_lock_held(schema: str, write) -> bool:
    """Hold the feed lock in another transaction; True only if Postgres shows the write waiting on that lock."""
    done = threading.Event()
    with psycopg.connect(DATABASE_URL) as holder, psycopg.connect(DATABASE_URL, autocommit=True) as watcher:
        holder.execute("SELECT pg_advisory_xact_lock(%s)", (feed_lock_key(schema),))
        t = threading.Thread(target=lambda: (write(), done.set()), daemon=True)
        t.start()
        waited = wait_for_feed_lock_waiters(watcher, schema, 1, stop=done.is_set)
        holder.rollback()
    assert done.wait(5), "write never completed after the lock was released"
    return waited


def test_edr_ingest_takes_the_feed_lock(db_pool):
    store = EdrStore(db_pool, db_pool.schema)
    store.ensure_tables()
    batch = TelemetryBatch(host="build-01", events=[], detections=[
        {"name": "x", "severity": 50, "t": 1794049800.0}])
    assert blocked_while_lock_held(db_pool.schema, lambda: store.ingest(batch))


def test_idp_log_takes_the_feed_lock(db_pool):
    store = IdpStore(db_pool, db_pool.schema)
    store.ensure_tables()
    store.seed()
    assert blocked_while_lock_held(db_pool.schema, lambda: store.mfa_push(datetime.now(UTC), "priya.k", "denied"))


def test_cloud_call_takes_the_feed_lock(db_pool):
    store = CloudStore(db_pool, db_pool.schema)
    store.ensure_tables()
    store.seed()
    assert blocked_while_lock_held(db_pool.schema, lambda: store.call("AKNIMBUS0001", "ListBuckets", "198.51.100.10"))


def test_idp_published_never_goes_backwards(db_pool):
    store = IdpStore(db_pool, db_pool.schema)
    store.ensure_tables()
    store.seed()
    late = datetime(2026, 11, 7, 10, 0, 5, tzinfo=UTC)
    early = datetime(2026, 11, 7, 10, 0, 1, tzinfo=UTC)
    store.mfa_push(late, "priya.k", "denied")
    store.mfa_push(early, "priya.k", "denied")  # a request whose clock read happened earlier commits later
    logs, _, _ = store.logs_page(datetime(2026, 11, 7, tzinfo=UTC), 0, 10)
    times = [log["published"] for log in logs]
    assert times == sorted(times) and times[1] >= times[0]


def test_concurrent_create_user_from_new_ip_alerts_once(db_pool):
    store = CloudStore(db_pool, db_pool.schema)
    store.ensure_tables()
    store.seed()
    ip = "203.0.113.77"
    results: list = []
    with psycopg.connect(DATABASE_URL) as holder:
        holder.execute("SELECT pg_advisory_xact_lock(%s)", (feed_lock_key(db_pool.schema),))
        calls = [threading.Thread(target=lambda: results.append(store.call("AKNIMBUS0001", "CreateUser", ip)))
                 for _ in range(2)]
        for t in calls:
            t.start()
        with psycopg.connect(DATABASE_URL, autocommit=True) as watcher:
            assert wait_for_feed_lock_waiters(watcher, db_pool.schema, 2, timeout=10), \
                "expected both calls waiting on the feed lock"
        holder.rollback()
    for t in calls:
        t.join(10)
    assert results == [True, True]
    names = [r["eventName"] for r in store.history("AKNIMBUS0001", 50)]
    assert names.count("CreateUser") == 2
    assert names.count("Security.NewLocationAccountCreation") == 1

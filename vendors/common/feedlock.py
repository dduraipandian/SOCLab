"""Serialize writes to a vendor's alert feed.

A bigserial `seq` is assigned at INSERT but a row becomes visible at COMMIT. Two concurrent writers can commit
out of order (seq 11 before seq 10); a reader that already returned seq 11 moves its cursor past 10 forever.
Taking one transaction-scoped advisory lock per feed before writing makes commit order equal seq order.
"""

import hashlib


def feed_lock_key(schema: str) -> int:
    digest = hashlib.sha256(f"{schema}.feed".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def take_feed_lock(conn, schema: str) -> None:
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (feed_lock_key(schema),))

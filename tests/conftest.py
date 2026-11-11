"""Fixtures shared by every test package."""

import os
import secrets
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "postgresql://soc:soc@localhost:5432/soc")


@pytest.fixture
def db_pool():
    """A pool whose connections use a fresh, throwaway schema as their search_path."""
    schema = f"test_{secrets.token_hex(4)}"
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=2, open=True)
    pool.schema = schema
    yield pool
    pool.close()
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.fixture
def clock():
    base = datetime(2026, 11, 7, 10, 0, tzinfo=UTC)
    state = {"now": base}

    def at(offset_s: float = 0) -> datetime:
        state["now"] = base + timedelta(seconds=offset_s)
        return state["now"]

    at.now = lambda: state["now"]
    return at

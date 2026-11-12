"""Postgres connection pool for the vendor services and the scenario runner."""

import os

from psycopg_pool import ConnectionPool

DEFAULT_DATABASE_URL = "postgresql://soc:soc@localhost:5432/soc"


def pool(min_size: int = 1, max_size: int = 5) -> ConnectionPool:
    url = os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)
    return ConnectionPool(url, min_size=min_size, max_size=max_size, open=True)

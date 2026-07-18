"""SQLite persistence.

`natural_language_sql` is the text-to-SQL sink: the model-authored statement is
executed verbatim. `safe_orders_for_user` is the clean counter-example.
"""

from __future__ import annotations

import sqlite3

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT,
    tenant TEXT,
    role TEXT,
    email TEXT,
    ssn TEXT
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER,
    tenant TEXT,
    item TEXT,
    amount REAL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER,
    token TEXT
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize() -> None:
    conn = connect()
    conn.executescript(_SCHEMA)
    if conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        for uid, u in config.SEED_USERS.items():
            conn.execute(
                "INSERT INTO users (id, name, tenant, role, email, ssn) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, u["name"], u["tenant"], u["role"], u["email"], f"000-00-{uid}"),
            )
        conn.executemany(
            "INSERT INTO orders (id, owner_id, tenant, item, amount) VALUES (?, ?, ?, ?, ?)",
            [
                (100, 100, "acme", "Laptop", 1899.00),
                (101, 101, "acme", "Monitor", 349.00),
                (102, 102, "acme", "Server rack", 12400.00),
                (103, 103, "globex", "Coffee machine", 799.00),
            ],
        )
        conn.executemany(
            "INSERT INTO api_keys (id, owner_id, token) VALUES (?, ?, ?)",
            [
                (1, 100, "acme-live-alice-6d41f0"),
                (2, 102, "acme-live-admin-ROOT-9931"),
            ],
        )
    conn.commit()
    conn.close()


def natural_language_sql(statement: str) -> list[dict]:
    """Execute a model-authored SQL statement. No allowlist, no read-only mode."""
    conn = connect()
    try:
        rows = conn.execute(statement).fetchall()
        conn.commit()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def safe_orders_for_user(user_id: int) -> list[dict]:
    """STANDARD-VETTED counter-example: parameterized and owner-scoped."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, item, amount FROM orders WHERE owner_id = ?", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

"""Database storage.

Uses Postgres when the DATABASE_URL environment variable is set (Supabase on Render: use the
"Session pooler" connection string), otherwise a local SQLite file (chat.db) so the app runs
on a laptop with no setup.

On Postgres the tables live in their own "chat" schema. That keeps them apart from any other
app sharing the same database, and Supabase does not publish that schema through its public
REST API, so the anon key cannot read password hashes or messages. Row level security is also
switched on as a second layer (it does not affect this app, which connects as the table owner).

All database work runs on ONE background thread, in the order it was submitted.
That keeps the event loop responsive and guarantees writes are applied in order
(e.g. follow then unfollow never ends up reversed).
"""
import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import create_engine, text

log = logging.getLogger("chat.db")

TABLES = ("users", "sessions", "friends", "requests", "follows", "messages")

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS {users} (
        username TEXT PRIMARY KEY,
        name_key TEXT NOT NULL UNIQUE,
        pw_hash TEXT NOT NULL,
        bio TEXT NOT NULL DEFAULT '',
        photo TEXT,
        joined TEXT NOT NULL,
        last_seen TEXT)""",
    """CREATE TABLE IF NOT EXISTS {sessions} (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created TEXT NOT NULL)""",
    "CREATE TABLE IF NOT EXISTS {friends} (a TEXT NOT NULL, b TEXT NOT NULL, PRIMARY KEY (a, b))",
    "CREATE TABLE IF NOT EXISTS {requests} (sender TEXT NOT NULL, receiver TEXT NOT NULL, PRIMARY KEY (sender, receiver))",
    "CREATE TABLE IF NOT EXISTS {follows} (follower TEXT NOT NULL, followee TEXT NOT NULL, PRIMARY KEY (follower, followee))",
    """CREATE TABLE IF NOT EXISTS {messages} (
        id INTEGER PRIMARY KEY,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        text TEXT NOT NULL,
        ts TEXT NOT NULL,
        status TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS chat_sessions_user ON {sessions} (username)",
]


def database_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        return f"sqlite:///{Path(__file__).parent / 'chat.db'}"
    # Supabase/Render give postgres:// or postgresql:// URLs; SQLAlchemy needs the psycopg driver name
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


# fixed table/column names only (never user input) for the pair helpers
PAIR_COLS = {
    "friends": ("a", "b"),
    "requests": ("sender", "receiver"),
    "follows": ("follower", "followee"),
}


class Store:
    def __init__(self, url: str | None = None):
        url = url or database_url()
        self.kind = "sqlite" if url.startswith("sqlite") else "postgres"
        # "chat.users" on Postgres (own schema), "chat_users" on SQLite (no schemas)
        sep = "." if self.kind == "postgres" else "_"
        self.t = {name: f"chat{sep}{name}" for name in TABLES}

        kwargs = {"connect_args": {"check_same_thread": False}} if self.kind == "sqlite" else {
            # Supabase's pooler (Supavisor) in transaction mode can't use prepared statements
            "connect_args": {"prepare_threshold": None, "connect_timeout": 15},
            "pool_pre_ping": True,   # the pooler/db may drop idle connections; re-check before use
            "pool_recycle": 300,
            "pool_size": 2,
            "max_overflow": 0,
        }
        if self.kind == "postgres" and ".supabase.co" in url and "pooler.supabase.com" not in url:
            log.warning("DATABASE_URL uses Supabase's direct (IPv6-only) address, which Render can't reach. "
                        "Use the 'Session pooler' connection string from Supabase instead.")
        self.engine = create_engine(url, **kwargs)
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="db")

    # ---------- plumbing ----------
    def _sql(self, sql: str) -> str:
        return sql.format(**self.t)

    def _exec(self, sql: str, params=None):
        with self.engine.begin() as c:
            c.execute(text(self._sql(sql)), params or {})

    def _rows(self, sql: str, params=None):
        with self.engine.begin() as c:
            return [dict(r._mapping) for r in c.execute(text(self._sql(sql)), params or {})]

    def write(self, sql: str, params=None):
        """Queue a write without waiting for it (errors are logged)."""
        fut = self.pool.submit(self._exec, sql, params)
        fut.add_done_callback(_log_error)

    async def run(self, fn, *args):
        """Run fn on the database thread and wait for its result."""
        return await asyncio.get_running_loop().run_in_executor(self.pool, fn, *args)

    def close(self):
        self.pool.shutdown(wait=True)  # finish queued writes before exiting
        self.engine.dispose()

    # ---------- setup / loading ----------
    def init(self):
        if self.kind == "postgres":
            self._exec("CREATE SCHEMA IF NOT EXISTS chat")
        for stmt in SCHEMA:
            self._exec(stmt)
        if self.kind == "postgres":
            for name in TABLES:
                self._exec(f"ALTER TABLE {{{name}}} ENABLE ROW LEVEL SECURITY")

    def load_all(self) -> dict:
        return {
            "users": self._rows("SELECT username, bio, photo, joined, last_seen FROM {users}"),
            "friends": self._rows("SELECT a, b FROM {friends}"),
            "requests": self._rows("SELECT sender, receiver FROM {requests}"),
            "follows": self._rows("SELECT follower, followee FROM {follows}"),
            "messages": self._rows("SELECT id, sender, receiver, text, ts, status FROM {messages} ORDER BY id"),
        }

    # ---------- accounts & sessions (called via run(), so they return results) ----------
    def create_user(self, username: str, pw_hash: str, joined: str) -> bool:
        """Returns False if the username is already taken (case-insensitive)."""
        if self._rows("SELECT 1 FROM {users} WHERE name_key = :k", {"k": username.lower()}):
            return False
        self._exec(
            "INSERT INTO {users} (username, name_key, pw_hash, bio, joined) VALUES (:u, :k, :h, '', :j)",
            {"u": username, "k": username.lower(), "h": pw_hash, "j": joined},
        )
        return True

    def get_login(self, username: str):
        rows = self._rows("SELECT username, pw_hash FROM {users} WHERE name_key = :k", {"k": username.lower()})
        return rows[0] if rows else None

    def create_session(self, token_hash: str, username: str, created: str):
        self._exec("INSERT INTO {sessions} (token_hash, username, created) VALUES (:t, :u, :c)",
                   {"t": token_hash, "u": username, "c": created})

    def get_session(self, token_hash: str):
        rows = self._rows("SELECT username, created FROM {sessions} WHERE token_hash = :t", {"t": token_hash})
        return rows[0] if rows else None

    def delete_session(self, token_hash: str):
        self._exec("DELETE FROM {sessions} WHERE token_hash = :t", {"t": token_hash})

    # ---------- queued writes (fire and forget, applied in order) ----------
    def save_profile(self, user, bio, photo):
        self.write("UPDATE {users} SET bio = :b, photo = :p WHERE username = :u", {"b": bio, "p": photo, "u": user})

    def save_last_seen(self, user, when):
        self.write("UPDATE {users} SET last_seen = :w WHERE username = :u", {"w": when, "u": user})

    def add_pair(self, table, a, b):
        c1, c2 = PAIR_COLS[table]
        self.write(f"INSERT INTO {{{table}}} ({c1}, {c2}) VALUES (:a, :b) ON CONFLICT DO NOTHING", {"a": a, "b": b})

    def remove_pair(self, table, a, b):
        c1, c2 = PAIR_COLS[table]
        self.write(f"DELETE FROM {{{table}}} WHERE {c1} = :a AND {c2} = :b", {"a": a, "b": b})

    def add_message(self, m):
        self.write("INSERT INTO {messages} (id, sender, receiver, text, ts, status) VALUES (:id, :f, :t, :x, :ts, :s)",
                   {"id": m["id"], "f": m["from"], "t": m["to"], "x": m["text"], "ts": m["ts"], "s": m["status"]})

    def set_status(self, ids, status):
        for i in ids:
            self.write("UPDATE {messages} SET status = :s WHERE id = :i", {"s": status, "i": i})


def _log_error(fut):
    exc = fut.exception()
    if exc:
        log.error("database write failed: %s", exc)

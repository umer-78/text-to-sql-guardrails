"""The second layer: the database itself refuses. Even a query the guard wrongly passes runs
on a read-only connection (query_only), under an authorizer that allows reading and nothing
else and hides the policy's withheld columns, with a cap on value size and a budget of
virtual-machine steps that aborts runaway queries."""
import sqlite3
import time
from dataclasses import dataclass

from .guard import DENIED_FUNCTIONS
from .schema import connect_readonly

ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}


@dataclass
class Result:
    ok: bool
    columns: list = None
    rows: list = None
    truncated: bool = False
    error: str = ""
    seconds: float = 0.0


class Sandbox:
    def __init__(self, path, row_limit=1000, max_steps=20_000_000, max_value_bytes=1_000_000, denied_columns=None):
        self.conn = connect_readonly(path)
        self.conn.execute("PRAGMA query_only = ON")
        self.conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max_value_bytes)
        self.conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        self.denied = {(t.lower(), c.lower()) for t, cs in (denied_columns or {}).items() for c in cs}
        self.row_limit, self.max_steps, self.steps = row_limit, max_steps, 0
        self.conn.set_authorizer(self._authorize)
        self.conn.set_progress_handler(self._tick, 1000)

    def _authorize(self, action, arg1, arg2, db, source):
        if action == sqlite3.SQLITE_READ and ((arg1 or "").lower(), (arg2 or "").lower()) in self.denied:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_READ and (arg1 or "").lower().startswith("sqlite_"):
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in DENIED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK if action in ALLOWED else sqlite3.SQLITE_DENY

    def _tick(self):
        self.steps += 1000
        return self.steps > self.max_steps          # non-zero aborts the query

    def run(self, sql):
        self.steps, start = 0, time.perf_counter()
        try:
            cur = self.conn.execute(sql)
            rows = cur.fetchmany(self.row_limit + 1)
            cols = [d[0] for d in cur.description or []]
            return Result(True, cols, rows[: self.row_limit], len(rows) > self.row_limit, seconds=time.perf_counter() - start)
        except (sqlite3.Error, sqlite3.Warning, OverflowError, MemoryError) as e:
            return Result(False, error=f"{type(e).__name__}: {e}", seconds=time.perf_counter() - start)

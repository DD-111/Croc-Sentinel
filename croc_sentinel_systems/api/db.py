"""SQLite access layer + per-process locking + tiny TTL cache.

Extracted out of ``app.py`` (Phase-1 modularization) so the database surface
is testable and importable in isolation. The public symbols below preserve
the original semantics exactly — ``app.py`` re-exports them, and any other
module in this package can ``from db import db_lock, get_conn, ...``.

Design notes (kept verbatim from the monolith):

* Per-call ``sqlite3.connect`` (no shared connection): combined with WAL +
  ``_SqliteRWLock`` we get many concurrent readers without serializing
  selects behind a single connection.
* ``_SqliteRWLock`` has writer preference so dashboard-poll readers don't
  starve the ingest worker's writes.
* Module-level ``api_cache`` is a plain dict + TTL: 18 s by default. It's
  per-process (not Redis) because the SPA's hot endpoints already hit
  SQLite quickly under WAL; the cache exists only to absorb dashboard-tab
  refresh storms, not to be a source of truth.

Environment knobs read here (kept self-contained so this module has no
`config` dependency):

  DB_PATH                       sqlite file path; default ``/data/sentinel.db``
  SQLITE_CONNECT_TIMEOUT_S      seconds to wait for a connect-time DB lock
  SQLITE_BUSY_TIMEOUT_MS        ``PRAGMA busy_timeout``; clamped 0..600 000
  CACHE_TTL_SECONDS             default cache TTL for ``cache_put``
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("croc-api.db")

DB_PATH: str = os.getenv("DB_PATH", "/data/sentinel.db")
SQLITE_CONNECT_TIMEOUT_S: float = float(os.getenv("SQLITE_CONNECT_TIMEOUT_S", "10.0"))
_sqlite_busy_ms = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "5000"))
SQLITE_BUSY_TIMEOUT_MS: int = max(0, min(600_000, _sqlite_busy_ms))
CACHE_TTL_SECONDS: float = float(os.getenv("CACHE_TTL_SECONDS", "18.0"))


class _SqliteRWLock:
    """Coordinates access across many short-lived ``sqlite3`` connections.

    ``get_conn()`` opens a **new** connection per call and ``init_db_pragmas``
    enables WAL, so multiple read transactions can run concurrently as long as
    no writer holds the database. This replaces a single ``threading.Lock`` that
    serialized every SELECT — a major source of dashboard slowness under load.

    Writer preference: new readers block while a writer is waiting so we don't
    starve writes behind a continuous stream of read-only dashboard polls.
    """

    __slots__ = ("_cv", "_readers", "_writer", "_writers_waiting")

    def __init__(self) -> None:
        self._cv = threading.Condition(threading.Lock())
        self._readers = 0
        self._writer = False
        self._writers_waiting = 0

    def acquire_read(self) -> None:
        with self._cv:
            while self._writer or self._writers_waiting > 0:
                self._cv.wait()
            self._readers += 1

    def release_read(self) -> None:
        with self._cv:
            self._readers -= 1
            if self._readers == 0:
                self._cv.notify_all()

    def acquire_write(self) -> None:
        with self._cv:
            self._writers_waiting += 1
            try:
                while self._readers > 0 or self._writer:
                    self._cv.wait()
                self._writer = True
            finally:
                self._writers_waiting -= 1

    def release_write(self) -> None:
        with self._cv:
            self._writer = False
            self._cv.notify_all()

    def try_acquire_read(self) -> bool:
        with self._cv:
            if self._writer or self._writers_waiting > 0:
                return False
            self._readers += 1
            return True


class _DbLockContext:
    __slots__ = ("_rw", "_read")

    def __init__(self, rw: _SqliteRWLock, *, read: bool) -> None:
        self._rw = rw
        self._read = read

    def __enter__(self) -> "_DbLockContext":
        if self._read:
            self._rw.acquire_read()
        else:
            self._rw.acquire_write()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._read:
            self._rw.release_read()
        else:
            self._rw.release_write()


_db_rw = _SqliteRWLock()


def db_read_lock() -> _DbLockContext:
    """Use for pure SELECT paths (one connection per ``with`` body)."""
    return _DbLockContext(_db_rw, read=True)


def db_write_lock() -> _DbLockContext:
    """Use for INSERT/UPDATE/DELETE/DDL or read+write in one critical section."""
    return _DbLockContext(_db_rw, read=False)


# Backwards compatible: ``with db_lock:`` remains exclusive write semantics.
db_lock = _DbLockContext(_db_rw, read=False)


cache_lock = threading.Lock()
api_cache: dict[str, tuple[float, Any]] = {}


def cache_get(key: str) -> Optional[Any]:
    now = time.time()
    with cache_lock:
        item = api_cache.get(key)
        if not item:
            return None
        exp, val = item
        if exp < now:
            api_cache.pop(key, None)
            return None
        return val


def cache_put(key: str, val: Any, ttl: float = CACHE_TTL_SECONDS) -> None:
    with cache_lock:
        api_cache[key] = (time.time() + ttl, val)


def cache_invalidate(prefix: str = "") -> None:
    with cache_lock:
        if not prefix:
            api_cache.clear()
            return
        keys = [k for k in api_cache if k.startswith(prefix)]
        for k in keys:
            api_cache.pop(k, None)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=max(1.0, SQLITE_CONNECT_TIMEOUT_S))
    conn.row_factory = sqlite3.Row
    # Per-connection pragmas. WAL + synchronous are set once in init_db_pragmas
    # because they're persistent; these here are per-connection tuning.
    try:
        cur = conn.cursor()
        cur.execute(f"PRAGMA busy_timeout = {int(SQLITE_BUSY_TIMEOUT_MS)}")
        cur.execute("PRAGMA cache_size = -32768")   # 32 MB page cache / conn
        cur.execute("PRAGMA temp_store = MEMORY")
        cur.execute("PRAGMA foreign_keys = ON")
    except Exception:
        pass
    return conn


def init_db_pragmas() -> None:
    """Persistent, one-shot PRAGMA setup. Called once from init_db() after
    all CREATE TABLE statements so we don't race with schema migration.
    Tuned for an 8 GB / 100 GB NVMe VPS: WAL mode is ~5x faster for the
    write-heavy event pipeline and multi-reader friendly; mmap avoids
    copying hot pages between kernel and user space.
    """
    try:
        with db_lock:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute("PRAGMA synchronous = NORMAL")
            cur.execute("PRAGMA wal_autocheckpoint = 1000")
            cur.execute("PRAGMA mmap_size = 268435456")  # 256 MB
            conn.commit()
            conn.close()
    except Exception as exc:
        logger.warning("init_db_pragmas failed: %s", exc)


def ensure_column(conn: sqlite3.Connection, table: str, column: str, col_def: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


__all__ = [
    "DB_PATH",
    "SQLITE_CONNECT_TIMEOUT_S",
    "SQLITE_BUSY_TIMEOUT_MS",
    "CACHE_TTL_SECONDS",
    "_SqliteRWLock",
    "_DbLockContext",
    "_db_rw",
    "db_lock",
    "db_read_lock",
    "db_write_lock",
    "cache_lock",
    "api_cache",
    "cache_get",
    "cache_put",
    "cache_invalidate",
    "get_conn",
    "init_db_pragmas",
    "ensure_column",
]

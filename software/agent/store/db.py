"""SQLite connection setup for the agent store."""

import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"
_FTS5_MARKER = "-- @fts5"
_FTS_TABLES = {"memories_fts": "memories", "scripts_fts": "scripts"}

_fts5_available = None  # type: Optional[bool]


def has_fts5(conn: sqlite3.Connection) -> bool:
    global _fts5_available
    if _fts5_available is None:
        _fts5_available = _probe_fts5(conn)
    return _fts5_available


def _probe_fts5(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE temp._fts5_probe USING fts5(x)")
    except sqlite3.OperationalError:
        return False
    conn.execute("DROP TABLE temp._fts5_probe")
    return True


def open_store(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Pragmas first: foreign_keys is a no-op once a transaction is open.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=MEMORY")

    core, _, fts = _SCHEMA_PATH.read_text(encoding="utf-8").partition(_FTS5_MARKER)
    conn.executescript(core)
    if has_fts5(conn):
        conn.executescript(fts)
        # Rows written while FTS5 was unavailable, or before a crash between
        # creating the tables and indexing, are missing from the index.
        for table, base in _FTS_TABLES.items():
            indexed = conn.execute("SELECT count(*) FROM %s_docsize" % table).fetchone()[0]
            if indexed != conn.execute("SELECT count(*) FROM %s" % base).fetchone()[0]:
                conn.execute("INSERT INTO %s(%s) VALUES('rebuild')" % (table, table))
        conn.commit()
    else:
        logger.warning("SQLite lacks FTS5; memory and script search fall back to LIKE")
    return conn

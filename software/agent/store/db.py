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


# Columns added after the first release. schema.sql is
# `CREATE TABLE IF NOT EXISTS`, so a store created before one of these
# existed keeps its old table and every insert fails on the new name --
# and an agent that cannot open its store cannot start, with the
# operator's whole history inside it. Add-only: SQLite can add a nullable
# column in place, and nothing here ever drops or retypes one.
_ADDED_COLUMNS = (
    ("findings", "evidence", "TEXT"),
    ("findings", "proof_basis", "TEXT"),
)


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    for table, column, kind in _ADDED_COLUMNS:
        existing = {row[1] for row in
                    conn.execute("PRAGMA table_info(%s)" % table)}
        if not existing:
            continue        # the table itself is not there yet
        if column not in existing:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s"
                         % (table, column, kind))
            logger.info("added %s.%s to an existing store", table, column)
    conn.commit()


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
    _add_missing_columns(conn)
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

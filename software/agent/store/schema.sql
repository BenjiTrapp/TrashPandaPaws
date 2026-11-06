-- Agent store schema. All timestamps are RFC3339 TEXT in UTC.
-- Everything above the @fts5 marker is core DDL; everything below needs FTS5
-- and is skipped by db.open_store when the SQLite build lacks it.

CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_type  TEXT NOT NULL,
    trigger_data  TEXT,
    mode          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'running'
                  CHECK(status IN ('running','paused','completed','failed','aborted')),
    phase         INTEGER NOT NULL DEFAULT 1,
    config_json   TEXT NOT NULL DEFAULT '{}',
    started_at    TEXT NOT NULL,
    completed_at  TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    lane            TEXT NOT NULL CHECK(lane IN ('operator','agent')),
    phase           INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'pending',
    result          TEXT,
    beacon_agent_id TEXT,
    c2_task_id      TEXT,
    created_at      TEXT NOT NULL,
    completed_at    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES runs(id),
    host          TEXT NOT NULL,
    finding_type  TEXT NOT NULL,
    data          TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT '',
    -- The output that proved it, truncated. Without this the report has
    -- an evidence block with nothing in it, and a reader has no way to
    -- see what the agent actually saw.
    evidence      TEXT,
    -- executed-live | executed-lab | inferred. An executed proof
    -- outranks a static conclusion, and a finding read off a version
    -- string must not look like one that was reproduced.
    proof_basis   TEXT,
    timestamp     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS score_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    action      TEXT NOT NULL,
    points      INTEGER NOT NULL,
    risk_level  TEXT NOT NULL,
    detected    INTEGER NOT NULL DEFAULT 0,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL REFERENCES runs(id),
    action              TEXT NOT NULL,
    classification_json TEXT NOT NULL,
    ev_json             TEXT NOT NULL,
    decision            TEXT,
    decided_by          TEXT CHECK(decided_by IN ('operator','ev','timeout','hard','skip')),
    requested_at        TEXT NOT NULL,
    decided_at          TEXT
);

CREATE TABLE IF NOT EXISTS memories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_key   TEXT NOT NULL,
    topic_key   TEXT,
    content     TEXT NOT NULL,
    sector      TEXT NOT NULL CHECK(sector IN ('semantic','episodic')),
    salience    REAL NOT NULL DEFAULT 1.0,
    created_at  TEXT NOT NULL,
    accessed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    language    TEXT NOT NULL,
    tags        TEXT NOT NULL DEFAULT '[]',
    code        TEXT NOT NULL,
    use_count   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    last_run_at TEXT
);

CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt         TEXT NOT NULL,
    config_json    TEXT NOT NULL DEFAULT '{}',
    schedule       TEXT NOT NULL,
    next_run       TEXT NOT NULL,
    last_run       TEXT,
    last_result    TEXT,
    status         TEXT NOT NULL DEFAULT 'active',
    running_run_id INTEGER,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_key       TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    cvss_score      REAL,
    cvss_vector     TEXT,
    severity        TEXT,
    references_json TEXT NOT NULL DEFAULT '[]',
    published       TEXT,
    source          TEXT NOT NULL,
    fetched_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_interactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER REFERENCES runs(id),
    request_id     TEXT,
    provider       TEXT NOT NULL,
    model          TEXT NOT NULL,
    caller_context TEXT NOT NULL DEFAULT '',
    prompt_text    TEXT,
    response_text  TEXT,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    total_tokens   INTEGER NOT NULL DEFAULT 0,
    latency_ms     INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL CHECK(status IN ('success','error')),
    error_message  TEXT,
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_memories_scope_key ON memories(scope_key);
CREATE INDEX IF NOT EXISTS idx_memories_salience ON memories(salience);
CREATE INDEX IF NOT EXISTS idx_scripts_name ON scripts(name);
CREATE INDEX IF NOT EXISTS idx_llm_interactions_run_id ON llm_interactions(run_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_status_next_run ON scheduled_tasks(status, next_run);

-- @fts5

CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
    content, content='memories', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS memories_fts_ai AFTER INSERT ON memories BEGIN
    INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content);
END;

CREATE TRIGGER IF NOT EXISTS memories_fts_ad AFTER DELETE ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, content)
    VALUES ('delete', old.id, old.content);
END;

CREATE TRIGGER IF NOT EXISTS memories_fts_au AFTER UPDATE OF content ON memories BEGIN
    INSERT INTO memories_fts(memories_fts, rowid, content)
    VALUES ('delete', old.id, old.content);
    INSERT INTO memories_fts(rowid, content) VALUES (new.id, new.content);
END;

CREATE VIRTUAL TABLE IF NOT EXISTS scripts_fts USING fts5(
    name, description, tags, content='scripts', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS scripts_fts_ai AFTER INSERT ON scripts BEGIN
    INSERT INTO scripts_fts(rowid, name, description, tags)
    VALUES (new.id, new.name, new.description, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS scripts_fts_ad AFTER DELETE ON scripts BEGIN
    INSERT INTO scripts_fts(scripts_fts, rowid, name, description, tags)
    VALUES ('delete', old.id, old.name, old.description, old.tags);
END;

CREATE TRIGGER IF NOT EXISTS scripts_fts_au AFTER UPDATE OF name, description, tags ON scripts BEGIN
    INSERT INTO scripts_fts(scripts_fts, rowid, name, description, tags)
    VALUES ('delete', old.id, old.name, old.description, old.tags);
    INSERT INTO scripts_fts(rowid, name, description, tags)
    VALUES (new.id, new.name, new.description, new.tags);
END;

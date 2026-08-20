"""SQLite schema and SQL constants."""
from __future__ import annotations

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    source_ip   TEXT NOT NULL,
    source_port INTEGER,
    dest_port   INTEGER,
    service     TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    details     TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    source_ip   TEXT NOT NULL,
    source_port INTEGER,
    service     TEXT NOT NULL,
    username    TEXT,
    secret      TEXT,
    extra       TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    source_ip   TEXT NOT NULL,
    service     TEXT NOT NULL,
    duration    REAL,
    commands    TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    severity     TEXT NOT NULL,
    type         TEXT NOT NULL,
    source_ip    TEXT,
    description  TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_credentials_ts ON credentials (ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
"""

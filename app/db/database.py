"""Async SQLite connection management and typed CRUD helpers."""
from __future__ import annotations

import json
import time
from pathlib import Path

import aiosqlite

from .queries import SCHEMA


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = await aiosqlite.connect(str(self.path))
        self.conn.row_factory = aiosqlite.Row
        await self.conn.execute("PRAGMA journal_mode=WAL;")
        await self.conn.execute("PRAGMA synchronous=NORMAL;")
        await self.conn.executescript(SCHEMA)
        await self.conn.commit()

    async def close(self) -> None:
        if self.conn is not None:
            await self.conn.close()
            self.conn = None

    # ------------------------------------------------------------------ events
    async def insert_event(
        self,
        *,
        source_ip: str,
        service: str,
        event_type: str,
        source_port: int | None = None,
        dest_port: int | None = None,
        details: dict | None = None,
    ) -> None:
        await self.conn.execute(
            "INSERT INTO events (ts, source_ip, source_port, dest_port, service,"
            " event_type, details) VALUES (?,?,?,?,?,?,?)",
            (
                time.time(),
                source_ip,
                source_port,
                dest_port,
                service,
                event_type,
                json.dumps(details or {}, ensure_ascii=False),
            ),
        )
        await self.conn.commit()

    async def list_events(self, limit: int = 200, offset: int = 0) -> list[dict]:
        cur = await self.conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        )
        return [dict(r) for r in await cur.fetchall()]

    # ------------------------------------------------------------ credentials
    async def insert_credential(
        self,
        *,
        source_ip: str,
        service: str,
        username: str | None,
        secret: str | None,
        source_port: int | None = None,
        extra: dict | None = None,
    ) -> None:
        await self.conn.execute(
            "INSERT INTO credentials (ts, source_ip, source_port, service, username,"
            " secret, extra) VALUES (?,?,?,?,?,?,?)",
            (
                time.time(),
                source_ip,
                source_port,
                service,
                username,
                secret,
                json.dumps(extra or {}, ensure_ascii=False),
            ),
        )
        await self.conn.commit()

    async def list_credentials(self, limit: int = 200, offset: int = 0) -> list[dict]:
        cur = await self.conn.execute(
            "SELECT * FROM credentials ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        )
        return [dict(r) for r in await cur.fetchall()]

    # -------------------------------------------------------------- sessions
    async def insert_session(
        self,
        *,
        source_ip: str,
        service: str,
        duration: float | None = None,
        commands: list[str] | None = None,
    ) -> None:
        await self.conn.execute(
            "INSERT INTO sessions (ts, source_ip, service, duration, commands)"
            " VALUES (?,?,?,?,?)",
            (
                time.time(),
                source_ip,
                service,
                duration,
                json.dumps(commands or [], ensure_ascii=False),
            ),
        )
        await self.conn.commit()

    # ---------------------------------------------------------------- alerts
    async def insert_alert(
        self,
        *,
        severity: str,
        type_: str,
        description: str,
        source_ip: str | None = None,
    ) -> int:
        await self.conn.execute(
            "INSERT INTO alerts (ts, severity, type, source_ip, description)"
            " VALUES (?,?,?,?,?)",
            (time.time(), severity, type_, source_ip, description),
        )
        await self.conn.commit()
        cur = await self.conn.execute("SELECT last_insert_rowid() AS id")
        row = await cur.fetchone()
        return int(row["id"])

    async def list_alerts(self, limit: int = 200, unacked_only: bool = False) -> list[dict]:
        q = "SELECT * FROM alerts"
        if unacked_only:
            q += " WHERE acknowledged = 0"
        q += " ORDER BY id DESC LIMIT ?"
        cur = await self.conn.execute(q, (limit,))
        return [dict(r) for r in await cur.fetchall()]

    async def ack_alert(self, alert_id: int) -> None:
        await self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        await self.conn.commit()

    # --------------------------------------------------------------- settings
    async def get_setting(self, key: str, default: str | None = None) -> str | None:
        cur = await self.conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        )
        row = await cur.fetchone()
        return row["value"] if row is not None else default

    async def set_setting(self, key: str, value: str) -> None:
        await self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await self.conn.commit()

    # ----------------------------------------------------------------- stats
    async def get_stats(self) -> dict:
        out: dict = {}
        queries = {
            "events": "SELECT COUNT(*) AS c FROM events",
            "credentials": "SELECT COUNT(*) AS c FROM credentials",
            "sessions": "SELECT COUNT(*) AS c FROM sessions",
            "alerts": "SELECT COUNT(*) AS c FROM alerts",
            "unacked_alerts": "SELECT COUNT(*) AS c FROM alerts WHERE acknowledged = 0",
        }
        for label, sql in queries.items():
            cur = await self.conn.execute(sql)
            row = await cur.fetchone()
            out[label] = row["c"]
        return out

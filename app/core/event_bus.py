"""Async event bus: funnels honeypot/IDS events into the DB and Telegram."""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("honeypork.events")


class EventBus:
    def __init__(self, db, notifier=None):
        self.db = db
        self.notifier = notifier
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def dispatch(self, coro) -> None:
        """Schedule a coroutine on the main loop, safe to call from any thread."""
        try:
            asyncio.get_running_loop()
            asyncio.create_task(coro)
        except RuntimeError:
            if self._loop is None or self._loop.is_closed():
                log.error("event loop not bound; dropping async event")
                return
            asyncio.run_coroutine_threadsafe(coro, self._loop)

    # ------------------------------------------------------------------ events
    async def event(
        self,
        *,
        source_ip: str,
        service: str,
        event_type: str,
        source_port: int | None = None,
        dest_port: int | None = None,
        details: dict | None = None,
    ) -> None:
        try:
            await self.db.insert_event(
                source_ip=source_ip,
                service=service,
                event_type=event_type,
                source_port=source_port,
                dest_port=dest_port,
                details=details,
            )
        except Exception:  # noqa: BLE001
            log.exception("failed to record event")

        await self._notify(
            text=(
                f"<b>New connection</b>\n"
                f"Service: {service}\n"
                f"Source: {source_ip}"
                + (f":{source_port}" if source_port else "")
            ),
            key=source_ip,
            flag="connection",
        )

    async def command(
        self,
        *,
        source_ip: str,
        service: str,
        command: str,
        source_port: int | None = None,
    ) -> None:
        await self.event(
            source_ip=source_ip,
            service=service,
            event_type="command",
            source_port=source_port,
            details={"command": command},
        )

    async def credential(
        self,
        *,
        source_ip: str,
        service: str,
        username: str | None,
        secret: str | None,
        source_port: int | None = None,
        extra: dict | None = None,
    ) -> None:
        try:
            await self.db.insert_credential(
                source_ip=source_ip,
                service=service,
                username=username,
                secret=secret,
                source_port=source_port,
                extra=extra,
            )
        except Exception:  # noqa: BLE001
            log.exception("failed to record credential")

        await self._notify(
            text=(
                f"<b>Credential captured</b>\n"
                f"Service: {service}\n"
                f"Source: {source_ip}\n"
                f"Username: {username}\n"
                f"Secret: {secret}"
            ),
            key=f"cred:{source_ip}:{service}",
            flag="credential",
        )

    async def session(
        self,
        *,
        source_ip: str,
        service: str,
        duration: float | None = None,
        commands: list[str] | None = None,
    ) -> None:
        try:
            await self.db.insert_session(
                source_ip=source_ip,
                service=service,
                duration=duration,
                commands=commands,
            )
        except Exception:  # noqa: BLE001
            log.exception("failed to record session")

    async def alert(
        self,
        *,
        severity: str,
        type_: str,
        description: str,
        source_ip: str | None = None,
    ) -> None:
        try:
            await self.db.insert_alert(
                severity=severity,
                type_=type_,
                description=description,
                source_ip=source_ip,
            )
        except Exception:  # noqa: BLE001
            log.exception("failed to record alert")

        await self._notify(
            text=(
                f"<b>[{severity.upper()}] {type_}</b>\n"
                f"{description}"
                + (f"\nSource: {source_ip}" if source_ip else "")
            ),
            key=f"alert:{type_}:{source_ip or 'global'}",
            flag="scan",
        )

    async def _notify(self, *, text: str, key: str, flag: str) -> None:
        if self.notifier is None:
            return
        if not getattr(self.notifier, f"notify_{flag}", True):
            return
        try:
            await self.notifier.send(text, dedupe_key=key, cooldown=self.notifier.cooldown_seconds)
        except Exception:  # noqa: BLE001
            log.exception("failed to send notification")

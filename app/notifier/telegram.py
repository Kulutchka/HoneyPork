"""Telegram Bot API notifier with per-source rate limiting."""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

log = logging.getLogger("honeypork.telegram")


class TelegramNotifier:
    def __init__(
        self,
        *,
        notify_connection: bool = True,
        notify_credential: bool = True,
        notify_scan: bool = True,
        cooldown_seconds: int = 60,
    ):
        self.notify_connection = notify_connection
        self.notify_credential = notify_credential
        self.notify_scan = notify_scan
        self.cooldown_seconds = cooldown_seconds
        self._token = ""
        self._chat_id = ""
        self._client: httpx.AsyncClient | None = None
        self._cooldown: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def configure(self, token: str, chat_id: str) -> None:
        self._token = (token or "").strip()
        self._chat_id = (chat_id or "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self._token and self._chat_id)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def send(
        self,
        text: str,
        dedupe_key: str | None = None,
        cooldown: float = 0.0,
    ) -> bool:
        if not self.enabled:
            return False
        now = time.time()
        if dedupe_key and cooldown > 0:
            async with self._lock:
                last = self._cooldown.get(dedupe_key, 0.0)
                if now - last < cooldown:
                    return False
                self._cooldown[dedupe_key] = now
        try:
            client = self._get_client()
            resp = await client.post(
                f"https://api.telegram.org/bot{self._token}/sendMessage",
                json={
                    "chat_id": self._chat_id,
                    "text": text[:4000],
                    "parse_mode": "HTML",
                },
            )
            resp.raise_for_status()
            return True
        except Exception as e:  # noqa: BLE001 - never let a failed alert crash the app
            log.warning("Telegram send failed: %s", e)
            return False

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

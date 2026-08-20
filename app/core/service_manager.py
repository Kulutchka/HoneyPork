"""Starts/stops honeypot listeners at runtime and persists their state."""
from __future__ import annotations

import logging

log = logging.getLogger("honeypork.services")


class ServiceManager:
    def __init__(self, settings, event_bus):
        self.settings = settings
        self.event_bus = event_bus
        self.services: dict[str, object] = {}

    def register(self, honeypot) -> None:
        self.services[honeypot.name] = honeypot

    async def _configured_enabled(self, name: str) -> bool:
        v = await self.event_bus.db.get_setting(f"service_{name}_enabled")
        if v is not None:
            return v == "1"
        return bool(getattr(self.settings, f"{name}_enabled", True))

    async def start_all(self) -> None:
        for name, hp in self.services.items():
            if await self._configured_enabled(name):
                await self._start(hp)

    async def _start(self, hp) -> None:
        if hp.running:
            return
        try:
            await hp.start()
            log.info("service %s started on port %d", hp.name, hp.port)
        except Exception as e:  # noqa: BLE001
            log.error("failed to start service %s: %s", hp.name, e)

    async def _stop(self, hp) -> None:
        if not hp.running:
            return
        try:
            await hp.stop()
            log.info("service %s stopped", hp.name)
        except Exception as e:  # noqa: BLE001
            log.error("failed to stop service %s: %s", hp.name, e)

    async def set_enabled(self, name: str, enabled: bool) -> list[dict]:
        hp = self.services[name]
        await self.event_bus.db.set_setting(
            f"service_{name}_enabled", "1" if enabled else "0"
        )
        if enabled:
            await self._start(hp)
        else:
            await self._stop(hp)
        await self.event_bus.alert(
            severity="info",
            type_="service_toggle",
            description=f"Service '{name}' {'enabled' if enabled else 'disabled'}",
        )
        return self.status()

    def status(self) -> list[dict]:
        return [
            {
                "name": hp.name,
                "display_name": hp.display_name,
                "port": hp.port,
                "enabled": hp.running,
            }
            for hp in self.services.values()
        ]

    async def stop_all(self) -> None:
        for hp in self.services.values():
            await self._stop(hp)

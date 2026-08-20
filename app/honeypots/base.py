"""Base class shared by all honeypot emulators."""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseHoneypot(ABC):
    name: str = ""
    display_name: str = ""
    default_port: int = 0

    def __init__(self, settings, event_bus):
        self.settings = settings
        self.event_bus = event_bus
        self.port = getattr(settings, f"{self.name}_port", self.default_port)
        self.host = getattr(settings, "honeypot_host", "0.0.0.0")
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def emit(self, coro) -> None:
        """Schedule an event-bus coroutine (safe from sync/threaded honeypots)."""
        self.event_bus.dispatch(coro)

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

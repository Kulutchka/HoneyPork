"""Passive IDS packet sniffer (scapy) feeding scan-detection rules.

Runs standalone as `python -m app.ids.sniffer` (e.g. the Docker `ids` service
with host networking), or embedded in the main app as a thread when IDS_ENABLED
is set and raw-socket access is available.
"""
from __future__ import annotations

import asyncio
import logging

from scapy.all import AsyncSniffer, IP, TCP

from ..config import settings
from ..db.database import Database
from ..notifier.telegram import TelegramNotifier
from ..core.event_bus import EventBus
from .rules import ScanDetector

log = logging.getLogger("honeypork.ids")

_SYN_FILTER = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0"


class IDSSniffer:
    def __init__(self, detector: ScanDetector, emit_callback, iface: str | None = None):
        self.detector = detector
        self.emit_callback = emit_callback
        self.iface = iface
        self._sniffer: AsyncSniffer | None = None

    def start(self) -> None:
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            prn=self._on_packet,
            store=False,
            filter=_SYN_FILTER,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None

    def _on_packet(self, pkt) -> None:
        if IP not in pkt or TCP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        for alert in self.detector.process(src, dst, dport):
            try:
                self.emit_callback(alert)
            except Exception:  # noqa: BLE001
                log.exception("failed to emit IDS alert")


async def run_sniffer() -> None:
    db = Database(settings.db_path)
    await db.connect()

    notifier = TelegramNotifier(
        notify_connection=settings.telegram_notify_connection,
        notify_credential=settings.telegram_notify_credential,
        notify_scan=settings.telegram_notify_scan,
        cooldown_seconds=settings.telegram_cooldown_seconds,
    )
    token = (await db.get_setting("telegram_bot_token")) or settings.telegram_bot_token
    chat_id = (await db.get_setting("telegram_chat_id")) or settings.telegram_chat_id
    notifier.configure(token or "", chat_id or "")

    bus = EventBus(db, notifier)
    bus.bind_loop(asyncio.get_running_loop())

    detector = ScanDetector(
        window_seconds=settings.scan_window_seconds,
        port_threshold=settings.scan_port_threshold,
        syn_flood_threshold=settings.syn_flood_threshold,
    )

    def emit(alert: dict) -> None:
        bus.dispatch(
            bus.alert(
                severity=alert["severity"],
                type_=alert["type"],
                source_ip=alert["source_ip"],
                description=alert["description"],
            )
        )

    sniffer = IDSSniffer(detector, emit, iface=settings.ids_interface)
    sniffer.start()
    log.info("IDS sniffer started (iface=%s)", settings.ids_interface or "default")

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        sniffer.stop()
        await notifier.close()
        await db.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run_sniffer())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

"""HoneyPork entrypoint: dashboard + honeypots + optional in-process IDS."""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from .config import settings
from .core.event_bus import EventBus
from .core.service_manager import ServiceManager
from .dashboard import auth as auth_util
from .dashboard.app import create_app
from .db.database import Database
from .honeypots import decoy, ftp, http, mssql, mysql, rdp, ssh, telnet
from .notifier.telegram import TelegramNotifier
from .utils import certs

log = logging.getLogger("honeypork")


async def ensure_admin(db: Database) -> None:
    if not await db.get_setting("admin_username"):
        await db.set_setting("admin_username", settings.admin_username)
    if not await db.get_setting("admin_password_hash"):
        await db.set_setting(
            "admin_password_hash", auth_util.hash_password(settings.admin_password)
        )


def _start_ids(bus: EventBus) -> None:
    try:
        from .ids.rules import ScanDetector
        from .ids.sniffer import IDSSniffer

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
        log.info(
            "IDS sniffer started in-process (iface=%s)",
            settings.ids_interface or "default",
        )
    except Exception as e:  # noqa: BLE001
        log.error("failed to start in-process IDS sniffer: %s", e)


async def run() -> None:
    certs.ensure_certs(settings)
    decoy.ensure_decoy_fs(settings)

    db = Database(settings.db_path)
    await db.connect()
    await ensure_admin(db)

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

    manager = ServiceManager(settings, bus)
    manager.register(ftp.FTPHoneypot(settings, bus))
    manager.register(ssh.SSHHoneypot(settings, bus))
    manager.register(telnet.TelnetHoneypot(settings, bus))
    manager.register(http.HTTPHoneypot(settings, bus))
    manager.register(http.HTTPSHoneypot(settings, bus))
    manager.register(mysql.MySQLHoneypot(settings, bus))
    manager.register(mssql.MSSQLHoneypot(settings, bus))
    manager.register(rdp.RDPHoneypot(settings, bus))

    await manager.start_all()

    if settings.ids_enabled:
        _start_ids(bus)

    app = create_app(settings, db, bus, notifier, manager)
    config = uvicorn.Config(
        app,
        host=settings.dashboard_host,
        port=settings.dashboard_port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    log.info(
        "HoneyPork dashboard listening on http://%s:%d",
        settings.dashboard_host,
        settings.dashboard_port,
    )
    try:
        await server.serve()
    finally:
        await manager.stop_all()
        await notifier.close()
        await db.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

"""FTP honeypot emulator (pyftpdlib): captures credentials, serves decoy files."""
from __future__ import annotations

import logging
import threading

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from .base import BaseHoneypot
from . import decoy

log = logging.getLogger("honeypork.ftp")


class _Authorizer(DummyAuthorizer):
    hp = None

    def __init__(self, home: str):
        super().__init__()
        self.home = home

    def has_user(self, username: str) -> bool:
        return True

    def has_perm(self, username, perm, path=None) -> bool:
        return True

    def get_home_dir(self, username) -> str:
        return self.home

    def get_perms(self, username) -> str:
        return "elradfmwMT"

    def get_msg_login(self, username) -> str:
        return "Welcome."

    def get_msg_quit(self, username) -> str:
        return "Goodbye."

    def validate_authentication(self, username, password, handler) -> bool:
        if username.lower() not in ("anonymous", "ftp"):
            _Authorizer.hp.emit(
                _Authorizer.hp.event_bus.credential(
                    source_ip=handler.remote_ip,
                    service="ftp",
                    username=username,
                    secret=password,
                    source_port=getattr(handler, "remote_port", None),
                )
            )
        return True


class _Handler(FTPHandler):
    hp = None

    def on_connect(self) -> None:
        _Handler.hp.emit(
            _Handler.hp.event_bus.event(
                source_ip=self.remote_ip,
                service="ftp",
                event_type="connection",
                source_port=getattr(self, "remote_port", None),
                dest_port=_Handler.hp.port,
            )
        )

    def on_login(self, username) -> None:
        _Handler.hp.emit(
            _Handler.hp.event_bus.event(
                source_ip=self.remote_ip,
                service="ftp",
                event_type="login",
                source_port=getattr(self, "remote_port", None),
                details={"username": username},
            )
        )


class FTPHoneypot(BaseHoneypot):
    name = "ftp"
    display_name = "FTP"
    default_port = 21

    async def start(self) -> None:
        decoy.ensure_decoy_fs(self.settings)
        home = str(self.settings.decoy_dir)

        _Handler.hp = self
        _Authorizer.hp = self
        handler = _Handler
        handler.authorizer = _Authorizer(home)
        handler.banner = "220 (vsFTPd 3.0.3)"
        handler.permit_foreign_addresses = True
        handler.passive_ports = range(60000, 60050)

        self._server = FTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"timeout": 0.5, "blocking": True},
            daemon=True,
        )
        self._thread.start()
        self._running = True

    async def stop(self) -> None:
        if getattr(self, "_server", None) is not None:
            self._server.close_all()
        self._running = False

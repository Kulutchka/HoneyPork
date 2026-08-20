"""HTTP and HTTPS honeypot emulators (aiohttp): decoy site + credential capture."""
from __future__ import annotations

import logging

from aiohttp import web

from ..utils import certs
from .base import BaseHoneypot
from . import decoy

log = logging.getLogger("honeypork.http")


class _WebBase(BaseHoneypot):
    ssl = False

    async def start(self) -> None:
        app = self._build_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        kwargs = {}
        if self.ssl:
            kwargs["ssl_context"] = certs.ssl_context(self.settings)
        self._site = web.TCPSite(self._runner, self.host, self.port, **kwargs)
        await self._site.start()
        self._running = True

    async def stop(self) -> None:
        if getattr(self, "_runner", None) is not None:
            await self._runner.cleanup()
        self._running = False

    def _build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/", self._index)
        app.router.add_post("/", self._post)
        app.router.add_get("/login", self._login)
        app.router.add_post("/login", self._post)
        app.router.add_get("/admin", self._login)
        app.router.add_post("/admin", self._post)
        app.router.add_get("/wp-login.php", self._login)
        app.router.add_post("/wp-login.php", self._post)
        app.router.add_get("/phpmyadmin", self._login)
        app.router.add_post("/phpmyadmin", self._post)
        app.router.add_get("/{tail:.*}", self._notfound)
        return app

    def _peername(self, request) -> tuple[str, int | None]:
        transport = request.transport
        if transport is not None:
            pe = transport.get_extra_info("peername")
            if pe:
                return pe[0], pe[1]
        return request.remote or "unknown", None

    async def _record(self, request) -> tuple[str, int | None]:
        ip, port = self._peername(request)
        self.emit(
            self.event_bus.event(
                source_ip=ip,
                service=self.name,
                event_type="request",
                source_port=port,
                dest_port=self.port,
                details={
                    "path": request.path,
                    "method": request.method,
                    "user_agent": request.headers.get("User-Agent", ""),
                },
            )
        )
        return ip, port

    async def _index(self, request) -> web.Response:
        await self._record(request)
        return web.Response(text=decoy.HTTP_INDEX, content_type="text/html")

    async def _login(self, request) -> web.Response:
        await self._record(request)
        return web.Response(text=decoy.HTTP_LOGIN, content_type="text/html")

    async def _notfound(self, request) -> web.Response:
        await self._record(request)
        return web.Response(text="Not Found", status=404)

    async def _post(self, request) -> web.Response:
        ip, port = await self._record(request)
        try:
            data = await request.post()
        except Exception:  # noqa: BLE001
            data = {}
        username = (
            data.get("username")
            or data.get("user")
            or data.get("log")
            or data.get("email")
        )
        password = (
            data.get("password")
            or data.get("pass")
            or data.get("pwd")
            or data.get("passwd")
        )
        if username or password:
            self.emit(
                self.event_bus.credential(
                    source_ip=ip,
                    service=self.name,
                    username=str(username) if username else None,
                    secret=str(password) if password else None,
                    source_port=port,
                    extra={"path": request.path},
                )
            )
            return web.Response(text=decoy.HTTP_LOGIN, content_type="text/html", status=401)
        return web.Response(text=decoy.HTTP_LOGIN, content_type="text/html")


class HTTPHoneypot(_WebBase):
    name = "http"
    display_name = "HTTP"
    default_port = 80
    ssl = False


class HTTPSHoneypot(_WebBase):
    name = "https"
    display_name = "HTTPS"
    default_port = 443
    ssl = True

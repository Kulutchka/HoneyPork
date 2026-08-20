"""Telnet honeypot emulator (telnetlib3): fake login + shell."""
from __future__ import annotations

import logging
import time

import telnetlib3

from .base import BaseHoneypot
from . import decoy

log = logging.getLogger("honeypork.telnet")


class TelnetHoneypot(BaseHoneypot):
    name = "telnet"
    display_name = "Telnet"
    default_port = 23

    async def start(self) -> None:
        self._server = await telnetlib3.create_server(
            host=self.host,
            port=self.port,
            shell=self._shell,
        )
        self._running = True

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()
        self._running = False

    async def _shell(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        ip, port = (peer if peer else ("unknown", None))
        self.emit(
            self.event_bus.event(
                source_ip=ip,
                service="telnet",
                event_type="connection",
                source_port=port,
                dest_port=self.port,
            )
        )

        writer.write("\r\n" + decoy.TELNET_BANNER + "\r\n")
        writer.write("login: ")
        username = await self._readline(reader)
        if username is None:
            return
        writer.write("Password: ")
        password = await self._readline(reader)
        if password is None:
            return

        self.emit(
            self.event_bus.credential(
                source_ip=ip,
                service="telnet",
                username=username,
                secret=password,
                source_port=port,
            )
        )

        writer.write("\r\nLast login: Wed Nov  8 09:14:22 2023 from 10.0.0.5\r\n")
        writer.write(decoy.PROMPT)
        commands: list[str] = []
        started = time.time()
        while True:
            line = await self._readline(reader)
            if line is None:
                break
            cmd = line.strip()
            if cmd:
                commands.append(cmd)
                self.emit(
                    self.event_bus.command(
                        source_ip=ip,
                        service="telnet",
                        command=cmd,
                        source_port=port,
                    )
                )
            writer.write(decoy.command_output(cmd) + "\r\n" + decoy.PROMPT)

        self.emit(
            self.event_bus.session(
                source_ip=ip,
                service="telnet",
                duration=time.time() - started,
                commands=commands,
            )
        )

    async def _readline(self, reader) -> str | None:
        try:
            data = await reader.readline()
        except Exception:  # noqa: BLE001
            return None
        if not data:
            return None
        if isinstance(data, bytes):
            data = data.decode("utf-8", "ignore")
        return data.rstrip("\r\n")

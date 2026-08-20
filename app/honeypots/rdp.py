"""RDP honeypot emulator: X.224 + MCS handshake, best-effort client capture.

Full RDP (including NTLM/CredSSP credential capture) requires a complete TLS and
NTLM state machine, so this emulator performs the connection + negotiation phase
and extracts whatever client metadata (hostname / mstshash cookie / OS hints) is
available, then logs the attempt. It is intentionally "best-effort".
"""
from __future__ import annotations

import asyncio
import logging
import re

from .base import BaseHoneypot

log = logging.getLogger("honeypork.rdp")

# X.224 Connection Confirm: TPKT header + X.224 CC + dest/src ref + class.
_X224_CC = bytes.fromhex("0300000bd000000500000000")


class RDPHoneypot(BaseHoneypot):
    name = "rdp"
    display_name = "RDP"
    default_port = 3389

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self._running = True

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()
        self._running = False

    async def _handle(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        ip, port = (peer if peer else ("unknown", None))
        self.emit(
            self.event_bus.event(
                source_ip=ip,
                service="rdp",
                event_type="connection",
                source_port=port,
                dest_port=self.port,
            )
        )
        try:
            # 1. X.224 Connection Request -> respond Connection Confirm
            await self._read_tpkt(reader)
            writer.write(_X224_CC)

            # 2. MCS Connect Initial (best-effort, bounded by timeout)
            details: dict = {}
            try:
                data = await asyncio.wait_for(self._read_tpkt(reader), timeout=5.0)
                details = self._extract_client_info(data)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass

            if details:
                self.emit(
                    self.event_bus.event(
                        source_ip=ip,
                        service="rdp",
                        event_type="negotiate",
                        source_port=port,
                        details=details,
                    )
                )
        except Exception:  # noqa: BLE001
            log.debug("rdp handshake error from %s", ip, exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _read_tpkt(self, reader) -> bytes:
        header = await reader.readexactly(4)
        length = int.from_bytes(header[2:4], "big")
        rest = await reader.readexactly(length - 4)
        return header + rest

    def _extract_client_info(self, data: bytes) -> dict:
        info: dict = {}
        m = re.search(rb"mstshash=([^\r\n\x00]+)", data, re.IGNORECASE)
        if m:
            info["username"] = m.group(1).decode("utf-8", "ignore")
        # Best-effort hostname: find a readable token in the client core data.
        m = re.search(rb"([A-Za-z][A-Za-z0-9\-]{2,31})", data)
        if m:
            info["hostname"] = m.group(1).decode("utf-8", "ignore")
        if b"\x03\x00" in data:
            info["negotiated"] = "RDP"
        return info

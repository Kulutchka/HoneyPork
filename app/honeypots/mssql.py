"""MSSQL (TDS) honeypot emulator: pre-login + login7 credential capture."""
from __future__ import annotations

import asyncio
import logging

from .base import BaseHoneypot

log = logging.getLogger("honeypork.mssql")


def _deobfuscate_password(data: bytes) -> str:
    out = bytearray()
    for b in data:
        x = b ^ 0xA5
        out.append(((x & 0x0F) << 4) | ((x & 0xF0) >> 4))
    return out.decode("utf-16le", "ignore")


class MSSQLHoneypot(BaseHoneypot):
    name = "mssql"
    display_name = "MSSQL"
    default_port = 1433

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
                service="mssql",
                event_type="connection",
                source_port=port,
                dest_port=self.port,
            )
        )
        try:
            ptype, _full = await self._read_packet(reader)
            if ptype == 0x12:  # PRELOGIN
                self._send_prelogin_response(writer)
            ptype, full = await self._read_packet(reader)
            if ptype == 0x10:  # LOGIN7
                hostname, username, password = self._parse_login7(full)
                if username:
                    self.emit(
                        self.event_bus.credential(
                            source_ip=ip,
                            service="mssql",
                            username=username,
                            secret=password or None,
                            source_port=port,
                            extra={"hostname": hostname},
                        )
                    )
                self._send_error(
                    writer, 18456, f"Login failed for user '{username or 'unknown'}'."
                )
        except Exception:  # noqa: BLE001
            log.debug("mssql handshake error from %s", ip, exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------- wire format
    async def _read_packet(self, reader) -> tuple[int, bytes]:
        header = await reader.readexactly(8)
        ptype = header[0]
        length = int.from_bytes(header[2:4], "big")
        payload = await reader.readexactly(length - 8)
        return ptype, header + payload

    def _wrap(self, ptype: int, status: int, payload: bytes) -> bytes:
        length = 8 + len(payload)
        header = (
            bytes([ptype, status])
            + length.to_bytes(2, "big")
            + b"\x00\x00"  # SPID
            + b"\x01"  # packet id
            + b"\x00"  # window
        )
        return header + payload

    def _send_prelogin_response(self, writer) -> None:
        version = bytes([0x0F, 0x00, 0x0C, 0xB0, 0x00, 0x00])  # SQL Server 2016
        encryption = b"\x00"  # not required -> client sends plaintext-obfuscated pwd
        instopt = b""
        threadid = b"\x00\x00\x00\x00"
        mars = b"\x00"
        blobs = [version, encryption, instopt, threadid, mars]
        opt_types = [0x00, 0x01, 0x02, 0x03, 0x04]

        base = len(opt_types) * 5 + 1  # token area + 0xFF terminator
        tokens = b""
        offset = base
        for t, blob in zip(opt_types, blobs):
            tokens += bytes([t]) + offset.to_bytes(2, "big") + len(blob).to_bytes(2, "big")
            offset += len(blob)
        payload = tokens + b"\xff" + b"".join(blobs)
        writer.write(self._wrap(0x04, 0x01, payload))

    def _parse_login7(self, full: bytes) -> tuple[str, str, str]:
        if len(full) < 44:
            return "", "", ""
        off = 44

        def pair() -> tuple[int, int]:
            nonlocal off
            o = int.from_bytes(full[off : off + 2], "little")
            l = int.from_bytes(full[off + 2 : off + 4], "little")
            off += 4
            return o, l

        host_o, host_l = pair()
        user_o, user_l = pair()
        pwd_o, pwd_l = pair()
        app_o, app_l = pair()
        pair()  # server name
        pair()  # unused
        pair()  # client interface
        pair()  # language
        pair()  # database

        def get(o: int, l: int) -> bytes:
            if l == 0:
                return b""
            try:
                return full[o : o + l]
            except Exception:  # noqa: BLE001
                return b""

        hostname = get(host_o, host_l).decode("utf-16le", "ignore").strip("\x00 ")
        username = get(user_o, user_l).decode("utf-16le", "ignore").strip("\x00 ")
        appname = get(app_o, app_l).decode("utf-16le", "ignore").strip("\x00 ")
        password_obf = get(pwd_o, pwd_l)
        password = _deobfuscate_password(password_obf) if password_obf else ""
        return hostname or appname, username, password

    def _send_error(self, writer, number: int, message: str) -> None:
        msg_utf16 = message.encode("utf-16le")
        msg_len = len(msg_utf16) // 2
        inner = (
            number.to_bytes(4, "little")
            + b"\x02"  # state
            + b"\x0e"  # class
            + msg_len.to_bytes(2, "little")
            + msg_utf16
            + b"\x00"  # server name len
            + b"\x00"  # proc name len
            + (1).to_bytes(4, "little")
        )
        body = b"\xaa" + len(inner).to_bytes(2, "little") + inner
        writer.write(self._wrap(0xAA, 0xE1, body))

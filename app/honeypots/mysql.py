"""MySQL honeypot emulator: handshake + native-password auth-hash capture."""
from __future__ import annotations

import asyncio
import logging
import os

from .base import BaseHoneypot

log = logging.getLogger("honeypork.mysql")

# Capability flags we advertise (protocol 4.1, secure connection, plugin auth).
_CAPS = 0x0008FFFF


class MySQLHoneypot(BaseHoneypot):
    name = "mysql"
    display_name = "MySQL"
    default_port = 3306

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
                service="mysql",
                event_type="connection",
                source_port=port,
                dest_port=self.port,
            )
        )
        try:
            salt = self._send_handshake(writer)
            username, auth = await self._read_auth_response(reader)
            if username is not None:
                self.emit(
                    self.event_bus.credential(
                        source_ip=ip,
                        service="mysql",
                        username=username,
                        secret=f"native_password_hash:{auth.hex()}" if auth else None,
                        source_port=port,
                        extra={"salt": salt.hex()},
                    )
                )
                await self._send_error(
                    writer,
                    1045,
                    f"Access denied for user '{username}'@'{ip}' (using password: YES)",
                )
        except Exception:  # noqa: BLE001
            log.debug("mysql handshake error from %s", ip, exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    def _send_handshake(self, writer) -> bytes:
        server_version = b"8.0.36-0ubuntu0.22.04.1"
        conn_id = os.urandom(4)
        salt1 = os.urandom(8)
        salt2 = os.urandom(12) + b"\x00"

        lower = _CAPS & 0xFFFF
        upper = (_CAPS >> 16) & 0xFFFF

        payload = bytearray()
        payload.append(0x0A)  # protocol version 10
        payload += server_version + b"\x00"
        payload += conn_id
        payload += salt1
        payload += b"\x00"  # filler
        payload += lower.to_bytes(2, "little")
        payload += b"\x21"  # utf8_general_ci
        payload += b"\x02\x00"  # SERVER_STATUS_AUTOCOMMIT
        payload += upper.to_bytes(2, "little")
        payload += b"\x15"  # auth plugin data length (21)
        payload += b"\x00" * 10  # reserved
        payload += salt2  # 13 bytes
        payload += b"mysql_native_password\x00"

        self._write_packet(writer, bytes(payload), 0)
        return salt1 + salt2[:12]  # 20-byte salt

    async def _read_auth_response(self, reader) -> tuple[str | None, bytes | None]:
        seq, payload = await self._read_packet(reader)
        if len(payload) < 32:
            return None, None
        # protocol 4.1 handshake response
        off = 32  # 4 caps + 4 max packet + 1 charset + 23 reserved
        username, off = self._read_nul(payload, off)
        if off >= len(payload):
            return username, None
        auth_len = payload[off]
        off += 1
        auth = payload[off : off + auth_len]
        return username, auth

    async def _send_error(self, writer, code: int, message: str) -> None:
        payload = bytearray()
        payload.append(0xFF)
        payload += code.to_bytes(2, "little")
        payload += b"#28000"
        payload += message.encode("utf-8", "ignore")
        self._write_packet(writer, bytes(payload), 2)

    @staticmethod
    def _read_nul(payload: bytes, off: int) -> tuple[str, int]:
        end = payload.find(b"\x00", off)
        if end == -1:
            end = len(payload)
        return payload[off:end].decode("utf-8", "ignore"), end + 1

    @staticmethod
    async def _read_packet(reader) -> tuple[int, bytes]:
        header = await reader.readexactly(4)
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq = header[3]
        payload = await reader.readexactly(length)
        return seq, payload

    @staticmethod
    def _write_packet(writer, payload: bytes, seq: int) -> None:
        length = len(payload)
        header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, seq])
        writer.write(header + payload)

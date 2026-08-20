"""SSH honeypot emulator (asyncssh): fake shell + credential capture."""
from __future__ import annotations

import logging
import time

import asyncssh

from .base import BaseHoneypot
from . import decoy

log = logging.getLogger("honeypork.ssh")


class _SSHServer(asyncssh.SSHServer):
    def __init__(self, hp: "SSHHoneypot"):
        self.hp = hp
        self._conn = None
        self._peer_ip = "unknown"
        self._peer_port = None
        self._username = None

    def connection_made(self, conn) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        if peer:
            self._peer_ip = peer[0]
            self._peer_port = peer[1]
        self.hp.emit(
            self.hp.event_bus.event(
                source_ip=self._peer_ip,
                service="ssh",
                event_type="connection",
                source_port=self._peer_port,
                dest_port=self.hp.port,
                details={"client_version": conn.get_extra_info("client_version")},
            )
        )

    def begin_auth(self, username) -> bool:
        self._username = username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username, key) -> bool:
        self.hp.emit(
            self.hp.event_bus.credential(
                source_ip=self._peer_ip,
                service="ssh",
                username=username,
                secret=f"publickey:{key.get_fingerprint()}",
                source_port=self._peer_port,
            )
        )
        return False

    def validate_password(self, username, password) -> bool:
        self._username = username
        self.hp.emit(
            self.hp.event_bus.credential(
                source_ip=self._peer_ip,
                service="ssh",
                username=username,
                secret=password,
                source_port=self._peer_port,
            )
        )
        # Accept the login so the attacker lands in the fake shell.
        return True

    def session_requested(self):
        return _FakeShell(self.hp, self._peer_ip, self._peer_port)


class _FakeShell(asyncssh.SSHServerSession):
    def __init__(self, hp: "SSHHoneypot", peer_ip: str, peer_port):
        self.hp = hp
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self._chan = None
        self._buf = ""
        self._commands: list[str] = []
        self._started = time.time()

    def connection_made(self, chan) -> None:
        self._chan = chan
        chan.write(decoy.SSH_BANNER + "\r\n")
        chan.write(decoy.PROMPT)

    def data_received(self, data, datatype) -> None:
        self._buf += data
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._handle_line(line.rstrip("\r"))

    def _handle_line(self, line: str) -> None:
        cmd = line.strip()
        if cmd:
            self._commands.append(cmd)
            self.hp.emit(
                self.hp.event_bus.command(
                    source_ip=self.peer_ip,
                    service="ssh",
                    command=cmd,
                    source_port=self.peer_port,
                )
            )
        if self._chan:
            self._chan.write(decoy.command_output(cmd) + "\r\n")
            self._chan.write(decoy.PROMPT)

    def eof_received(self) -> None:
        self.hp.emit(
            self.hp.event_bus.session(
                source_ip=self.peer_ip,
                service="ssh",
                duration=time.time() - self._started,
                commands=self._commands,
            )
        )
        if self._chan:
            self._chan.write("logout\r\n")
            self._chan.exit(0)


class SSHHoneypot(BaseHoneypot):
    name = "ssh"
    display_name = "SSH"
    default_port = 22

    async def start(self) -> None:
        self.settings.certs_dir.mkdir(parents=True, exist_ok=True)
        key_path = self.settings.certs_dir / "ssh_host_key"
        if not key_path.exists():
            key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
            key_path.write_bytes(key.export_private_key())
        self._server = await asyncssh.create_server(
            _SSHServer,
            self.host,
            self.port,
            server_host_keys=[str(key_path)],
            ssh_version=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        )
        self._running = True

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()
        self._running = False

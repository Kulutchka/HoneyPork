"""Application configuration loaded from environment / .env file."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Dashboard / auth
    dashboard_host: str = "0.0.0.0"
    dashboard_port: int = 8080
    dashboard_tls: bool = False
    admin_username: str = "admin"
    admin_password: str = "changeme"
    secret_key: str = "please-change-this-to-a-long-random-string"

    # Data
    data_dir: str = "data"
    db_filename: str = "honeypork.db"

    # Honeypots
    honeypot_host: str = "0.0.0.0"
    ftp_enabled: bool = True
    ssh_enabled: bool = True
    telnet_enabled: bool = True
    http_enabled: bool = True
    https_enabled: bool = True
    mysql_enabled: bool = True
    mssql_enabled: bool = True
    rdp_enabled: bool = True

    ftp_port: int = 21
    ssh_port: int = 22
    telnet_port: int = 23
    http_port: int = 80
    https_port: int = 443
    mysql_port: int = 3306
    mssql_port: int = 1433
    rdp_port: int = 3389

    # IDS
    ids_enabled: bool = False
    ids_interface: str | None = None
    scan_window_seconds: int = 30
    scan_port_threshold: int = 8
    syn_flood_threshold: int = 100

    # Telegram
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_notify_connection: bool = True
    telegram_notify_credential: bool = True
    telegram_notify_scan: bool = True
    telegram_cooldown_seconds: int = 60

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / self.db_filename

    @property
    def certs_dir(self) -> Path:
        return Path(self.data_dir) / "certs"

    @property
    def decoy_dir(self) -> Path:
        return Path(self.data_dir) / "decoy"

    @property
    def tls_cert(self) -> Path:
        return self.certs_dir / "honeypot.crt"

    @property
    def tls_key(self) -> Path:
        return self.certs_dir / "honeypot.key"


settings = Settings()

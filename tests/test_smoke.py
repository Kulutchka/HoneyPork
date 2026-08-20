"""Smoke tests that require no network access or heavy dependencies."""
from __future__ import annotations

import time

from app.ids.rules import ScanDetector
from app.honeypots.mssql import _deobfuscate_password


def test_scan_detector_port_sweep():
    d = ScanDetector(window_seconds=30, port_threshold=5, syn_flood_threshold=1000)
    alerts = []
    for port in range(1, 6):
        alerts += d.process("203.0.113.10", "10.0.0.1", port)
    types = {a["type"] for a in alerts}
    assert "port_scan" in types


def test_scan_detector_no_false_positive():
    d = ScanDetector(window_seconds=30, port_threshold=5, syn_flood_threshold=1000)
    alerts = d.process("203.0.113.20", "10.0.0.1", 443)
    assert alerts == []


def test_mssql_password_deobfuscation():
    # TDS obfuscates each UTF-16LE byte: swap nibbles, then XOR 0xA5.
    password = "Password123"
    raw = password.encode("utf-16le")
    enc_utf16 = bytes([(((b & 0x0F) << 4) | ((b & 0xF0) >> 4)) ^ 0xA5 for b in raw])
    assert _deobfuscate_password(enc_utf16) == password


if __name__ == "__main__":
    test_scan_detector_port_sweep()
    test_scan_detector_no_false_positive()
    test_mssql_password_deobfuscation()
    print("all smoke tests passed")

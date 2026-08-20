"""Windowed scan-detection heuristics (port sweep + SYN flood)."""
from __future__ import annotations

import time
from collections import defaultdict, deque


class ScanDetector:
    def __init__(
        self,
        window_seconds: int = 30,
        port_threshold: int = 8,
        syn_flood_threshold: int = 100,
    ):
        self.window = window_seconds
        self.port_threshold = port_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self._ports: dict[str, deque] = defaultdict(deque)  # ip -> [(ts, dport)]
        self._syns: dict[str, deque] = defaultdict(deque)   # ip -> [ts]
        self._alerted: dict[tuple[str, str], float] = {}

    def process(
        self,
        src_ip: str,
        dst_ip: str,
        dport: int,
        ts: float | None = None,
    ) -> list[dict]:
        ts = ts if ts is not None else time.time()
        alerts: list[dict] = []

        self._prune_ports(self._ports[src_ip])
        self._ports[src_ip].append((ts, dport))

        self._prune_times(self._syns[src_ip])
        self._syns[src_ip].append(ts)

        distinct = {p for _, p in self._ports[src_ip]}
        if len(distinct) >= self.port_threshold and self._ok("sweep", src_ip):
            alerts.append(
                {
                    "severity": "high",
                    "type": "port_scan",
                    "source_ip": src_ip,
                    "description": (
                        f"Port scan detected: {len(distinct)} distinct ports"
                        f" from {src_ip} in the last {self.window}s"
                    ),
                }
            )

        syn_count = len(self._syns[src_ip])
        if syn_count >= self.syn_flood_threshold and self._ok("flood", src_ip):
            alerts.append(
                {
                    "severity": "high",
                    "type": "syn_flood",
                    "source_ip": src_ip,
                    "description": (
                        f"SYN flood detected: {syn_count} SYNs from {src_ip}"
                        f" in the last {self.window}s"
                    ),
                }
            )

        return alerts

    def _prune_ports(self, dq: deque) -> None:
        cutoff = time.time() - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _prune_times(self, dq: deque) -> None:
        cutoff = time.time() - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _ok(self, kind: str, src_ip: str) -> bool:
        now = time.time()
        key = (kind, src_ip)
        last = self._alerted.get(key, 0.0)
        if now - last < self.window:
            return False
        self._alerted[key] = now
        return True

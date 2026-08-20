"""Lightweight IP classification (offline). Optional MaxMind mmdb hook."""
from __future__ import annotations

import ipaddress


def classify_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved:
        return "private"
    if a.is_multicast:
        return "multicast"
    return "public"


def geo_lookup(ip: str, mmdb_path: str | None = None) -> dict:
    """Best-effort offline geo lookup.

    If a MaxMind GeoLite2 .mmdb file is available at mmdb_path, it is used;
    otherwise a lightweight classification is returned.
    """
    result = {"ip": ip, "scope": classify_ip(ip)}
    if not mmdb_path:
        return result
    try:
        import geoip2.database  # optional dependency

        with geoip2.database.Reader(mmdb_path) as reader:
            resp = reader.city(ip)
            result["country"] = resp.country.iso_code
            result["city"] = resp.city.name
    except Exception:  # noqa: BLE001 - geoip2 is optional
        pass
    return result

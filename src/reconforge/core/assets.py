"""Thread-safe store of assets discovered during a scan, shared between modules."""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Optional, Set

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


class AssetStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: Dict[str, Set[str]] = {}          # hostname -> sources
        self._ips: Dict[str, Dict[str, Any]] = {}      # ip -> {"hosts": set, "meta": dict}
        self._resolution: Dict[str, str] = {}          # hostname -> "ok" | "nxdomain" | "empty"

    # -- hostnames ----------------------------------------------------------
    def add_host(self, host: str, source: str = "") -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if host.startswith("*.") or not _HOST_RE.match(host):
            return False
        with self._lock:
            new = host not in self._hosts
            self._hosts.setdefault(host, set()).add(source)
            return new

    def hosts(self) -> List[str]:
        with self._lock:
            return sorted(self._hosts)

    def host_sources(self, host: str) -> List[str]:
        with self._lock:
            return sorted(self._hosts.get(host, ()))

    # -- resolution state (set by host_resolve) -----------------------------
    def set_resolution(self, host: str, state: str) -> None:
        with self._lock:
            self._resolution[host] = state

    def resolution(self, host: str) -> Optional[str]:
        with self._lock:
            return self._resolution.get(host)

    # -- IPs ------------------------------------------------------------------
    def add_ip(self, ip: str, host: str = "", source: str = "") -> bool:
        with self._lock:
            new = ip not in self._ips
            entry = self._ips.setdefault(ip, {"hosts": set(), "meta": {}, "sources": set()})
            if host:
                entry["hosts"].add(host)
            if source:
                entry["sources"].add(source)
            return new

    def ips(self) -> List[str]:
        with self._lock:
            return sorted(self._ips)

    def ip_hosts(self, ip: str) -> List[str]:
        with self._lock:
            return sorted(self._ips.get(ip, {}).get("hosts", ()))

    def set_ip_meta(self, ip: str, **kw: Any) -> None:
        with self._lock:
            self._ips.setdefault(ip, {"hosts": set(), "meta": {}, "sources": set()})["meta"].update(kw)

    def ip_meta(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            return dict(self._ips.get(ip, {}).get("meta", {}))

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "hostnames": [{"host": h, "sources": sorted(s), "resolution": self._resolution.get(h, "")}
                              for h, s in sorted(self._hosts.items())],
                "ips": [{"ip": ip, "hosts": sorted(e["hosts"]), **e["meta"]}
                        for ip, e in sorted(self._ips.items())],
            }

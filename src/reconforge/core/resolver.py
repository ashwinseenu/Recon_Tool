"""DNS resolution that never leaks.

With an anonymity layer on, queries go out as DNS-over-HTTPS through the same
Tor/proxy path as everything else. The system resolver is only used in direct
mode (or when explicitly forced with dns.mode=system and fail_closed off).
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

from .chain import AnonymityError
from .config import Settings
from .netclient import build_client
from .ratelimit import RateLimiter

RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
          "DS": 43, "CAA": 257}
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass
class DnsAnswer:
    records: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)   # CNAME chain seen while resolving
    nxdomain: bool = False
    error: str = ""


def _clean(rtype: str, data: str) -> str:
    if rtype == "TXT":
        chunks = _QUOTED.findall(data)
        return "".join(chunks) if chunks else data.strip('"')
    if rtype in ("CNAME", "NS", "PTR"):
        return data.rstrip(".").lower()
    if rtype == "MX":
        return data.rstrip(".")
    return data


class Resolver:
    def __init__(self, settings: Settings, limiter: Optional[RateLimiter] = None) -> None:
        self.settings = settings
        self.limiter = limiter
        self._cache: Dict[Tuple[str, str], DnsAnswer] = {}
        self._lock = threading.Lock()
        self._client: Optional[httpx.Client] = None

    # -- backend selection ----------------------------------------------------
    @property
    def backend(self) -> str:
        mode = self.settings.dns.mode
        anon = self.settings.proxy.mode != "direct"
        if mode == "auto":
            return "doh" if anon else "system"
        if mode == "system" and anon and self.settings.fail_closed:
            raise AnonymityError("dns.mode=system would leak DNS queries outside the anonymity layer")
        return mode

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # -- public API -----------------------------------------------------------
    def query(self, name: str, rtype: str = "A") -> DnsAnswer:
        name = name.strip().rstrip(".").lower()
        key = (name, rtype)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        if self.limiter:
            self.limiter.throttle("dns")
        ans = self._doh(name, rtype) if self.backend == "doh" else self._system(name, rtype)
        if not ans.error:
            with self._lock:
                self._cache[key] = ans
        return ans

    def ips(self, name: str) -> List[str]:
        out: List[str] = []
        for t in ("A", "AAAA"):
            out += self.query(name, t).records
        return out

    # -- DoH ------------------------------------------------------------------
    def _doh(self, name: str, rtype: str) -> DnsAnswer:
        with self._lock:
            if self._client is None:
                self._client = build_client(self.settings, module="dns", timeout=15)
            client = self._client
        last = "no DoH endpoint reachable"
        for url in self.settings.dns.doh_urls:
            try:
                r = client.get(url, params={"name": name, "type": rtype},
                               headers={"accept": "application/dns-json"})
                r.raise_for_status()
                return self._parse_doh(r.json(), rtype)
            except AnonymityError:
                raise
            except Exception as exc:  # noqa: BLE001
                last = f"{type(exc).__name__}: {exc}"
        return DnsAnswer(error=last)

    @staticmethod
    def _parse_doh(body: dict, rtype: str) -> DnsAnswer:
        status = body.get("Status", 2)
        ans = DnsAnswer(nxdomain=(status == 3))
        if status not in (0, 3):
            ans.error = f"DNS status {status}"
            return ans
        want = RTYPES[rtype]
        for rec in body.get("Answer", []) or []:
            if rec.get("type") == 5:
                ans.cnames.append(_clean("CNAME", rec.get("data", "")))
            elif rec.get("type") == want:
                ans.records.append(_clean(rtype, rec.get("data", "")))
        return ans

    # -- system (direct mode only) -----------------------------------------------
    def _system(self, name: str, rtype: str) -> DnsAnswer:
        import dns.exception
        import dns.resolver

        res = dns.resolver.Resolver()
        res.lifetime = 8
        try:
            answer = res.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(nxdomain=True)
        except dns.resolver.NoAnswer:
            return DnsAnswer()
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            return DnsAnswer(error=type(exc).__name__)
        except Exception as exc:  # noqa: BLE001
            return DnsAnswer(error=f"{type(exc).__name__}: {exc}")
        out = DnsAnswer()
        canonical = str(answer.canonical_name).rstrip(".").lower()
        if canonical != name:
            out.cnames.append(canonical)
        for rr in answer:
            if rtype == "TXT":
                out.records.append(b"".join(rr.strings).decode("utf-8", "replace"))
            else:
                out.records.append(_clean(rtype, rr.to_text()))
        return out

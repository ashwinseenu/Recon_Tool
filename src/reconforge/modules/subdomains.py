"""Passive subdomain aggregation from free datasets (no contact with the target)."""
from __future__ import annotations

from typing import Callable, Dict, List, Set, Tuple

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register
from ..core.scope import is_ip


@register
class Subdomains(ReconModule):
    name = "subdomains"
    description = "Subdomains from HackerTarget, Anubis, OTX passive DNS and (optionally) SecurityTrails."
    phase = 1
    targets = {"domain"}
    optional_key = "securitytrails"

    def gather(self, target: str, result: ModuleResult) -> None:
        found: Dict[str, Set[str]] = {}
        failed: List[str] = []

        def add(host: str, source: str, ip: str = "") -> None:
            host = host.strip().lower()
            if host == target or host.endswith("." + target):
                found.setdefault(host, set()).add(source)
                self.ctx.assets.add_host(host, source)
                if ip:
                    self.ctx.assets.add_ip(ip, host, source)

        with self.client() as c:
            sources: List[Tuple[str, Callable[[], None]]] = [
                ("hackertarget", lambda: self._hackertarget(c, target, add)),
                ("anubis", lambda: self._anubis(c, target, add)),
                ("otx", lambda: self._otx(c, target, add)),
            ]
            if self.key():
                sources.append(("securitytrails", lambda: self._securitytrails(c, target, add)))
            for name, fn in sources:
                try:
                    self.throttle()
                    fn()
                except Exception as exc:  # noqa: BLE001 - one flaky source must not hide the others
                    failed.append(f"{name} ({type(exc).__name__})")

        by_source: Dict[str, int] = {}
        for srcs in found.values():
            for s in srcs:
                by_source[s] = by_source.get(s, 0) + 1
        detail = ", ".join(f"{k}: {v}" for k, v in sorted(by_source.items())) or "no source returned results"
        if failed:
            detail += " | unavailable: " + ", ".join(failed)
        if len(failed) == len(sources):
            raise RuntimeError("all passive sources failed: " + ", ".join(failed))
        result.add(Finding(f"{len(found)} subdomains from passive sources", detail, Severity.INFO,
                           {"subdomains": sorted(found), "by_source": by_source}, host=target))

    @staticmethod
    def _hackertarget(c, target, add):
        r = c.get("https://api.hackertarget.com/hostsearch/", params={"q": target})
        r.raise_for_status()
        if "error" in r.text[:60].lower() or "API count" in r.text[:80]:
            raise RuntimeError(r.text[:80])
        for line in r.text.splitlines():
            host, _, ip = line.partition(",")
            add(host, "hackertarget", ip.strip())

    @staticmethod
    def _anubis(c, target, add):
        r = c.get(f"https://jldc.me/anubis/subdomains/{target}")
        r.raise_for_status()
        for host in r.json():
            add(str(host), "anubis")

    @staticmethod
    def _otx(c, target, add):
        r = c.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns")
        r.raise_for_status()
        for rec in r.json().get("passive_dns", []):
            addr = str(rec.get("address", ""))
            add(str(rec.get("hostname", "")), "otx", addr if is_ip(addr) else "")

    def _securitytrails(self, c, target, add):
        r = c.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains", headers={"APIKEY": self.key()})
        r.raise_for_status()
        for sub in r.json().get("subdomains", []):
            add(f"{sub}.{target}", "securitytrails")

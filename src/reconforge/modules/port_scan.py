"""TCP connect port check (ACTIVE). Only IPs inside scope.allowed_cidrs are ever probed."""
from __future__ import annotations

import concurrent.futures
from typing import List

from ..constants import COMMON_SERVICES, RISKY_PORTS
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.netclient import open_socket
from ..core.registry import register
from ..core.scope import ip_in_scope


@register
class PortScan(ReconModule):
    name = "port_scan"
    description = "TCP connect check of ~55 common service ports on in-scope IPs."
    active = True
    phase = 4

    def _probe(self, ip: str, port: int) -> bool:
        self.throttle()
        try:
            s = open_socket(self.settings, ip, port, self.settings.limits.port_timeout)
            s.close()
            return True
        except Exception:  # noqa: BLE001 - closed/filtered/proxy refusal all mean "not open"
            return False

    def gather(self, target: str, result: ModuleResult) -> None:
        # Resolved IPs may belong to a CDN or shared host, so they must be explicitly inside allowed_cidrs.
        ips = [ip for ip in self.ctx.assets.ips() if ip_in_scope(ip, self.settings.scope)]
        ips = ips[: self.settings.limits.max_ips]
        if not ips:
            result.skipped, result.skip_reason = True, (
                "no discovered IP is inside scope.allowed_cidrs (resolved IPs are never scanned implicitly)")
            return
        ports: List[int] = self.settings.limits.ports
        for ip in ips:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.settings.limits.port_workers) as pool:
                states = list(pool.map(lambda p: self._probe(ip, p), ports))
            open_ports = [p for p, ok in zip(ports, states) if ok]
            if not open_ports:
                result.add(Finding(f"No open ports among {len(ports)} checked on {ip}", "", Severity.INFO, {"ip": ip}, host=ip))
                continue
            risky = [p for p in open_ports if p in RISKY_PORTS]
            label = ", ".join(f"{p}/{COMMON_SERVICES.get(p, RISKY_PORTS.get(p, ('?',))[0])}" for p in open_ports)
            result.add(Finding(f"{len(open_ports)} open ports on {ip}", label, Severity.INFO,
                               {"ip": ip, "open": open_ports, "checked": len(ports)}, host=ip))
            for p in risky:
                svc, sev, advice = RISKY_PORTS[p]
                result.add(Finding(f"{svc} reachable on {ip}:{p}", f"TCP {p} accepted a connection from the scanner.",
                                   Severity(sev), {"ip": ip, "port": p}, host=ip, remediation=advice))

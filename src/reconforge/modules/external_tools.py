"""Optional integrations with installed command-line tools.

subfinder / amass are Go binaries and only run with --direct (see core/external.py).
nmap is wrapped in proxychains when an anonymity mode is on.
"""
from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import List

from ..constants import RISKY_PORTS
from ..core.external import run_tool
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register


class _SubdomainTool(ReconModule):
    phase = 1
    targets = {"domain"}
    args: List[str] = []

    def gather(self, target: str, result: ModuleResult) -> None:
        proc = run_tool(self.settings, self.name, [*self.args, target], timeout=420)
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError((proc.stderr or "no output").strip()[:200])
        hosts = {ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip().endswith(target)}
        for h in hosts:
            self.ctx.assets.add_host(h, self.name)
        result.add(Finding(f"{len(hosts)} subdomains from {self.name}", ", ".join(sorted(hosts)[:30]), Severity.INFO,
                           {"subdomains": sorted(hosts)}, host=target))


@register
class Subfinder(_SubdomainTool):
    name = "subfinder"
    description = "Passive subdomain discovery via the subfinder binary (--direct only)."
    external_tool = "subfinder"
    args = ["-silent", "-d"]


@register
class Amass(_SubdomainTool):
    name = "amass"
    description = "Passive subdomain discovery via the amass binary (--direct only)."
    external_tool = "amass"
    args = ["enum", "-passive", "-silent", "-d"]


@register
class Nmap(ReconModule):
    name = "nmap"
    description = "Service/version detection (nmap -sT -sV) on in-scope IPs."
    active = True
    phase = 4
    external_tool = "nmap"

    def gather(self, target: str, result: ModuleResult) -> None:
        ips = [ip for ip in self.ctx.assets.ips() if self.in_scope(ip)][: self.settings.limits.max_ips]
        if not ips:
            result.skipped, result.skip_reason = True, "no discovered IP is inside scope.allowed_cidrs"
            return
        for ip in ips:
            ipaddress.ip_address(ip)  # validate before it reaches argv
            proc = run_tool(self.settings, "nmap", ["-Pn", "-sT", "-sV", "--version-light", "--top-ports", "100",
                                                    "--open", "-T3", "-oX", "-", ip], timeout=900)
            if not proc.stdout.strip().startswith("<?xml"):
                raise RuntimeError((proc.stderr or "nmap produced no XML").strip()[:200])
            rows = []
            for port in ET.fromstring(proc.stdout).iter("port"):
                svc = port.find("service")
                num = int(port.get("portid", 0))
                rows.append({"port": num, "proto": port.get("protocol"), "service": svc.get("name") if svc is not None else "",
                             "product": " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""})
            if not rows:
                continue
            risky = [r for r in rows if r["port"] in RISKY_PORTS]
            result.add(Finding(f"nmap: {len(rows)} open ports on {ip}",
                               "; ".join(f"{r['port']}/{r['proto']} {r['service']} {r['product']}".strip() for r in rows)[:600],
                               Severity.HIGH if risky else Severity.INFO, {"ip": ip, "ports": rows}, host=ip,
                               remediation="Close or firewall services that do not need internet exposure." if risky else ""))

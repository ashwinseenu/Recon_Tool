"""Internet-exposure datasets for discovered IPs: Shodan InternetDB (free), Shodan API, AbuseIPDB.

All passive: they query third-party datasets, they never touch the target.
"""
from __future__ import annotations

from typing import Dict, List

from ..constants import RISKY_PORTS
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register


def port_findings(ip: str, ports: List[int], source: str) -> List[Finding]:
    out = []
    risky = [p for p in ports if p in RISKY_PORTS]
    sev = Severity.INFO
    for p in risky:
        sev = max(sev, Severity(RISKY_PORTS[p][1]), key=lambda s: s.rank)
    out.append(Finding(f"{source}: {len(ports)} open ports on {ip}", "Ports: " + ", ".join(map(str, sorted(ports))),
                       Severity.INFO if not risky else sev, {"ip": ip, "ports": sorted(ports), "source": source}, host=ip))
    for p in risky:
        svc, severity, advice = RISKY_PORTS[p]
        out.append(Finding(f"{svc} exposed on {ip}:{p}", f"{source} reports port {p} ({svc}) open to the internet.",
                           Severity(severity), {"ip": ip, "port": p}, host=ip, remediation=advice))
    return out


@register
class InternetDb(ReconModule):
    name = "internetdb"
    description = "Open ports, CPEs, tags and CVEs from Shodan InternetDB (free, no key)."
    phase = 3

    def gather(self, target: str, result: ModuleResult) -> None:
        ips = self.ctx.assets.ips()[: self.settings.limits.max_ips]
        missing = ok = 0
        with self.client() as c:
            for ip in ips:
                self.throttle()
                r = c.get(f"https://internetdb.shodan.io/{ip}")
                if r.status_code == 404:
                    missing += 1
                    continue
                r.raise_for_status()
                ok += 1
                d = r.json()
                ports, vulns = d.get("ports", []), d.get("vulns", [])
                if ports:
                    for f in port_findings(ip, ports, "InternetDB"):
                        result.add(f)
                if vulns:
                    result.add(Finding(f"{len(vulns)} known CVEs on {ip}", ", ".join(sorted(vulns)[:25]), Severity.HIGH,
                                       {"ip": ip, "cves": sorted(vulns), "cpes": d.get("cpes", [])}, host=ip,
                                       remediation="Patch or isolate the affected service. Verify applicability: InternetDB matches banners, not exploitability."))
                if d.get("tags"):
                    result.add(Finding(f"Tags for {ip}", ", ".join(d["tags"]), Severity.INFO, {"ip": ip, "tags": d["tags"]}, host=ip))
        result.add(Finding("InternetDB coverage", f"{ok} IPs with data, {missing} without (no exposed services indexed).",
                           Severity.INFO, {"with_data": ok, "without": missing}, host=target))


@register
class Shodan(ReconModule):
    name = "shodan"
    description = "Detailed host data (banners, org, OS, vulns) from the Shodan API."
    phase = 3
    requires_key = "shodan"

    def gather(self, target: str, result: ModuleResult) -> None:
        with self.client() as c:
            for ip in self.ctx.assets.ips()[: self.settings.limits.max_ips]:
                self.throttle()
                r = c.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": self.key()})
                if r.status_code == 404:
                    continue
                if r.status_code in (401, 402, 403):
                    raise RuntimeError(f"Shodan API refused the request (HTTP {r.status_code}): check key/plan")
                r.raise_for_status()
                d = r.json()
                ports = d.get("ports", [])
                for f in port_findings(ip, ports, "Shodan"):
                    result.add(f)
                result.add(Finding(f"Shodan host {ip}", f"Org {d.get('org', '?')} | OS {d.get('os') or '?'} | ISP {d.get('isp', '?')}",
                                   Severity.INFO, {"ip": ip, "org": d.get("org"), "hostnames": d.get("hostnames", []),
                                                   "last_update": d.get("last_update")}, host=ip))
                if d.get("vulns"):
                    result.add(Finding(f"{len(d['vulns'])} CVEs reported by Shodan on {ip}", ", ".join(sorted(d["vulns"])[:25]),
                                       Severity.HIGH, {"ip": ip, "cves": sorted(d["vulns"])}, host=ip,
                                       remediation="Patch or isolate the affected service."))


@register
class AbuseIpdb(ReconModule):
    name = "abuseipdb"
    description = "Abuse confidence score and report history for discovered IPs."
    phase = 3
    requires_key = "abuseipdb"

    def gather(self, target: str, result: ModuleResult) -> None:
        with self.client() as c:
            for ip in self.ctx.assets.ips()[: self.settings.limits.max_ips]:
                self.throttle()
                r = c.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": self.key(), "Accept": "application/json"},
                          params={"ipAddress": ip, "maxAgeInDays": 90})
                r.raise_for_status()
                d: Dict = r.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                sev = Severity.HIGH if score >= 50 else (Severity.MEDIUM if score >= 10 else Severity.INFO)
                result.add(Finding(f"AbuseIPDB score {score}% for {ip}",
                                   f"{d.get('totalReports', 0)} reports | ISP {d.get('isp', '?')} | {d.get('countryCode', '?')}",
                                   sev, {"ip": ip, "score": score, "reports": d.get("totalReports"),
                                         "usage": d.get("usageType")}, host=ip,
                                   remediation="Investigate whether this host is compromised or shares an abused range." if sev.rank >= 2 else ""))

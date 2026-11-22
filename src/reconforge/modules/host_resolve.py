"""Resolve discovered hostnames; flag dangling CNAMEs (subdomain-takeover candidates). Passive DNS only."""
from __future__ import annotations

import concurrent.futures

from ..constants import TAKEOVER_SERVICES
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register


def takeover_service(cname: str) -> str:
    for suffix, service in TAKEOVER_SERVICES:
        if cname.endswith(suffix) or suffix in cname and suffix.startswith("s3-website"):
            return service
    return ""


@register
class HostResolve(ReconModule):
    name = "host_resolve"
    description = "Resolve discovered hostnames to IPs and detect dangling CNAMEs."
    phase = 2
    targets = {"domain"}

    def gather(self, target: str, result: ModuleResult) -> None:
        hosts = self.ctx.assets.hosts()[: self.settings.limits.max_hosts]
        resolved, stale, dangling, third_party, failures = [], [], [], [], 0

        def work(host: str):
            return host, self.ctx.resolver.query(host, "A")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for host, ans in pool.map(work, hosts):
                if ans.error:
                    failures += 1
                    continue
                cname = ans.cnames[-1] if ans.cnames else ""
                service = takeover_service(cname) if cname else ""
                if ans.records:
                    self.ctx.assets.set_resolution(host, "ok")
                    for ip in ans.records:
                        self.ctx.assets.add_ip(ip, host, "host_resolve")
                    resolved.append({"host": host, "ips": ans.records, "cname": cname})
                    if service:
                        third_party.append({"host": host, "cname": cname, "service": service})
                elif cname and ans.nxdomain:
                    self.ctx.assets.set_resolution(host, "nxdomain")
                    dangling.append({"host": host, "cname": cname, "service": service or "unknown"})
                elif ans.nxdomain:
                    self.ctx.assets.set_resolution(host, "nxdomain")
                    stale.append(host)
                else:
                    self.ctx.assets.set_resolution(host, "empty")
                    stale.append(host)
        if hosts and failures == len(hosts):
            raise RuntimeError("every DNS lookup failed")

        result.add(Finding(f"{len(resolved)}/{len(hosts)} hostnames resolve",
                           f"{len(self.ctx.assets.ips())} unique IPs; {len(stale)} names do not resolve.",
                           Severity.INFO, {"resolved": resolved, "stale": stale}, host=target))
        for d in dangling:
            sev = Severity.HIGH if d["service"] != "unknown" else Severity.MEDIUM
            result.add(Finding(f"Dangling CNAME: {d['host']}", f"{d['host']} -> {d['cname']} (target does not exist; {d['service']})",
                               sev, d, host=d["host"],
                               remediation="Remove the DNS record, or re-claim the target resource, to prevent subdomain takeover."))
        if third_party:
            result.add(Finding(f"{len(third_party)} hostnames point at third-party platforms",
                               "; ".join(f"{t['host']} -> {t['service']}" for t in third_party[:15]), Severity.LOW,
                               {"hosts": third_party},
                               remediation="Confirm each external resource is still owned and in use."))

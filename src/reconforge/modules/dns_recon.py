"""DNS records and basic DNS hygiene (passive; resolves via DoH when anonymised)."""
from __future__ import annotations

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register
from ..core.scope import registered_domain

TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "DS"]


@register
class DnsRecon(ReconModule):
    name = "dns"
    description = "A/AAAA/CNAME/NS/MX/TXT/SOA/CAA records plus DNSSEC and CAA hygiene."
    phase = 1
    targets = {"domain"}

    def gather(self, target: str, result: ModuleResult) -> None:
        res = self.ctx.resolver
        records, errors = {}, []
        for rtype in TYPES:
            ans = res.query(target, rtype)
            if ans.error:
                errors.append(f"{rtype}: {ans.error}")
            elif ans.records:
                records[rtype] = ans.records
        if errors and not records:
            raise RuntimeError("; ".join(errors[:3]))

        for rtype, vals in records.items():
            result.add(Finding(f"{rtype} records", "; ".join(vals)[:600], Severity.INFO,
                               {"type": rtype, "values": vals}, host=target))

        assets = self.ctx.assets
        for ip in records.get("A", []) + records.get("AAAA", []):
            assets.add_ip(ip, target, "dns")
        related = records.get("NS", []) + [m.split()[-1].rstrip(".") for m in records.get("MX", [])]
        for host in related:
            if host.endswith("." + target) or host == target:
                assets.add_host(host, "dns")

        if not any(t in records for t in ("A", "AAAA", "CNAME")):
            result.add(Finding("Name does not resolve", f"No address records for {target}.", Severity.INFO, host=target))

        if registered_domain(target) == target:   # apex-only hygiene checks
            if "CAA" not in records:
                result.add(Finding("No CAA record", "Any certificate authority may issue certificates for this domain.",
                                   Severity.LOW, host=target,
                                   remediation="Publish CAA records restricting issuance to your CAs."))
            if "DS" not in records:
                result.add(Finding("DNSSEC not enabled", "No DS record at the parent zone.", Severity.INFO, host=target,
                                   remediation="Enable DNSSEC at your registrar/DNS host if supported."))
            if len(records.get("NS", [])) == 1:
                result.add(Finding("Single nameserver", "Only one NS record - no DNS redundancy.", Severity.LOW,
                                   host=target, remediation="Add at least two nameservers on separate networks."))

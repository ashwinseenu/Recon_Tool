"""Per-IP intelligence: ASN/holder (RIPEstat), reverse DNS, hosting provider/CDN detection."""
from __future__ import annotations

import ipaddress

from ..constants import CDN_KEYWORDS
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register


def provider_for(holder: str) -> str:
    h = holder.lower()
    for key, name in CDN_KEYWORDS.items():
        if key in h:
            return name
    return ""


@register
class IpIntel(ReconModule):
    name = "ip_intel"
    description = "ASN, network holder, reverse DNS and hosting/CDN provider for discovered IPs."
    phase = 3

    def gather(self, target: str, result: ModuleResult) -> None:
        ips = self.ctx.assets.ips()[: self.settings.limits.max_ips]
        if not ips:
            result.add(Finding("No IP addresses discovered", "", Severity.INFO, host=target))
            return
        ok = 0
        with self.client() as c:
            for ip in ips:
                self.throttle()
                asn, holder, prefix = "", "", ""
                try:
                    r = c.get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": ip})
                    r.raise_for_status()
                    data = r.json().get("data", {})
                    prefix = data.get("resource", "")
                    asns = data.get("asns") or []
                    if asns:
                        asn, holder = f"AS{asns[0].get('asn')}", asns[0].get("holder", "")
                    ok += 1
                except Exception:  # noqa: BLE001
                    pass
                ptr = self.ctx.resolver.query(ipaddress.ip_address(ip).reverse_pointer, "PTR").records
                provider = provider_for(holder)
                self.ctx.assets.set_ip_meta(ip, asn=asn, holder=holder, prefix=prefix,
                                            ptr=ptr[0] if ptr else "", provider=provider)
                result.add(Finding(f"{ip} - {asn or 'ASN unknown'}",
                                   f"{holder or '?'} | prefix {prefix or '?'} | PTR {ptr[0] if ptr else '-'}"
                                   + (f" | {provider}" if provider else ""),
                                   Severity.INFO, {"ip": ip, "asn": asn, "holder": holder, "prefix": prefix,
                                                   "ptr": ptr, "provider": provider}, host=ip))
        if ok == 0:
            raise RuntimeError("RIPEstat lookups all failed")

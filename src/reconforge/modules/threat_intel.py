"""Threat-intel reputation: AlienVault OTX, VirusTotal and the public HIBP breach list."""
from __future__ import annotations

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register
from ..core.scope import is_ip, registered_domain


@register
class Otx(ReconModule):
    name = "otx"
    description = "AlienVault OTX threat pulses for the domain/IP (works without a key)."
    phase = 1
    optional_key = "otx"

    def gather(self, target: str, result: ModuleResult) -> None:
        section = "IPv6" if (is_ip(target) and ":" in target) else ("IPv4" if is_ip(target) else "domain")
        headers = {"X-OTX-API-KEY": self.key()} if self.key() else {}
        self.throttle()
        with self.client() as c:
            r = c.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{target}/general", headers=headers)
        if r.status_code != 200:
            result.add(Finding("No OTX data", f"HTTP {r.status_code}", Severity.INFO, host=target))
            return
        info = r.json().get("pulse_info", {})
        count = info.get("count", 0)
        names = [p.get("name") for p in info.get("pulses", []) if p.get("name")][:10]
        sev = Severity.HIGH if count >= 5 else (Severity.MEDIUM if count else Severity.INFO)
        result.add(Finding(f"{count} OTX threat pulses", "; ".join(names)[:600] or "No pulses reference this indicator.",
                           sev, {"pulse_count": count, "pulses": names}, host=target))


@register
class VirusTotal(ReconModule):
    name = "virustotal"
    description = "VirusTotal reputation and known subdomains for the domain/IP."
    phase = 1
    requires_key = "virustotal"

    def gather(self, target: str, result: ModuleResult) -> None:
        kind = "ip_addresses" if is_ip(target) else "domains"
        headers = {"x-apikey": self.key()}
        self.throttle()
        with self.client() as c:
            r = c.get(f"https://www.virustotal.com/api/v3/{kind}/{target}", headers=headers)
            if r.status_code == 404:
                result.add(Finding("No VirusTotal record", target, Severity.INFO, host=target))
                return
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            subs = []
            if kind == "domains":
                self.throttle()
                sr = c.get(f"https://www.virustotal.com/api/v3/domains/{target}/subdomains", headers=headers,
                           params={"limit": 40})
                if sr.status_code == 200:
                    subs = [d.get("id", "") for d in sr.json().get("data", [])]
                    for s in subs:
                        self.ctx.assets.add_host(s, "virustotal")
        stats = attrs.get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        sev = Severity.HIGH if mal >= 3 else (Severity.MEDIUM if mal or sus else Severity.INFO)
        result.add(Finding(f"VirusTotal: {mal} malicious / {sus} suspicious",
                           f"Reputation {attrs.get('reputation', '?')} | {len(subs)} subdomains listed", sev,
                           {"stats": stats, "categories": attrs.get("categories", {}), "subdomains": subs}, host=target))


@register
class HibpBreaches(ReconModule):
    name = "hibp_breaches"
    description = "Public Have I Been Pwned breaches OF services hosted on this domain (no key needed)."
    phase = 1
    targets = {"domain"}

    def gather(self, target: str, result: ModuleResult) -> None:
        domain = registered_domain(target)
        self.throttle()
        with self.client() as c:
            r = c.get("https://haveibeenpwned.com/api/v3/breaches", params={"domain": domain})
        r.raise_for_status()
        breaches = r.json()
        if not breaches:
            result.add(Finding("No public breaches of this domain's services", domain, Severity.INFO, host=domain))
            return
        total = sum(b.get("PwnCount", 0) for b in breaches)
        names = [f"{b.get('Name')} ({b.get('BreachDate')})" for b in breaches]
        result.add(Finding(f"{len(breaches)} public breaches of services on {domain}", "; ".join(names)[:600],
                           Severity.HIGH if total >= 100000 else Severity.MEDIUM,
                           {"breaches": names, "accounts": total}, host=domain,
                           remediation="Confirm credential resets and notification obligations were met."))

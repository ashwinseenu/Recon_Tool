"""Registration data via RDAP over HTTPS (replaces port-43 WHOIS, which cannot be anonymised)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register
from ..core.scope import is_ip, registered_domain


def parse_date(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _events(body: dict) -> dict:
    return {e.get("eventAction"): e.get("eventDate") for e in body.get("events", []) if e.get("eventAction")}


def _registrar(body: dict) -> str:
    for ent in body.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for prop in (ent.get("vcardArray") or [None, []])[1]:
                if prop and prop[0] == "fn":
                    return str(prop[3])
    return ""


@register
class Rdap(ReconModule):
    name = "rdap"
    description = "Registrar, dates, status and nameservers (domains); network owner and range (IPs)."
    phase = 1

    def gather(self, target: str, result: ModuleResult) -> None:
        subject = target if is_ip(target) else registered_domain(target)
        kind = "ip" if is_ip(target) else "domain"
        with self.client() as c:
            r = c.get(f"https://rdap.org/{kind}/{subject}")
        if r.status_code == 404:
            result.add(Finding("No RDAP data", f"No RDAP record for {subject} (the TLD may not support RDAP).", Severity.INFO))
            return
        r.raise_for_status()
        body = r.json()
        if kind == "ip":
            cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in body.get("cidr0_cidrs", [])]
            result.add(Finding(f"Network {body.get('name', '?')}",
                               f"Range {body.get('startAddress')} - {body.get('endAddress')} | country {body.get('country', '?')}"
                               f" | {', '.join(cidrs)}", Severity.INFO,
                               {"name": body.get("name"), "handle": body.get("handle"), "country": body.get("country"),
                                "cidrs": cidrs}, host=target))
            return
        ev = _events(body)
        registrar = _registrar(body)
        ns = [n.get("ldhName", "").lower() for n in body.get("nameservers", [])]
        status = body.get("status", [])
        result.add(Finding(f"Registration of {subject}",
                           f"Registrar: {registrar or '?'} | registered {ev.get('registration', '?')} | "
                           f"expires {ev.get('expiration', '?')}", Severity.INFO,
                           {"registrar": registrar, "events": ev, "status": status, "nameservers": ns}, host=subject))
        exp = parse_date(ev.get("expiration", "")) if ev.get("expiration") else None
        if exp:
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                result.add(Finding("Domain registration has expired", f"Expired {-days} days ago.", Severity.CRITICAL,
                                   host=subject, remediation="Renew immediately."))
            elif days <= 30:
                result.add(Finding(f"Domain expires in {days} days", ev.get("expiration", ""), Severity.HIGH,
                                   host=subject, remediation="Renew and enable auto-renew."))
            elif days <= 60:
                result.add(Finding(f"Domain expires in {days} days", ev.get("expiration", ""), Severity.MEDIUM,
                                   host=subject, remediation="Renew and enable auto-renew."))
        if status and not any("transferprohibited" in s.replace(" ", "").lower() for s in status):
            result.add(Finding("No registrar transfer lock", f"Status: {', '.join(status)}", Severity.LOW, host=subject,
                               remediation="Enable the registrar transfer lock (clientTransferProhibited)."))

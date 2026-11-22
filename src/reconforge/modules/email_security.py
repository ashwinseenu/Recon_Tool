"""Email authentication posture: SPF, DMARC, DKIM (common selectors), MTA-STS, TLS-RPT."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register
from ..core.scope import registered_domain

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp"]
_ALL = re.compile(r"(?:^|\s)([+\-~?]?)all(?:\s|$)")
_LOOKUP = re.compile(r"(?:^|\s)[+\-~?]?(include:|a(?::|\s|$)|mx(?::|\s|$)|ptr|exists:|redirect=)")


def parse_tags(record: str) -> Dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyse_spf(records: List[str]) -> List[Finding]:
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return [Finding("No SPF record", "Receivers cannot verify which servers may send mail for this domain.",
                        Severity.MEDIUM, remediation="Publish an SPF TXT record, e.g. 'v=spf1 include:<provider> -all'.")]
    out: List[Finding] = []
    if len(spf) > 1:
        out.append(Finding("Multiple SPF records", "More than one SPF record makes SPF evaluation fail (permerror).",
                           Severity.MEDIUM, remediation="Merge into a single SPF record."))
    rec = spf[0]
    m = _ALL.search(rec)
    qual = m.group(1) if m else None
    if m is None:
        out.append(Finding("SPF has no 'all' mechanism", rec, Severity.LOW, remediation="End the record with -all or ~all."))
    elif qual in ("", "+"):
        out.append(Finding("SPF allows any sender (+all)", rec, Severity.HIGH,
                           remediation="Replace '+all' with '-all' (or '~all' while testing)."))
    elif qual == "?":
        out.append(Finding("SPF is neutral (?all)", rec, Severity.MEDIUM, remediation="Use -all or ~all."))
    elif qual == "~":
        out.append(Finding("SPF soft-fail (~all)", rec, Severity.INFO, remediation="Move to -all once senders are verified."))
    else:
        out.append(Finding("SPF hard-fail (-all)", rec, Severity.INFO))
    lookups = len(_LOOKUP.findall(rec))
    if lookups > 10:
        out.append(Finding("SPF exceeds the 10 DNS-lookup limit", f"~{lookups} lookup mechanisms in the top-level record.",
                           Severity.MEDIUM, remediation="Flatten or reduce include: mechanisms."))
    return out


def analyse_dmarc(records: List[str]) -> List[Finding]:
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [Finding("No DMARC record", "The domain can be spoofed in email without receivers enforcing policy.",
                        Severity.MEDIUM, remediation="Publish _dmarc TXT 'v=DMARC1; p=quarantine; rua=mailto:...' then move to p=reject.")]
    tags = parse_tags(dmarc[0])
    policy = tags.get("p", "none").lower()
    out = []
    if policy == "none":
        out.append(Finding("DMARC policy is p=none (monitor only)", dmarc[0], Severity.LOW,
                           remediation="Move to p=quarantine, then p=reject, once reports look clean."))
    else:
        out.append(Finding(f"DMARC policy p={policy}", dmarc[0], Severity.INFO))
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy != "none":
        out.append(Finding(f"DMARC applies to only {pct}% of mail", dmarc[0], Severity.LOW,
                           remediation="Raise pct to 100."))
    if "rua" not in tags:
        out.append(Finding("DMARC has no aggregate report address", dmarc[0], Severity.INFO,
                           remediation="Add rua=mailto:... to receive reports."))
    return out


@register
class EmailSecurity(ReconModule):
    name = "email_security"
    description = "SPF, DMARC, DKIM (common selectors), MTA-STS and TLS-RPT posture."
    phase = 1
    targets = {"domain"}

    def _txt(self, name: str) -> Optional[List[str]]:
        ans = self.ctx.resolver.query(name, "TXT")
        if ans.error:
            raise RuntimeError(f"DNS error for {name}: {ans.error}")
        return ans.records

    def gather(self, target: str, result: ModuleResult) -> None:
        apex = registered_domain(target)
        mx = self.ctx.resolver.query(target, "MX").records
        txt = self._txt(target) or []
        spf_findings = analyse_spf(txt)
        # A host with no mail and no SPF is common for web-only subdomains; keep it informational.
        if target != apex and not mx and spf_findings and spf_findings[0].title == "No SPF record":
            spf_findings = []
        for f in spf_findings:
            f.host = target
            result.add(f)

        dmarc = self._txt(f"_dmarc.{target}") or []
        if not dmarc and target != apex:
            dmarc = self._txt(f"_dmarc.{apex}") or []
        if dmarc or target == apex or mx:
            for f in analyse_dmarc(dmarc):
                f.host = target
                result.add(f)

        if not mx:
            result.add(Finding("No MX records", "The domain does not receive mail.", Severity.INFO, host=target))
            return
        found = [s for s in DKIM_SELECTORS if self.ctx.resolver.query(f"{s}._domainkey.{target}", "TXT").records]
        result.add(Finding("DKIM selectors found" if found else "No DKIM at common selectors",
                           ", ".join(found) if found else "Custom selectors may still exist; this is not conclusive.",
                           Severity.INFO, {"selectors": found}, host=target))
        sts = [r for r in (self._txt(f"_mta-sts.{target}") or []) if r.lower().startswith("v=stsv1")]
        if not sts:
            result.add(Finding("MTA-STS not configured", "Inbound mail TLS is not enforced via MTA-STS.", Severity.LOW,
                               host=target, remediation="Publish _mta-sts TXT and a policy file."))
        if not [r for r in (self._txt(f"_smtp._tls.{target}") or []) if r.lower().startswith("v=tlsrptv1")]:
            result.add(Finding("TLS-RPT not configured", "No SMTP TLS failure reporting address.", Severity.INFO, host=target))

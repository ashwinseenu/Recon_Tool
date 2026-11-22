"""Certificate Transparency mining via crt.sh (passive)."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register


@register
class CertTransparency(ReconModule):
    name = "cert_transparency"
    description = "Hostnames and issuers seen in public CT logs (crt.sh)."
    phase = 1
    targets = {"domain"}

    def gather(self, target: str, result: ModuleResult) -> None:
        self.throttle()
        with self.client(timeout=60) as c:
            r = c.get("https://crt.sh/", params={"q": f"%.{target}", "output": "json"})
        if r.status_code != 200:
            raise RuntimeError(f"crt.sh returned HTTP {r.status_code}")
        try:
            rows = r.json()
        except ValueError as exc:
            raise RuntimeError("crt.sh returned a non-JSON response (service busy)") from exc

        names, wildcards, issuers, recent = set(), set(), set(), set()
        cutoff = time.time() - 30 * 86400
        for row in rows:
            issuers.add(row.get("issuer_name", ""))
            issued = row.get("not_before", "")
            try:
                is_recent = datetime.fromisoformat(issued).replace(tzinfo=timezone.utc).timestamp() > cutoff
            except ValueError:
                is_recent = False
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower()
                if not n or not (n == target or n.endswith("." + target) or n.endswith(".*." + target)):
                    continue
                if n.startswith("*."):
                    wildcards.add(n)
                    continue
                names.add(n)
                if is_recent:
                    recent.add(n)
        for n in names:
            self.ctx.assets.add_host(n, "ct")

        result.add(Finding(f"{len(names)} hostnames in CT logs", ", ".join(sorted(names)[:40]) + (" ..." if len(names) > 40 else ""),
                           Severity.INFO, {"hostnames": sorted(names), "issuers": sorted(i for i in issuers if i)}, host=target))
        if wildcards:
            result.add(Finding(f"{len(wildcards)} wildcard certificates", ", ".join(sorted(wildcards)[:10]), Severity.INFO,
                               {"wildcards": sorted(wildcards)}, host=target))
        if recent:
            result.add(Finding(f"{len(recent)} hostnames got certificates in the last 30 days",
                               ", ".join(sorted(recent)[:20]), Severity.INFO, {"hostnames": sorted(recent)}, host=target))

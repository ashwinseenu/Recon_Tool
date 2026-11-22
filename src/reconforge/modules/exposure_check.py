"""Well-known exposure indicators (ACTIVE).

A short, fixed list of paths that should never be public. Each is one GET with a
byte-range header and no redirects; content is matched against a signature and
never stored or displayed (so secrets cannot leak into reports).
"""
from __future__ import annotations

import re
from typing import Callable, List, NamedTuple

from ..core.http import fetch_limited
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register


class Check(NamedTuple):
    path: str
    title: str
    severity: Severity
    match: Callable[[int, str, bytes], bool]
    fix: str


def _json_like(body: bytes) -> bool:
    return body.lstrip()[:1] in (b"{", b"[")


CHECKS: List[Check] = [
    Check("/.git/HEAD", "Git repository exposed", Severity.HIGH,
          lambda s, ct, b: s == 200 and b.startswith(b"ref:"),
          "Block access to /.git and remove it from the web root."),
    Check("/.env", "Environment file exposed", Severity.CRITICAL,
          lambda s, ct, b: s == 200 and "html" not in ct and bool(re.search(rb"^[A-Z][A-Z0-9_]{2,}=", b, re.M)),
          "Remove .env from the web root and rotate every secret it contained."),
    Check("/.svn/entries", "Subversion metadata exposed", Severity.HIGH,
          lambda s, ct, b: s == 200 and "html" not in ct and len(b) > 0,
          "Block access to /.svn and remove it from the web root."),
    Check("/.DS_Store", ".DS_Store file exposed", Severity.MEDIUM,
          lambda s, ct, b: s == 200 and b.startswith(b"\x00\x00\x00\x01Bud1"),
          "Delete .DS_Store files from deployments."),
    Check("/server-status", "Apache server-status exposed", Severity.MEDIUM,
          lambda s, ct, b: s == 200 and b"Apache Server Status" in b,
          "Restrict mod_status to localhost/management networks."),
    Check("/phpinfo.php", "phpinfo() page exposed", Severity.HIGH,
          lambda s, ct, b: s == 200 and b"phpinfo()" in b,
          "Remove phpinfo pages from production."),
    Check("/actuator/env", "Spring Boot actuator /env exposed", Severity.HIGH,
          lambda s, ct, b: s == 200 and _json_like(b) and b"propertySources" in b,
          "Disable or authenticate actuator endpoints."),
    Check("/actuator", "Spring Boot actuator index exposed", Severity.MEDIUM,
          lambda s, ct, b: s == 200 and _json_like(b) and b"_links" in b,
          "Restrict actuator endpoints to management networks."),
    Check("/.well-known/security.txt", "security.txt present", Severity.INFO,
          lambda s, ct, b: s == 200 and b"Contact:" in b, ""),
]


@register
class ExposureCheck(ReconModule):
    name = "exposure_check"
    description = "Checks nine well-known paths (.git, .env, phpinfo, actuator, ...) for accidental exposure."
    active = True
    phase = 4

    def gather(self, target: str, result: ModuleResult) -> None:
        hosts = self.web_hosts(min(self.settings.limits.max_web_hosts, 10))
        if not hosts:
            result.skipped, result.skip_reason = True, "no in-scope hosts to probe"
            return
        with_security_txt = 0
        with self.client(verify=False, follow_redirects=False) as c:
            for host in hosts:
                scheme = "https"
                for chk in CHECKS:
                    self.throttle()
                    try:
                        page = fetch_limited(c, f"{scheme}://{host}{chk.path}", max_bytes=1024, headers={"Range": "bytes=0-1023"})
                    except Exception:  # noqa: BLE001
                        if chk is CHECKS[0]:
                            break  # host not reachable over HTTPS; skip remaining paths
                        continue
                    ct = page.headers.get("content-type", "").lower()
                    if not chk.match(page.status if page.status != 206 else 200, ct, page.body):
                        continue
                    if chk.severity is Severity.INFO:
                        with_security_txt += 1
                        continue
                    result.add(Finding(f"{chk.title}: {host}{chk.path}", "Matched a content signature; contents not stored.",
                                       chk.severity, {"host": host, "path": chk.path}, host=host, remediation=chk.fix))
        if with_security_txt == 0:
            result.add(Finding("No security.txt published", "No /.well-known/security.txt found on probed hosts.", Severity.INFO,
                               host=target, remediation="Publish security.txt (RFC 9116) so researchers can report issues."))

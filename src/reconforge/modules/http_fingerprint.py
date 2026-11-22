"""HTTP(S) fingerprinting and security-header review (ACTIVE: connects to in-scope hosts)."""
from __future__ import annotations

import re
from typing import Dict, List

from ..core.http import fetch_limited
from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_VERSIONED = re.compile(r"\d+\.\d+")
TECH_HEADERS = {"server": "Server", "x-powered-by": "Powered by", "x-generator": "Generator",
                "x-aspnet-version": "ASP.NET", "via": "Via", "cf-ray": "Cloudflare",
                "x-amz-cf-id": "CloudFront", "x-served-by": "Fastly/Varnish"}
COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
               "laravel_session": "Laravel", "csrftoken": "Django"}
SEC_HEADERS = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", Severity.LOW,
     "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    ("content-security-policy", "Content-Security-Policy", Severity.LOW,
     "Define a Content-Security-Policy to limit script/content sources."),
    ("x-content-type-options", "X-Content-Type-Options", Severity.LOW, "Send 'X-Content-Type-Options: nosniff'."),
]


def analyse_cookie(raw: str) -> List[str]:
    low = raw.lower()
    problems = []
    if "secure" not in [p.strip() for p in low.split(";")]:
        problems.append("Secure")
    if "httponly" not in low:
        problems.append("HttpOnly")
    if "samesite" not in low:
        problems.append("SameSite")
    return problems


@register
class HttpFingerprint(ReconModule):
    name = "http_fingerprint"
    description = "Status, title, technology hints, security headers, cookie flags and HTTP->HTTPS redirect."
    active = True
    phase = 4

    def gather(self, target: str, result: ModuleResult) -> None:
        hosts = self.web_hosts(self.settings.limits.max_web_hosts)
        if not hosts:
            result.skipped, result.skip_reason = True, "no in-scope hosts to probe"
            return
        rows: List[Dict] = []
        missing: Dict[str, List[str]] = {h[0]: [] for h in SEC_HEADERS}
        disclose, cookie_issues, no_https_redirect, http_only = [], [], [], []

        with self.client(verify=False) as c, self.client(verify=False, follow_redirects=False) as nofollow:
            for host in hosts:
                self.throttle()
                page = None
                for scheme in ("https", "http"):
                    try:
                        page = fetch_limited(c, f"{scheme}://{host}/")
                        break
                    except Exception:  # noqa: BLE001
                        continue
                if page is None:
                    continue
                h = {k.lower(): v for k, v in page.headers.items()}
                title = _TITLE.search(page.text)
                tech = {TECH_HEADERS[k]: h[k] for k in TECH_HEADERS if k in h}
                gen = _GENERATOR.search(page.text)
                if gen:
                    tech["Generator"] = gen.group(1)
                for ck in page.cookies:
                    for needle, name in COOKIE_TECH.items():
                        if ck.lower().startswith(needle):
                            tech.setdefault("Framework", name)
                rows.append({"host": host, "url": page.url, "status": page.status, "title": (title.group(1).strip()[:80] if title else ""),
                             "tech": tech})
                is_https = page.url.startswith("https://")
                if is_https:
                    for key, _, _, _ in SEC_HEADERS:
                        if key not in h:
                            missing[key].append(host)
                    if "frame-ancestors" not in h.get("content-security-policy", "") and "x-frame-options" not in h:
                        missing.setdefault("clickjacking", []).append(host)
                else:
                    http_only.append(host)
                for hdr in ("server", "x-powered-by", "x-aspnet-version"):
                    if hdr in h and _VERSIONED.search(h[hdr]):
                        disclose.append(f"{host}: {hdr}={h[hdr]}")
                bad = [(ck.split("=", 1)[0], analyse_cookie(ck)) for ck in page.cookies]
                cookie_issues += [f"{host}: {n} lacks {', '.join(p)}" for n, p in bad if p and is_https]
                if is_https:
                    try:
                        self.throttle()
                        rr = nofollow.get(f"http://{host}/")
                        loc = rr.headers.get("location", "")
                        if not (300 <= rr.status_code < 400 and loc.startswith("https://")):
                            no_https_redirect.append(host)
                    except Exception:  # noqa: BLE001 - port 80 closed is fine
                        pass

        result.add(Finding(f"{len(rows)}/{len(hosts)} hosts answered over HTTP(S)",
                           "; ".join(f"{r['host']} [{r['status']}] {r['title']}" for r in rows[:12]), Severity.INFO,
                           {"hosts": rows}, host=target))
        if http_only:
            result.add(Finding(f"{len(http_only)} hosts serve content over plain HTTP only", ", ".join(http_only), Severity.MEDIUM,
                               {"hosts": http_only}, remediation="Serve over HTTPS with a valid certificate."))
        if no_https_redirect:
            result.add(Finding(f"{len(no_https_redirect)} hosts do not redirect HTTP to HTTPS", ", ".join(no_https_redirect),
                               Severity.LOW, {"hosts": no_https_redirect}, remediation="Redirect port 80 to HTTPS (301) and enable HSTS."))
        for key, label, sev, fix in SEC_HEADERS:
            if missing[key]:
                result.add(Finding(f"Missing {label} on {len(missing[key])} hosts", ", ".join(missing[key][:15]), sev,
                                   {"hosts": missing[key]}, remediation=fix))
        if missing.get("clickjacking"):
            result.add(Finding(f"No clickjacking protection on {len(missing['clickjacking'])} hosts",
                               ", ".join(missing["clickjacking"][:15]), Severity.LOW, {"hosts": missing["clickjacking"]},
                               remediation="Send X-Frame-Options: DENY or CSP frame-ancestors."))
        if disclose:
            result.add(Finding("Software version disclosure in headers", "; ".join(disclose[:10]), Severity.LOW,
                               {"items": disclose}, remediation="Remove or genericise Server/X-Powered-By version strings."))
        if cookie_issues:
            result.add(Finding("Cookies missing security flags", "; ".join(cookie_issues[:10]), Severity.LOW,
                               {"items": cookie_issues}, remediation="Set Secure, HttpOnly and SameSite on session cookies."))

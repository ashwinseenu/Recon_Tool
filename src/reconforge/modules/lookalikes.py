"""Look-alike (typosquat) domain detection for brand protection (passive DNS only)."""
from __future__ import annotations

import concurrent.futures
import re
from typing import List

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.registry import register
from ..core.scope import _tld

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_KEYS = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
         "p": "ol", "a": "qsz", "s": "awdx", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb",
         "j": "huikmn", "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
         "n": "bhjm", "m": "njk"}
_GLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "m": ["rn"], "w": ["vv"], "d": ["cl"], "b": ["6"]}
_TLDS = ["com", "net", "org", "co", "io", "in", "co.in", "info", "biz", "app", "online", "xyz"]
_AFFIX_PRE = ["secure-", "login-", "my", "www-"]
_AFFIX_POST = ["-login", "-secure", "-support", "-portal", "-online", "app"]


def generate(registered: str) -> List[str]:
    """Candidate look-alike domains for a registered domain, most likely first."""
    ext = _tld(registered)
    label, suffix = ext.domain, ext.suffix
    if not label or not suffix:
        return []
    ordered: List[str] = []

    def push(l: str, s: str = suffix) -> None:
        if l and _LABEL.match(l) and f"{l}.{s}" != registered and f"{l}.{s}" not in ordered:
            ordered.append(f"{l}.{s}")

    for t in _TLDS:                                    # TLD swaps
        push(label, t)
    for i, ch in enumerate(label):                     # homoglyphs
        for g in _GLYPHS.get(ch, []):
            push(label[:i] + g + label[i + 1:])
    for i in range(len(label) - 1):                    # transposition
        push(label[:i] + label[i + 1] + label[i] + label[i + 2:])
    for i in range(len(label)):                        # omission
        push(label[:i] + label[i + 1:])
    for i, ch in enumerate(label):                     # repetition
        push(label[:i] + ch + label[i:])
    for i, ch in enumerate(label):                     # keyboard-adjacent replacement
        for k in _KEYS.get(ch, ""):
            push(label[:i] + k + label[i + 1:])
    for i in range(1, len(label)):                     # hyphenation
        push(label[:i] + "-" + label[i:])
    for a in _AFFIX_PRE:
        push(a + label)
    for p in _AFFIX_POST:
        push(label + p)
    return ordered


@register
class Lookalikes(ReconModule):
    name = "lookalikes"
    description = "Registered look-alike/typosquat domains of your brand (DNS checks only)."
    phase = 1
    targets = {"domain"}

    def gather(self, target: str, result: ModuleResult) -> None:
        from ..core.scope import registered_domain
        apex = registered_domain(target)
        cands = generate(apex)[: self.settings.limits.lookalike_max]
        live, errors = [], 0

        def check(domain: str):
            ans = self.ctx.resolver.query(domain, "A")
            return domain, ans

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for domain, ans in pool.map(check, cands):
                if ans.error:
                    errors += 1
                elif ans.records:
                    live.append({"domain": domain, "ips": ans.records})
        if errors and errors == len(cands):
            raise RuntimeError("every DNS lookup failed")
        if live:
            result.add(Finding(f"{len(live)} look-alike domains resolve", "; ".join(f"{d['domain']} -> {', '.join(d['ips'][:2])}" for d in live[:15]),
                               Severity.MEDIUM, {"domains": live, "checked": len(cands)}, host=apex,
                               remediation="Review each for phishing/brand abuse; file takedowns or register defensively."))
        else:
            result.add(Finding("No resolving look-alike domains found", f"Checked {len(cands)} permutations of {apex}.",
                               Severity.INFO, {"checked": len(cands)}, host=apex))

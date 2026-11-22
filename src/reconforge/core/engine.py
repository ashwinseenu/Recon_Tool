"""Scan orchestrator."""
from __future__ import annotations

import concurrent.futures
import re
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse

from . import registry
from .assets import AssetStore, _HOST_RE
from .config import Settings, load_settings
from .models import ScanReport
from .module_base import ModuleContext
from .netclient import ensure_anonymity, new_tor_circuit
from .ratelimit import RateLimiter
from .resolver import Resolver
from .scope import is_ip, summarize_scope

ProgressCb = Optional[Callable[[str, str, str], None]]  # (module, status, detail)


def normalize_target(raw: str) -> Tuple[str, str]:
    t = (raw or "").strip().lower()
    if "://" in t:
        t = urlparse(t).hostname or ""
    t = t.strip().rstrip(".")
    if is_ip(t):
        return t, "ip"
    try:
        t = t.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    if _HOST_RE.match(t):
        return t, "domain"
    raise ValueError(f"Invalid target {raw!r}: expected a domain name or an IP address")


def _scan_id(target: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{re.sub(r'[^a-z0-9.-]', '_', target)}-{ts}"


def run_scan(target: str, settings: Optional[Settings] = None, only: Optional[List[str]] = None,
             exclude: Optional[List[str]] = None, passive_only: bool = False, max_workers: int = 6,
             progress: ProgressCb = None) -> ScanReport:
    settings = settings or load_settings()
    target, kind = normalize_target(target)
    classes = registry.select(settings, kind, only, exclude, passive_only)

    report = ScanReport(target=target, kind=kind, scan_id=_scan_id(target))
    report.scope = summarize_scope(settings.scope)
    report.options = {"only": only or [], "exclude": exclude or [], "passive_only": passive_only,
                      "proxy_mode": settings.proxy.mode}

    status = ensure_anonymity(settings)           # fail-closed gate
    report.egress = {"mode": status.mode, "egress_ip": status.egress_ip, "is_tor": status.is_tor,
                     "ok": status.ok, "detail": status.detail}
    if settings.tor.new_circuit_per_scan:
        new_tor_circuit(settings)

    assets = AssetStore()
    limiter = RateLimiter(settings.rate_limit)
    resolver = Resolver(settings, limiter)
    if kind == "domain":
        assets.add_host(target, "target")
    else:
        assets.add_ip(target, source="target")
    ctx = ModuleContext(settings=settings, limiter=limiter, resolver=resolver, assets=assets,
                        target=target, kind=kind, passive_only=passive_only)

    def run_one(cls):
        if progress:
            progress(cls.name, "start", "")
        res = cls(ctx).run(target)
        if progress:
            st = "skip" if res.skipped else ("error" if not res.ok else "done")
            progress(cls.name, st, res.skip_reason or res.error)
        return res

    try:
        for phase in sorted({c.phase for c in classes}):
            batch = [c for c in classes if c.phase == phase]
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                report.modules.extend(pool.map(run_one, batch))
    finally:
        resolver.close()

    report.assets = assets.to_dict()
    return report.finish()

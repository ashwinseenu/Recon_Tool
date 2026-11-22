"""Base class and shared context for recon modules.

Phases (modules in a phase run in parallel; phases run in order):
  1 discovery   domain/IP intelligence; adds hostnames and IPs to the asset store
  2 resolution  resolves discovered hostnames to IPs, finds dangling CNAMEs
  3 enrichment  per-IP intelligence (ASN, InternetDB, Shodan, AbuseIPDB)
  4 active      probes the target directly; scope-gated
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import List, Optional

import httpx

from .assets import AssetStore
from .config import Settings
from .models import ModuleResult
from .netclient import build_client
from .ratelimit import RateLimiter
from .resolver import Resolver
from .scope import assert_in_scope, in_scope, scope_empty


@dataclass
class ModuleContext:
    settings: Settings
    limiter: RateLimiter
    resolver: Resolver
    assets: AssetStore
    target: str = ""
    kind: str = "domain"
    passive_only: bool = False

    def client(self, module: str = "", **kw) -> httpx.Client:
        return build_client(self.settings, module=module, **kw)


class ReconModule(abc.ABC):
    name: str = "unnamed"
    description: str = ""
    active: bool = False
    phase: int = 1
    targets = {"domain", "ip"}
    requires_key: Optional[str] = None     # module is skipped without this API key
    optional_key: Optional[str] = None     # key improves results but is not required
    external_tool: Optional[str] = None    # binary that must be installed

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.settings = ctx.settings

    # -- helpers --------------------------------------------------------------
    def throttle(self) -> None:
        self.ctx.limiter.throttle(self.name)

    def client(self, **kw) -> httpx.Client:
        return self.ctx.client(self.name, **kw)

    def key(self) -> str:
        return getattr(self.settings.api, self.requires_key or self.optional_key or "", "") \
            if (self.requires_key or self.optional_key) else ""

    def in_scope(self, item: str) -> bool:
        if scope_empty(self.settings.scope) and not self.settings.scope.require_allowlist:
            return True
        return in_scope(item, self.settings.scope)

    def web_hosts(self, limit: int) -> List[str]:
        """In-scope hostnames worth probing, target first, skipping known non-resolving names."""
        a = self.ctx.assets
        hosts = [self.ctx.target] if self.ctx.kind == "domain" else []
        hosts += [h for h in a.hosts() if h != self.ctx.target]
        hosts = [h for h in hosts if self.in_scope(h) and a.resolution(h) not in ("nxdomain", "empty")]
        if self.ctx.kind == "ip" and self.in_scope(self.ctx.target):
            hosts = [self.ctx.target]
        return hosts[:limit]

    # -- lifecycle ------------------------------------------------------------
    def run(self, target: str) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target, active=self.active, phase=self.phase)
        if self.requires_key and not self.key():
            res.skipped = True
            res.skip_reason = (f"needs a {self.requires_key} API key - run: "
                               f"reconforge keys set {self.requires_key}")
            return res.finish()
        if self.external_tool:
            from .external import tool_path
            if not tool_path(self.external_tool):
                res.skipped = True
                res.skip_reason = f"{self.external_tool} is not installed"
                return res.finish()
        if self.active:
            if self.ctx.passive_only:
                res.skipped, res.skip_reason = True, "active module (--passive-only)"
                return res.finish()
            try:
                assert_in_scope(target, self.settings.scope)
            except PermissionError as exc:
                res.skipped, res.skip_reason = True, f"out of scope: {exc}"
                return res.finish()
        try:
            self.gather(target, res)
        except Exception as exc:  # noqa: BLE001 - one module failing must not stop the scan
            res.ok = False
            res.error = f"{type(exc).__name__}: {exc}"
        return res.finish()

    @abc.abstractmethod
    def gather(self, target: str, result: ModuleResult) -> None:
        raise NotImplementedError

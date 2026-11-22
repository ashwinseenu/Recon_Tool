"""Scope enforcement: active modules only touch authorised targets."""
from __future__ import annotations

import ipaddress
from typing import List

import tldextract

from .config import ScopeConfig

# Offline: use the bundled public-suffix snapshot, never fetch it over the network
# (a fetch would bypass the anonymity layer).
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


class ScopeError(PermissionError):
    pass


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    ext = _tld(host)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else host.lower()


def _norm_domain(d: str) -> str:
    return d.strip().lower().lstrip("*.").rstrip(".")


def domain_in_scope(host: str, scope: ScopeConfig) -> bool:
    host = host.strip().lower().rstrip(".")
    for allowed in scope.allowed_domains:
        a = _norm_domain(allowed)
        if a and (host == a or host.endswith("." + a)):
            return True
    return False


def ip_in_scope(ip: str, scope: ScopeConfig) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in scope.allowed_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def in_scope(target: str, scope: ScopeConfig) -> bool:
    return ip_in_scope(target, scope) if is_ip(target) else domain_in_scope(target, scope)


def scope_empty(scope: ScopeConfig) -> bool:
    return not scope.allowed_domains and not scope.allowed_cidrs


def assert_in_scope(target: str, scope: ScopeConfig) -> None:
    if scope_empty(scope):
        if scope.require_allowlist:
            raise ScopeError("scope allowlist is empty - add authorised targets with "
                             "'reconforge scope add <domain|cidr>' (or --scope on the command line)")
        return
    if not in_scope(target, scope):
        raise ScopeError(f"'{target}' is not in the authorised scope allowlist")


def filter_in_scope(items: List[str], scope: ScopeConfig) -> List[str]:
    if scope_empty(scope) and not scope.require_allowlist:
        return list(items)
    return [i for i in items if in_scope(i, scope)]


def summarize_scope(scope: ScopeConfig) -> str:
    d = ", ".join(scope.allowed_domains) or "(none)"
    c = ", ".join(scope.allowed_cidrs) or "(none)"
    return f"domains: {d} | cidrs: {c} | require_allowlist: {scope.require_allowlist}"

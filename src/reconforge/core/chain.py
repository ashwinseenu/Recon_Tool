"""proxychains support: Tor -> proxy chaining and anonymising external tools.

Chain mode cannot be done inside httpx (single upstream only), so the CLI
re-executes itself under proxychains4 with a generated config. Every socket the
process opens (HTTP, DoH, TLS, port checks) then follows the chain, and
proxy_dns keeps name resolution inside it.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlparse

from . import paths
from .config import Settings

CHAIN_ENV = "RECONFORGE_CHAINED"


class AnonymityError(RuntimeError):
    pass


def is_chained() -> bool:
    return os.environ.get(CHAIN_ENV) == "1"


def proxychains_bin() -> Optional[str]:
    return shutil.which("proxychains4") or shutil.which("proxychains")


Hop = Tuple[str, str, int, str, str]  # type, host, port, user, password


def parse_proxy_url(url: str) -> Hop:
    u = urlparse(url)
    scheme = (u.scheme or "").lower()
    kind = {"socks5": "socks5", "socks5h": "socks5", "socks4": "socks4", "socks4a": "socks4",
            "http": "http", "https": "http"}.get(scheme)
    if not kind or not u.hostname:
        raise AnonymityError(f"Unsupported proxy URL {url!r} (use socks5://, socks4://, http://host:port)")
    default_port = {"socks5": 1080, "socks4": 1080, "http": 8080}[kind]
    return kind, u.hostname, u.port or default_port, unquote(u.username or ""), unquote(u.password or "")


def hops(settings: Settings) -> List[Hop]:
    mode = settings.proxy.mode
    tor = ("socks5", settings.tor.socks_host, settings.tor.socks_port, "", "")
    if mode == "tor":
        return [tor]
    if mode == "proxy":
        return [parse_proxy_url(settings.proxy.url)]
    if mode == "chain":
        if not settings.proxy.url:
            raise AnonymityError("proxy.mode=chain needs proxy.url (the hop after Tor)")
        return [tor, parse_proxy_url(settings.proxy.url)]
    return []


def write_conf(settings: Settings) -> Path:
    lines = ["strict_chain", "proxy_dns", "quiet_mode", "tcp_read_time_out 20000",
             "tcp_connect_time_out 10000", "", "[ProxyList]"]
    for kind, host, port, user, pw in hops(settings):
        entry = f"{kind} {host} {port}"
        if user:
            entry += f" {user} {pw}"
        lines.append(entry)
    path = paths.run_dir() / "proxychains.conf"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def ensure_chained(settings: Settings, argv: List[str]) -> None:
    """In chain mode, re-exec this command under proxychains (no-op otherwise)."""
    if settings.proxy.mode != "chain" or is_chained():
        return
    pc = proxychains_bin()
    if not pc:
        raise AnonymityError("chain mode needs proxychains4 (apt install proxychains4 | dnf install proxychains-ng)")
    conf = write_conf(settings)
    env = dict(os.environ, **{CHAIN_ENV: "1"})
    os.execvpe(pc, [pc, "-q", "-f", str(conf), sys.executable, "-m", "reconforge", *argv], env)

"""Anonymity-aware networking.

Every outbound connection in ReconForge goes through this module: HTTP(S) via
httpx, raw TCP/TLS via open_socket(). In tor/proxy/chain mode there is no direct
fallback; if the layer is unavailable the request fails (fail-closed).
"""
from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

from .chain import AnonymityError, is_chained, parse_proxy_url
from .config import Settings

log = logging.getLogger("reconforge.net")

TOR_CHECK = "https://check.torproject.org/api/ip"
IP_ECHO = ["https://api.ipify.org?format=json", "https://ifconfig.co/json"]

# Test hook: a factory returning an httpx transport (e.g. MockTransport).
_transport_override: Optional[Callable[[], httpx.BaseTransport]] = None


def set_transport_override(factory: Optional[Callable[[], httpx.BaseTransport]]) -> None:
    global _transport_override
    _transport_override = factory


@dataclass
class EgressStatus:
    mode: str
    egress_ip: Optional[str]
    is_tor: Optional[bool]
    ok: bool
    detail: str


def _chain_guard(settings: Settings) -> None:
    if settings.proxy.mode == "chain" and not is_chained():
        raise AnonymityError("chain mode must run under proxychains (the reconforge CLI does this automatically)")


def proxy_url(settings: Settings) -> Optional[str]:
    """Proxy for in-process httpx traffic. None = no proxy (direct, or already chained)."""
    mode = settings.proxy.mode
    if mode == "direct":
        return None
    if mode == "chain":
        _chain_guard(settings)
        return None
    if mode == "tor":
        return f"socks5://{settings.tor.socks_host}:{settings.tor.socks_port}"
    if mode == "proxy":
        if not settings.proxy.url:
            raise AnonymityError("proxy.mode=proxy but proxy.url is empty")
        kind, host, port, user, pw = parse_proxy_url(settings.proxy.url)
        scheme = "socks5" if kind == "socks5" else ("http" if kind == "http" else "")
        if not scheme:
            raise AnonymityError("httpx supports socks5:// and http:// proxies (socks4 only via chain mode)")
        auth = f"{user}:{pw}@" if user else ""
        return f"{scheme}://{auth}{host}:{port}"
    raise AnonymityError(f"unknown proxy.mode {mode!r}")


def build_client(settings: Settings, *, module: str = "", follow_redirects: bool = True,
                 timeout: Optional[float] = None, verify: Optional[bool] = None,
                 headers: Optional[dict] = None) -> httpx.Client:
    hdrs = {"User-Agent": settings.http.user_agent}
    hdrs.update(headers or {})
    to = timeout or settings.http.timeout_seconds
    if _transport_override is not None:
        return httpx.Client(transport=_transport_override(), headers=hdrs, timeout=to,
                            follow_redirects=follow_redirects)
    transport = httpx.HTTPTransport(retries=settings.http.max_retries,
                                    verify=settings.http.verify_tls if verify is None else verify,
                                    proxy=proxy_url(settings))
    return httpx.Client(transport=transport, headers=hdrs, timeout=to, follow_redirects=follow_redirects)


def open_socket(settings: Settings, host: str, port: int, timeout: float = 8.0) -> socket.socket:
    """TCP connection that honours the anonymity layer (remote DNS for proxies)."""
    mode = settings.proxy.mode
    if mode == "direct" or (mode == "chain" and is_chained()):
        return socket.create_connection((host, port), timeout=timeout)
    _chain_guard(settings)
    import socks  # PySocks

    s = socks.socksocket()
    s.settimeout(timeout)
    if mode == "tor":
        s.set_proxy(socks.SOCKS5, settings.tor.socks_host, settings.tor.socks_port, rdns=True)
    else:
        kind, phost, pport, user, pw = parse_proxy_url(settings.proxy.url)
        ptype = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4, "http": socks.HTTP}[kind]
        s.set_proxy(ptype, phost, pport, rdns=True, username=user or None, password=pw or None)
    try:
        s.connect((host, port))
    except Exception:
        s.close()
        raise
    return s


def tor_reachable(settings: Settings, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((settings.tor.socks_host, settings.tor.socks_port), timeout=timeout):
            return True
    except OSError:
        return False


def check_egress(settings: Settings) -> EgressStatus:
    mode = settings.proxy.mode
    if mode == "direct":
        return EgressStatus(mode, None, False, True, "Direct mode - no anonymity layer.")
    try:
        with build_client(settings, module="egress") as client:
            ip, is_tor = None, None
            if mode == "tor":
                data = client.get(TOR_CHECK).json()
                ip, is_tor = data.get("IP"), bool(data.get("IsTor"))
            else:
                for url in IP_ECHO:
                    try:
                        data = client.get(url).json()
                        ip = data.get("ip") or data.get("query")
                        if ip:
                            break
                    except Exception:  # noqa: BLE001
                        continue
            if not ip:
                return EgressStatus(mode, None, is_tor, False, "Could not determine the egress IP.")
            if mode == "tor" and not is_tor:
                return EgressStatus(mode, ip, False, False, "Egress IP is NOT a Tor exit - Tor is not carrying traffic.")
            return EgressStatus(mode, ip, is_tor, True, "Egress verified.")
    except AnonymityError:
        raise
    except Exception as exc:  # noqa: BLE001
        hint = " Is Tor running? (systemctl status tor)" if mode == "tor" else ""
        return EgressStatus(mode, None, None, False, f"Egress check failed: {exc}.{hint}")


def ensure_anonymity(settings: Settings) -> EgressStatus:
    status = check_egress(settings)
    if settings.fail_closed and not status.ok:
        raise AnonymityError(f"Refusing to run (fail_closed=true): {status.detail}")
    return status


def new_tor_circuit(settings: Settings) -> bool:
    """NEWNYM via the control port. Best effort; returns False if unavailable."""
    if settings.proxy.mode not in ("tor", "chain"):
        return False
    try:
        from stem import Signal
        from stem.control import Controller

        with Controller.from_port(address=settings.tor.socks_host, port=settings.tor.control_port) as ctrl:
            if settings.tor.control_password:
                ctrl.authenticate(password=settings.tor.control_password)
            else:
                ctrl.authenticate()
            ctrl.signal(Signal.NEWNYM)
            return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not rotate the Tor circuit: %s", exc)
        return False

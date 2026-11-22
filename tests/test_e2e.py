import socket, ssl, threading, datetime, ipaddress
import pytest
from reconforge.core import config as cfg
from reconforge.core.engine import run_scan
from reconforge.core.chain import AnonymityError
from reconforge.reporting import report as rpt


def direct(**scope):
    s = cfg.load_settings(reload=True)
    s.proxy.mode = "direct"
    s.dns.mode = "doh"
    for k, v in scope.items():
        setattr(s.scope, k, v)
    return s


def test_passive_scan_end_to_end(mock_net):
    mock_net["dns"].update({
        ("example.com", "A"): ["93.184.216.34"], ("example.com", "TXT"): ['"v=spf1 +all"'],
        ("example.com", "NS"): ["a.iana-servers.net."],
        ("www.example.com", "A"): ["93.184.216.34"],
    })
    mock_net["routes"]["https://crt.sh"] = [{"name_value": "www.example.com\nmail.example.com", "issuer_name": "CN=Test CA", "not_after": "2030-01-01T00:00:00"}]
    mock_net["routes"]["https://api.hackertarget.com"] = "www.example.com,93.184.216.34"
    s = direct()
    report = run_scan("example.com", s, passive_only=True)
    assert report.finding_count > 0
    titles = " ".join(f.title for r in report.modules for f in r.findings)
    assert "SPF" in titles
    hosts = {h["host"]: h for h in report.assets["hostnames"]}
    assert hosts["www.example.com"]["resolution"] != "nxdomain"
    paths = rpt.write_report(report, ["json", "html", "md", "csv"])
    assert len(paths) == 4
    assert rpt.load_report(report.scan_id)["target"] == "example.com"


def test_active_modules_blocked_without_scope(mock_net):
    s = direct()
    report = run_scan("example.com", s)
    active = [r for r in report.modules if r.module in ("port_scan", "tls_inspect", "http_fingerprint", "exposure_check")]
    assert all(r.skipped for r in active)


def test_fail_closed_when_tor_down():
    s = cfg.load_settings(reload=True)
    s.tor.socks_port = 1            # nothing listens here
    with pytest.raises(AnonymityError):
        run_scan("example.com", s)


def test_port_scan_local(mock_net):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    s = direct(allowed_cidrs=["127.0.0.1/32"], allowed_domains=[])
    s.limits.ports = [port]
    report = run_scan("127.0.0.1", s, only=["port_scan"])
    srv.close()
    res = [r for r in report.modules if r.module == "port_scan"][0]
    assert not res.error, res.error
    assert any(str(port) in (f.title + f.detail) for f in res.findings)


def test_no_stray_dns_calls():
    import pathlib, re
    src = pathlib.Path(__file__).parent.parent / "src" / "reconforge"
    bad = []
    for f in src.rglob("*.py"):
        if f.name in ("resolver.py", "netclient.py"):
            continue
        if re.search(r"gethostbyname|getaddrinfo|socket\.getfqdn", f.read_text()):
            bad.append(str(f))
    assert not bad, bad

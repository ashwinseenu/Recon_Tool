import json
import pytest
import httpx

from reconforge.core import config as cfg
from reconforge.core import netclient


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("RECONFORGE_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("RECONFORGE_DATA_DIR", str(tmp_path / "data"))
    for k in list(__import__("os").environ):
        if k.startswith("RECONFORGE_") and k not in ("RECONFORGE_CONFIG_DIR", "RECONFORGE_DATA_DIR"):
            monkeypatch.delenv(k)
    cfg.reset_settings()
    yield
    netclient.set_transport_override(None)
    cfg.reset_settings()


def doh_answer(name, rtype, table):
    types = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
    recs = table.get((name.rstrip("."), rtype))
    if recs is None:
        return {"Status": 3, "Answer": []}
    return {"Status": 0, "Answer": [{"name": name, "type": types[rtype], "TTL": 60, "data": d} for d in recs]}


@pytest.fixture
def mock_net():
    """Install a MockTransport. Returns a dict the test can fill: dns table and url routes."""
    state = {"dns": {}, "routes": {}, "seen": []}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        state["seen"].append(url)
        if "dns-query" in url or "resolve?" in url or "/dns" in request.url.path:
            q = request.url.params
            return httpx.Response(200, json=doh_answer(q["name"], q.get("type", "A"), state["dns"]))
        for prefix, resp in state["routes"].items():
            if url.startswith(prefix):
                if callable(resp):
                    return resp(request)
                return httpx.Response(200, json=resp) if not isinstance(resp, str) else httpx.Response(200, text=resp)
        return httpx.Response(404, text="nope")

    netclient.set_transport_override(lambda: httpx.MockTransport(handler))
    return state

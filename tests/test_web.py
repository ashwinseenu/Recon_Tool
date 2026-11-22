from fastapi.testclient import TestClient
from reconforge.web.app import create_app, ensure_token


def client():
    return TestClient(create_app(), base_url="http://127.0.0.1:8787")


def test_requires_token():
    c = client()
    assert c.get("/").status_code == 401
    assert c.get("/settings").status_code == 401


def test_token_cookie_flow_and_pages():
    c = client()
    t = ensure_token()
    r = c.get(f"/?token={t}", follow_redirects=False)
    assert r.status_code == 303 and "token" not in r.headers["location"]
    assert c.get("/").status_code == 200
    assert c.get("/settings").status_code == 200


def test_bad_host_rejected():
    c = TestClient(create_app(), base_url="http://evil.example")
    assert c.get(f"/?token={ensure_token()}").status_code == 403


def test_cross_origin_post_blocked_and_key_saved():
    c = client()
    c.cookies.set("rf_session", ensure_token())
    r = c.post("/settings/keys", data={"service": "shodan", "value": "ABCDEFGH12345678"},
               headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    r = c.post("/settings/keys", data={"service": "shodan", "value": "ABCDEFGH12345678"}, follow_redirects=True)
    assert r.status_code == 200 and "ABCDEFGH12345678" not in r.text

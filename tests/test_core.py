import pytest
from reconforge.core import config as cfg, keystore
from reconforge.core.scope import in_scope, assert_in_scope, ScopeError
from reconforge.core.engine import normalize_target
from reconforge.modules.lookalikes import generate
from reconforge.modules.email_security import analyse_spf, analyse_dmarc


def test_target_normalisation():
    assert normalize_target("https://Example.COM/path")[0] == "example.com"
    assert normalize_target("203.0.113.9")[1] == "ip"
    with pytest.raises(ValueError):
        normalize_target("not a host!")


def test_scope_rules():
    s = cfg.load_settings()
    s.scope.allowed_domains = ["example.com"]
    s.scope.allowed_cidrs = ["10.0.0.0/24"]
    assert in_scope("a.b.example.com", s.scope)
    assert not in_scope("evilexample.com", s.scope)
    assert in_scope("10.0.0.5", s.scope)
    assert not in_scope("10.0.1.5", s.scope)
    with pytest.raises(ScopeError):
        assert_in_scope("other.org", s.scope)


def test_config_precedence(monkeypatch):
    cfg.update_local_config("limits.max_hosts", 11)
    assert cfg.load_settings(reload=True).limits.max_hosts == 11
    monkeypatch.setenv("RECONFORGE_LIMITS__MAX_HOSTS", "22")
    assert cfg.load_settings(reload=True).limits.max_hosts == 22
    with pytest.raises(Exception):
        cfg.update_local_config("proxy.mode", "bogus")


def test_keystore_roundtrip():
    keystore.set_key("shodan", "ABCDEFGH12345678")
    st = keystore.status()["shodan"]
    assert st["configured"] and "ABCDEFGH12345678" not in st["masked"]
    keystore.unset_key("shodan")
    assert not keystore.status()["shodan"]["configured"]
    with pytest.raises(ValueError):
        keystore.set_key("shodan", "bad key with spaces")


def test_lookalikes_generate():
    out = generate("example.com")
    assert "examp1e.com" in out or "exarnple.com" in out
    assert "example.com" not in out


def test_spf_dmarc():
    assert any("+all" in f.title or "all" in f.title.lower() for f in analyse_spf(["v=spf1 +all"]))
    assert analyse_dmarc(["v=DMARC1; p=none"])

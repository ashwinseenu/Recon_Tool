import datetime, ipaddress, socket, ssl, threading
import pytest
from reconforge.core import config as cfg
from reconforge.core.engine import run_scan
from reconforge.modules.tls_inspect import TlsInspect


def _selfsigned(tmp_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=5)).sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return c, k


def test_tls_inspect_flags_selfsigned_and_expiry(tmp_path, monkeypatch):
    c, k = _selfsigned(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(c, k)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except Exception:
                conn.close()
    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(TlsInspect, "PORT", port)
    s = cfg.load_settings(reload=True)
    s.proxy.mode = "direct"; s.scope.allowed_cidrs = ["127.0.0.1/32"]
    try:
        report = run_scan("127.0.0.1", s, only=["tls_inspect"])
    finally:
        stop.set(); srv.close()
    res = [m for m in report.modules if m.module == "tls_inspect"][0]
    assert not res.error, res.error
    text = " ".join(f.title.lower() for f in res.findings)
    assert "self-signed" in text or "untrusted" in text or "expir" in text, text

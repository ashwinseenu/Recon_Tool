"""TLS certificate and protocol review (ACTIVE). Sockets go through the anonymity layer."""
from __future__ import annotations

import ssl
from datetime import datetime, timezone
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..core.models import Finding, ModuleResult, Severity
from ..core.module_base import ReconModule
from ..core.netclient import open_socket
from ..core.registry import register


def _handshake(settings, host: str, port: int, verify: bool, timeout: float = 8.0):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sock = open_socket(settings, host, port, timeout)
    try:
        ss = ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise
    try:
        return ss.getpeercert(binary_form=True), ss.version(), ss.cipher()
    finally:
        ss.close()


def supports_protocol(settings, host: str, port: int, version) -> Optional[bool]:
    """True/False if the server accepts exactly this protocol; None if we cannot test it locally."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        ctx.minimum_version = ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return None
    try:
        sock = open_socket(settings, host, port, 8.0)
    except Exception:  # noqa: BLE001
        return None
    try:
        with ctx.wrap_socket(sock, server_hostname=host):
            return True
    except ssl.SSLError:
        return False
    except OSError:
        return None
    finally:
        sock.close()


def describe_cert(der: bytes) -> Dict:
    cert = x509.load_der_x509_certificate(der)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)

    def cn(name: x509.Name) -> str:
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"EC {key.curve.name}", key.key_size
    else:
        key_desc, key_bits = type(key).__name__, 0
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "none"
    return {"subject": cn(cert.subject), "issuer": cn(cert.issuer), "self_signed": cert.issuer == cert.subject,
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_left": (not_after - datetime.now(timezone.utc)).days, "sans": sans,
            "key": key_desc, "key_bits": key_bits, "signature": sig}


@register
class TlsInspect(ReconModule):
    name = "tls_inspect"
    description = "Certificate validity/expiry, trust, key strength, signature, legacy TLS 1.0/1.1."
    active = True
    phase = 4
    PORT = 443

    def gather(self, target: str, result: ModuleResult) -> None:
        hosts = self.web_hosts(self.settings.tls.max_hosts)
        if not hosts:
            result.skipped, result.skip_reason = True, "no in-scope hosts to probe"
            return
        reached = 0
        for host in hosts:
            self.throttle()
            trust_error = ""
            try:
                der, proto, cipher = _handshake(self.settings, host, self.PORT, verify=True)
            except ssl.SSLCertVerificationError as exc:
                trust_error = exc.verify_message or str(exc)
                try:
                    der, proto, cipher = _handshake(self.settings, host, self.PORT, verify=False)
                except Exception:  # noqa: BLE001
                    continue
            except Exception:  # noqa: BLE001 - not listening / not TLS
                continue
            reached += 1
            info = describe_cert(der)
            for s in info["sans"]:
                self.ctx.assets.add_host(s, "tls_san")
            result.add(Finding(f"TLS on {host}: {info['subject']}",
                               f"issuer {info['issuer']} | {proto} | {info['key']} {info['key_bits']} | expires in {info['days_left']} days",
                               Severity.INFO, {**info, "protocol": proto, "cipher": cipher[0] if cipher else ""}, host=host))
            d = info["days_left"]
            if d < 0:
                result.add(Finding(f"Certificate EXPIRED on {host}", f"Expired {-d} days ago ({info['not_after']}).", Severity.CRITICAL, host=host,
                                   remediation="Renew and deploy the certificate; automate renewal."))
            elif d <= 14:
                result.add(Finding(f"Certificate on {host} expires in {d} days", info["not_after"], Severity.HIGH, host=host,
                                   remediation="Renew now; automate renewal (ACME)."))
            elif d <= 30:
                result.add(Finding(f"Certificate on {host} expires in {d} days", info["not_after"], Severity.MEDIUM, host=host,
                                   remediation="Schedule renewal; automate with ACME."))
            if info["self_signed"]:
                result.add(Finding(f"Self-signed certificate on {host}", info["subject"], Severity.HIGH, host=host,
                                   remediation="Use a certificate from a trusted CA."))
            elif trust_error:
                sev = Severity.MEDIUM if "match" in trust_error.lower() or "expired" in trust_error.lower() else Severity.HIGH
                result.add(Finding(f"Certificate not trusted on {host}", trust_error, sev, host=host,
                                   remediation="Serve a valid, complete, correctly named certificate chain."))
            if info["key"] == "RSA" and info["key_bits"] < 2048:
                result.add(Finding(f"Weak RSA key ({info['key_bits']} bits) on {host}", "", Severity.MEDIUM, host=host,
                                   remediation="Reissue with RSA >= 2048 or ECDSA P-256."))
            if info["signature"] in ("sha1", "md5"):
                result.add(Finding(f"Weak certificate signature ({info['signature']}) on {host}", "", Severity.HIGH, host=host,
                                   remediation="Reissue with SHA-256 or better."))
            if self.settings.tls.check_legacy and reached <= 5:
                legacy = [n for n, v in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
                          if supports_protocol(self.settings, host, self.PORT, v)]
                if legacy:
                    result.add(Finding(f"Legacy protocols accepted on {host}: {', '.join(legacy)}", "", Severity.MEDIUM, host=host,
                                       remediation="Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only."))
        if reached == 0:
            result.add(Finding("No TLS service reachable on 443", f"Tried {len(hosts)} hosts.", Severity.INFO, host=target))

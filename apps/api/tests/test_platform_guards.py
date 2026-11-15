"""Config guards, structured errors, health/readiness, catalogue parity, TLS helper."""
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.authz.catalog import PERMISSIONS, ROLE_PERMISSIONS
from app.core.config import ConfigError, Settings
from app.core.tls import TlsConfigError, ignored_insecure_flags, service_tls

SECRET = "s3cr3t-value-that-must-never-appear"


def _settings(**kw):
    base = dict(_env_file=None, database_url=f"postgresql+psycopg://u:{SECRET}@127.0.0.1:1/x")
    base.update(kw)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize("kw, needle", [
    (dict(env="development", database_url=f"postgresql+psycopg://u:{SECRET}@db.example.org/x"), "loopback"),
    (dict(env="staging", database_url=f"postgresql+psycopg://u:{SECRET}@prod-db.internal/x",
          production_database_hosts="prod-db.internal"), "production database host"),
    (dict(env="production", database_url=f"postgresql+psycopg://u:{SECRET}@prod-db.internal/x",
          session_cookie_secure=False), "SESSION_COOKIE_SECURE"),
    (dict(database_url=f"postgres://u:{SECRET}@127.0.0.1/x"), "scheme"),
])
def test_config_guards_name_settings_never_values(kw, needle):
    with pytest.raises((ConfigError, ValueError)) as e:
        _settings(**kw)
    assert needle in str(e.value) and SECRET not in str(e.value)


def test_production_disables_docs():
    s = _settings(env="production", database_url=f"postgresql+psycopg://u:{SECRET}@prod-db.internal/x")
    assert s.docs_enabled is False


def test_health_readiness_and_headers(app):
    c = TestClient(app)
    h = c.get("/healthz", headers={"X-Request-Id": "abcDEF12-trace"})
    assert h.status_code == 200 and h.json()["status"] == "ok"
    assert h.headers["x-request-id"] == "abcDEF12-trace" and h.headers["x-api-version"] == "1.0.0"
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["status"] == "ready"


def test_unknown_route_and_unexpected_errors_are_structured(app, settings):
    c = TestClient(app)
    r = c.get("/api/v1/does-not-exist")
    assert r.status_code == 404 and set(r.json()["error"]) >= {"code", "message", "request_id"}

    from app.main import create_app
    boom = create_app(settings)

    @boom.get("/boom")
    def _boom():
        raise RuntimeError(f"db password is {SECRET}")
    r = TestClient(boom, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error" and SECRET not in r.text


def test_database_unreachable_is_a_meaningful_503(settings):
    from app.main import create_app
    down = settings.model_copy(update={"database_url": settings.database_url.__class__(
        "postgresql+psycopg://novrsoc_app:x@127.0.0.1:1/none")})
    try:
        c = TestClient(create_app(down), raise_server_exceptions=False)
        r = c.post("/api/v1/auth/login", json={"email": "a@b.invalid", "password": "whatever-123"})
        assert r.status_code == 503 and r.json()["error"]["code"] == "database_unavailable"
        assert "psycopg" not in r.text and "127.0.0.1" not in r.text
        assert c.get("/readyz").status_code == 503
    finally:
        create_app(settings)  # the engine is process-wide: restore it for the remaining tests


def test_database_catalogue_equals_code_catalogue(owner):
    with owner.connect() as c:
        perms = {r[0] for r in c.execute(text("SELECT key FROM novrsoc.permissions"))}
        pairs = {(r[0], r[1]) for r in c.execute(text("SELECT role_key, permission_key FROM novrsoc.role_permissions"))}
    assert perms == set(PERMISSIONS)
    assert pairs == {(role, p) for role, ps in ROLE_PERMISSIONS.items() for p in ps}
    assert "response:approve" not in ROLE_PERMISSIONS["analyst"], "analysts request containment, managers approve"


# ---------------------------------------------------------------- TLS (port of lib/serviceTls.ts)
def _self_signed(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


def _serve_once(tmp_path, cert_pem, key_pem):
    (tmp_path / "c.pem").write_text(cert_pem); (tmp_path / "k.pem").write_text(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)

    def run():
        conn, _ = srv.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(1)
        except Exception:
            pass
        finally:
            srv.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def _handshake(tls, port) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with tls.context.wrap_socket(raw, server_hostname=tls.server_hostname or "127.0.0.1"):
                return True
    except ssl.SSLError:
        return False


def test_pinned_self_signed_certificate_is_accepted(tmp_path):
    cert, key = _self_signed("wazuh-manager.local.test")
    port = _serve_once(tmp_path, cert, key)
    tls = service_tls("WAZUH", {"WAZUH_CA_CERT": cert.replace("\n", "\\n"), "WAZUH_TLS_SERVERNAME": "wazuh-manager.local.test"})
    assert _handshake(tls, port) is True


def test_unpinned_self_signed_certificate_is_rejected(tmp_path):
    cert, key = _self_signed("wazuh-manager.local.test")
    port = _serve_once(tmp_path, cert, key)
    assert _handshake(service_tls("WAZUH", {"WAZUH_TLS_SERVERNAME": "wazuh-manager.local.test"}), port) is False


def test_wrong_pin_is_rejected(tmp_path):
    cert, key = _self_signed("wazuh-manager.local.test")
    other, _ = _self_signed("wazuh-manager.local.test")
    port = _serve_once(tmp_path, cert, key)
    assert _handshake(service_tls("WAZUH", {"WAZUH_CA_CERT": other, "WAZUH_TLS_SERVERNAME": "wazuh-manager.local.test"}), port) is False


def test_broken_pin_refuses_and_verify_flags_are_ignored():
    with pytest.raises(TlsConfigError):
        service_tls("OPNSENSE", {"OPNSENSE_CA_CERT": "not a certificate"})
    tls = service_tls("OPNSENSE", {"OPNSENSE_VERIFY_TLS": "false"})
    assert tls.context.verify_mode == ssl.CERT_REQUIRED and tls.context.check_hostname is True
    assert ignored_insecure_flags({"OPNSENSE_VERIFY_TLS": "false"}) == ["OPNSENSE_VERIFY_TLS"]

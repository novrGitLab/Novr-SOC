"""TLS for outbound connections to infrastructure services (port of legacy lib/serviceTls.ts).

Verification is ALWAYS on. For a service identified by an environment prefix:

  <PREFIX>_CA_CERT         optional PEM (raw, "\\n"-escaped or base64). When set it becomes the ONLY
                           trusted root for that service: the service's own self-signed certificate,
                           or the CA that issued it.
  <PREFIX>_TLS_SERVERNAME  optional name to check the certificate against (use as server_hostname)
                           when the service is reached by an address its certificate does not list.

A value that is set but is not a valid certificate raises TlsConfigError: connections are refused,
there is no fallback to unverified TLS. The retired <PREFIX>_VERIFY_TLS switches are ignored.
Workstreams B (Wazuh, Greenbone feeds), C (Wazuh SCA) and A (OPNsense) must build their clients on this.
"""
from __future__ import annotations

import base64
import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass

IGNORED_INSECURE_FLAGS = ("OPNSENSE_VERIFY_TLS", "WAZUH_VERIFY_TLS", "WAZUH_INDEXER_VERIFY_TLS")


class TlsConfigError(Exception):
    pass


@dataclass(frozen=True)
class ServiceTls:
    context: ssl.SSLContext
    server_hostname: str | None


def _pem(raw: str) -> str | None:
    text = raw.strip().replace("\\n", "\n")
    if "-----BEGIN CERTIFICATE-----" not in text:
        try:
            text = base64.b64decode(text, validate=True).decode("ascii")
        except Exception:
            return None
    if "-----BEGIN CERTIFICATE-----" not in text or "-----END CERTIFICATE-----" not in text:
        return None
    try:
        ssl.PEM_cert_to_DER_cert(text[text.index("-----BEGIN CERTIFICATE-----"): text.index("-----END CERTIFICATE-----") + 25])
    except Exception:
        return None
    return text


def service_tls(prefix: str, env: Mapping[str, str] | None = None) -> ServiceTls:
    env = os.environ if env is None else env
    raw = (env.get(f"{prefix}_CA_CERT") or "").strip()
    name = (env.get(f"{prefix}_TLS_SERVERNAME") or "").strip() or None
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if raw:
        pem = _pem(raw)
        if pem is None:
            raise TlsConfigError(f"{prefix}_CA_CERT is set but is not a valid PEM certificate; refusing to connect")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cadata=pem)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ServiceTls(context=ctx, server_hostname=name)


def ignored_insecure_flags(env: Mapping[str, str] | None = None) -> list[str]:
    env = os.environ if env is None else env
    return [k for k in IGNORED_INSECURE_FLAGS if (env.get(k) or "").strip()]

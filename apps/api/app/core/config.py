"""Settings. Every problem is reported by setting NAME, never by value (port of legacy lib/configCheck.ts).

Guards (port of legacy lib/runtimeEnv.ts behaviour):
  * development/test may only use a loopback database host;
  * a host listed in NOVRSOC_PRODUCTION_DATABASE_HOSTS is refused unless NOVRSOC_ENV=production;
  * production requires secure session cookies and disables the interactive docs.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
API_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class ConfigError(ValueError):
    """A configuration problem. The message names settings only."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NOVRSOC_", env_file=API_ENV_FILE, env_file_encoding="utf-8",
                                      extra="ignore")

    env: Literal["development", "test", "staging", "production"] = "development"
    database_url: SecretStr
    production_database_hosts: str = ""

    session_ttl_minutes: int = Field(default=720, ge=5, le=7 * 24 * 60)
    session_cookie_secure: bool = True
    session_cookie_name: str = "novrsoc_session"
    csrf_cookie_name: str = "novrsoc_csrf"
    login_max_failures: int = Field(default=5, ge=3, le=20)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)

    docs_enabled: bool | None = None
    # Wazuh data source. local_fixture is development/test only. live (Phase 5) uses the read-only, TLS-verified
    # clients configured from WAZUH_* / WAZUH_INDEXER_* environment variables (app/connectors/wazuh_live.py).
    wazuh_mode: Literal["unconfigured", "local_fixture", "live"] = "unconfigured"
    # NHAI inference backend used by the NHAI worker (never by the API process). test_adapter is a deterministic,
    # labelled stand-in for development/test; ollama is the local model behind an authenticated TLS proxy.
    nhai_backend: Literal["unconfigured", "test_adapter", "ollama"] = "unconfigured"
    nhai_model: str = Field(default="qwen2.5:3b", pattern=r"^[a-z0-9._:-]{1,80}$")
    # CPU-only host (~3.5 tokens/s measured): jobs are asynchronous with generous, bounded limits.
    nhai_inference_timeout_seconds: int = Field(default=300, ge=10, le=300)
    nhai_max_output_tokens: int = Field(default=384, ge=64, le=1024)
    nhai_max_prompt_chars: int = Field(default=12_000, ge=1_000, le=64_000)
    nhai_job_deadline_seconds: int = Field(default=1_800, ge=60, le=6 * 3600)
    # Ollama context window (tokens). The whole prompt (system rules, evidence, output schema) plus the answer must fit:
    # Ollama silently drops the BEGINNING of an over-long prompt, which is where the rules are (see nhai_budget()).
    nhai_num_ctx: int = Field(default=8192, ge=2048, le=32768)
    # SOAR execution bridge on Server 1 (pilot: a local bridge on loopback with the simulated adapter). Unset = no
    # consequential step can be dispatched (it fails honestly; nothing executes).
    soar_bridge_url: str = ""
    soar_bridge_key_id: str = Field(default="server2-soar", pattern=r"^[a-z0-9_.-]{1,60}$")
    soar_bridge_key_file: str = ""
    soar_bridge_ca_cert: str = ""
    # VMS scanning: disabled; local_test_targets (development: scopes limited to loopback and *.test / *.localhost);
    # authorized_scopes (scopes approved by the organization, held to its scan policy: protected networks, windows,
    # rate and concurrency caps). Even then nothing runs until an organization enables its policy AND a worker runs a
    # scanning engine inside a network it declares (services/vms-worker).
    vms_scanning: Literal["disabled", "local_test_targets", "authorized_scopes"] = "disabled"
    # Platform-wide scan caps across ALL organizations (each organization's own policy cap still applies): they protect
    # PostgreSQL and the API from result ingestion bursts, and the single Greenbone stack from parallel tasks.
    vms_max_running_scans: int = Field(default=2, ge=1, le=32)
    vms_max_running_greenbone: int = Field(default=1, ge=1, le=8)
    # Wazuh agent groups that collect agents but never establish ownership (an agent's organization must come from a
    # group mapped to exactly one organization). Comma-separated; `default` is where Wazuh enrolls every new agent.
    wazuh_collection_groups: str = Field(default="default", pattern=r"^[A-Za-z0-9_.,-]{0,500}$")
    # Events the Wazuh manager generates itself (agent 000, not a registered syslog/agentless source): stored under the
    # platform organization (they describe NovrSOC's own infrastructure), or quarantined.
    manager_events: Literal["platform", "quarantine"] = "platform"
    # Brand Protection lookalike resolution source: unconfigured, or test_adapter (deterministic, no live DNS)
    brand_resolver: Literal["unconfigured", "test_adapter"] = "unconfigured"
    service_name: str = "novrsoc-api"

    # ---- organization portals (one shared deployment; the host selects branding and restricts sign-in, never grants)
    # Hosts that serve the central platform (Command Center, every staff sign-in). Comma separated, lower case.
    platform_hosts: str = Field(default="localhost,127.0.0.1,testserver", pattern=r"^[a-z0-9.,:-]{1,1000}$")
    # Organization portals are <subdomain>.<portal_base_domain> (wildcard DNS and TLS). Empty = portals off.
    portal_base_domain: str = Field(default="", pattern=r"^$|^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    # Take the host from X-Forwarded-Host instead of Host: ONLY behind a proxy that overwrites it (the local Next.js
    # proxy in development). Production nginx passes the real Host and refuses unknown server names.
    trust_forwarded_host: bool = False
    # How links handed to people (invitations, installer downloads) are written.
    public_scheme: Literal["https", "http"] = "https"
    public_port: int = Field(default=0, ge=0, le=65535)          # 0: the scheme's default port
    public_platform_host: str = Field(default="", pattern=r"^$|^[a-z0-9.-]{1,253}$")
    invitation_ttl_hours: int = Field(default=72, ge=1, le=14 * 24)
    # NovrAgent enrollment is server-controlled: NovrSOC registers each agent on the NovrSIEM manager itself (manager_api:
    # a dedicated, least-privilege manager API user, WAZUH_ENROLLMENT_URL / _USER / _PASSWORD / _CA_CERT), in the
    # organization's provisioned group, against an organization-bound enrollment ticket. disabled = no installer.
    enrollment_mode: Literal["disabled", "manager_api"] = "disabled"
    enrollment_ticket_ttl_minutes: int = Field(default=60, ge=10, le=24 * 60)
    agent_manager_address: str = Field(default="", pattern=r"^$|^[A-Za-z0-9.-]{1,253}$")
    agent_manager_port: int = Field(default=1514, ge=1, le=65535)
    # Agent package version. Empty: the manager's own version (read from it). A value must not be newer than the
    # manager and must share its major version; otherwise installers are refused as incompatible.
    agent_version: str = Field(default="", pattern=r"^$|^[0-9]+\.[0-9]+\.[0-9]+$")
    # Scheduled agent -> asset inventory sync per organization (jobs worker). 0 = only on demand.
    asset_sync_interval_minutes: int = Field(default=60, ge=0, le=7 * 24 * 60)
    # Abuse protection of the public endpoints (portal identity, invitations, installer, enrollment).
    rate_limits_enabled: bool = True
    # Where devices send syslog (shown in the device guides).
    syslog_collector_address: str = Field(default="", pattern=r"^$|^[A-Za-z0-9.-]{1,253}$")
    syslog_collector_port: int = Field(default=514, ge=1, le=65535)

    @field_validator("database_url")
    @classmethod
    def _db_scheme(cls, v: SecretStr) -> SecretStr:
        if not v.get_secret_value().startswith("postgresql+psycopg://"):
            raise ConfigError("NOVRSOC_DATABASE_URL must use the postgresql+psycopg:// scheme")
        return v

    @property
    def platform_host_set(self) -> frozenset[str]:
        return frozenset(h.strip() for h in self.platform_hosts.split(",") if h.strip())

    @property
    def collection_groups(self) -> frozenset[str]:
        return frozenset(g.strip() for g in self.wazuh_collection_groups.split(",") if g.strip())

    @property
    def database_host(self) -> str:
        return (urlsplit(self.database_url.get_secret_value().replace("+psycopg", "")).hostname or "").lower()

    @model_validator(mode="after")
    def _guards(self) -> "Settings":
        prod_hosts = {h.strip().lower() for h in self.production_database_hosts.split(",") if h.strip()}
        if self.database_host in prod_hosts and self.env != "production":
            raise ConfigError("NOVRSOC_DATABASE_URL names a production database host but NOVRSOC_ENV is not production")
        if self.env in ("development", "test") and self.database_host not in LOOPBACK_HOSTS:
            raise ConfigError("NOVRSOC_DATABASE_URL must point at a loopback host in development/test")
        if self.env == "production" and not self.session_cookie_secure:
            raise ConfigError("NOVRSOC_SESSION_COOKIE_SECURE must be true in production")
        if self.wazuh_mode == "local_fixture" and self.env not in ("development", "test"):
            raise ConfigError("NOVRSOC_WAZUH_MODE=local_fixture is only allowed in development/test")
        if self.nhai_backend == "test_adapter" and self.env not in ("development", "test"):
            raise ConfigError("NOVRSOC_NHAI_BACKEND=test_adapter is only allowed in development/test")
        if self.vms_scanning == "local_test_targets" and self.env not in ("development", "test"):
            raise ConfigError("NOVRSOC_VMS_SCANNING=local_test_targets is only allowed in development/test")
        if self.brand_resolver == "test_adapter" and self.env not in ("development", "test"):
            raise ConfigError("NOVRSOC_BRAND_RESOLVER=test_adapter is only allowed in development/test")
        if self.env == "production" and self.trust_forwarded_host:
            raise ConfigError("NOVRSOC_TRUST_FORWARDED_HOST is a development setting: production nginx passes the real Host")
        if self.env == "production" and self.public_scheme != "https":
            raise ConfigError("NOVRSOC_PUBLIC_SCHEME must be https in production")
        if self.docs_enabled is None:
            self.docs_enabled = self.env != "production"
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]

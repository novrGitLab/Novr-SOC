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
    # SOAR execution bridge on Server 1 (pilot: a local bridge on loopback with the simulated adapter). Unset = no
    # consequential step can be dispatched (it fails honestly; nothing executes).
    soar_bridge_url: str = ""
    soar_bridge_key_id: str = Field(default="server2-soar", pattern=r"^[a-z0-9_.-]{1,60}$")
    soar_bridge_key_file: str = ""
    soar_bridge_ca_cert: str = ""
    # VMS scanning: disabled, or local_test_targets (pilot: scopes limited to loopback and *.test / *.localhost names)
    vms_scanning: Literal["disabled", "local_test_targets"] = "disabled"
    # Brand Protection lookalike resolution source: unconfigured, or test_adapter (deterministic, no live DNS)
    brand_resolver: Literal["unconfigured", "test_adapter"] = "unconfigured"
    service_name: str = "novrsoc-api"

    @field_validator("database_url")
    @classmethod
    def _db_scheme(cls, v: SecretStr) -> SecretStr:
        if not v.get_secret_value().startswith("postgresql+psycopg://"):
            raise ConfigError("NOVRSOC_DATABASE_URL must use the postgresql+psycopg:// scheme")
        return v

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
        if self.docs_enabled is None:
            self.docs_enabled = self.env != "production"
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]

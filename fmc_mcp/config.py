"""Environment-based configuration for the Cisco FMC MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if not normalized:
        return default
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ConfigError(f"Cannot interpret {value!r} as a boolean.")


@dataclass(frozen=True)
class Settings:
    host: str
    username: str
    password: str
    domain_uuid: str | None
    verify_ssl: bool
    ca_bundle: str | None
    allow_writes: bool
    mcp_transport: str
    mcp_host: str
    mcp_port: int
    log_level: str
    timeout: float = 30.0

    @property
    def base_url(self) -> str:
        return self.host.rstrip("/")

    @property
    def verify(self) -> bool | str:
        return self.ca_bundle or self.verify_ssl


def load_settings(env_file: str | None = None) -> Settings:
    """Load settings from the environment, optionally reading a .env file."""
    if env_file:
        load_dotenv(env_file, override=False)
    else:
        # Load a local .env if present without overriding explicit env vars.
        local = Path.cwd() / ".env"
        if local.is_file():
            load_dotenv(local, override=False)

    host = (os.getenv("FMC_HOST") or "").strip().rstrip("/")
    username = (os.getenv("FMC_USERNAME") or "").strip()
    password = os.getenv("FMC_PASSWORD") or ""
    if not host:
        raise ConfigError("FMC_HOST is required (for example https://fmc.example.local).")
    if not host.startswith("https://") and not host.startswith("http://"):
        raise ConfigError("FMC_HOST must include a scheme, for example https://fmc.example.local.")
    if not username or not password:
        raise ConfigError("FMC_USERNAME and FMC_PASSWORD are required.")

    ca_bundle = (os.getenv("FMC_CA_BUNDLE") or "").strip() or None
    if ca_bundle and not Path(ca_bundle).is_file():
        raise ConfigError(f"FMC_CA_BUNDLE does not exist: {ca_bundle}")

    transport = (os.getenv("MCP_TRANSPORT") or "http").strip().lower()
    if transport in {"streamable-http", "streamable_http"}:
        transport = "http"

    return Settings(
        host=host,
        username=username,
        password=password,
        domain_uuid=(os.getenv("FMC_DOMAIN_UUID") or "").strip() or None,
        verify_ssl=_as_bool(os.getenv("FMC_VERIFY_SSL"), default=True),
        ca_bundle=ca_bundle,
        allow_writes=_as_bool(os.getenv("FMC_ALLOW_WRITES"), default=False),
        mcp_transport=transport,
        mcp_host=(os.getenv("MCP_HOST") or "127.0.0.1").strip(),
        mcp_port=int(os.getenv("MCP_PORT") or "8000"),
        log_level=(os.getenv("LOG_LEVEL") or "INFO").strip().upper(),
    )


def require_writes(settings: Settings) -> None:
    if not settings.allow_writes:
        raise PermissionError(
            "Writes are disabled. Set FMC_ALLOW_WRITES=true to enable create/update/delete "
            "operations, and use only against a lab/non-production FMC after review."
        )

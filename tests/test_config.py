import os

import pytest

from fmc_mcp.config import ConfigError, load_settings, require_writes


def test_load_settings_requires_host(monkeypatch):
    monkeypatch.delenv("FMC_HOST", raising=False)
    monkeypatch.setenv("FMC_USERNAME", "u")
    monkeypatch.setenv("FMC_PASSWORD", "p")
    with pytest.raises(ConfigError):
        load_settings("/nonexistent/.env")


def test_load_settings_defaults(monkeypatch):
    monkeypatch.setenv("FMC_HOST", "https://fmc.example.local/")
    monkeypatch.setenv("FMC_USERNAME", "api")
    monkeypatch.setenv("FMC_PASSWORD", "secret")
    monkeypatch.delenv("FMC_ALLOW_WRITES", raising=False)
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    s = load_settings("/nonexistent/.env")
    assert s.base_url == "https://fmc.example.local"
    assert s.allow_writes is False
    assert s.mcp_transport == "http"  # normalized


def test_require_writes(monkeypatch):
    monkeypatch.setenv("FMC_HOST", "https://fmc.example.local")
    monkeypatch.setenv("FMC_USERNAME", "api")
    monkeypatch.setenv("FMC_PASSWORD", "secret")
    monkeypatch.setenv("FMC_ALLOW_WRITES", "false")
    s = load_settings("/nonexistent/.env")
    with pytest.raises(PermissionError):
        require_writes(s)

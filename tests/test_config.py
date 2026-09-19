"""
Tests for Pydantic Settings configuration loading.
"""

import os
import pytest
from unittest.mock import patch


def test_default_settings():
    """Settings should load with safe defaults when no .env is present."""
    from heimdall.core.config import HeimdallSettings
    s = HeimdallSettings()
    assert s.neo4j_uri == "bolt://localhost:7687"
    assert s.cache_ttl_seconds == 3600
    assert s.cache_max_size == 2048
    assert s.cache_enabled is True
    assert s.heimdall_persist is False
    assert s.alert_threat_threshold == 75
    assert s.ui_enabled is True


def test_api_keys_none_by_default():
    """All API keys should default to None (no required keys)."""
    from heimdall.core.config import HeimdallSettings
    s = HeimdallSettings()
    assert s.shodan_api_key is None
    assert s.virustotal_api_key is None
    assert s.abuseipdb_api_key is None
    assert s.heimdall_auth_token is None
    assert s.alert_webhook_url is None


def test_settings_from_env():
    """Settings should pick up values from environment variables."""
    env_overrides = {
        "SHODAN_API_KEY": "test_shodan_key",
        "VIRUSTOTAL_API_KEY": "test_vt_key",
        "CACHE_TTL_SECONDS": "1800",
        "HEIMDALL_PERSIST": "true",
        "ALERT_THREAT_THRESHOLD": "60",
    }
    with patch.dict(os.environ, env_overrides):
        from heimdall.core.config import HeimdallSettings
        s = HeimdallSettings()
        assert s.shodan_api_key == "test_shodan_key"
        assert s.virustotal_api_key == "test_vt_key"
        assert s.cache_ttl_seconds == 1800
        assert s.heimdall_persist is True
        assert s.alert_threat_threshold == 60


def test_auth_token_detection():
    """Auth should be considered disabled when token is empty string."""
    from heimdall.core.config import HeimdallSettings
    s = HeimdallSettings()
    assert not s.heimdall_auth_token  # Falsy


def test_sqlite_path_default():
    """SQLite DB path should have a sensible default."""
    from heimdall.core.config import HeimdallSettings
    s = HeimdallSettings()
    assert s.sqlite_db_path == "heimdall_investigations.db"

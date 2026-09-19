"""
Heimdall Global Configuration.

Loads settings from environment variables or .env file via Pydantic Settings.
All fields are optional; missing API keys will gracefully skip authenticated transforms.
"""

from __future__ import annotations

import functools
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class HeimdallSettings(BaseSettings):
    """
    Central configuration object populated from environment variables or .env.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── OSINT API Keys (all optional) ────────────────────────────────────────
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan REST API key for deep host enrichment")
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key (v3) for reputation lookups")
    abuseipdb_api_key: Optional[str] = Field(default=None, description="AbuseIPDB API key for IP abuse confidence scores")

    # ── Neo4j Graph Database ──────────────────────────────────────────────────
    neo4j_uri: str = Field(default="bolt://localhost:7687", description="Neo4j Bolt URI")
    neo4j_user: str = Field(default="neo4j", description="Neo4j username")
    neo4j_password: str = Field(default="password", description="Neo4j password")
    neo4j_database: str = Field(default="neo4j", description="Neo4j target database")

    # ── API Security ──────────────────────────────────────────────────────────
    heimdall_auth_token: Optional[str] = Field(
        default=None,
        description="Bearer token for API authentication. When set, all non-health endpoints require Authorization header.",
    )

    # ── Transform Result Cache ────────────────────────────────────────────────
    cache_ttl_seconds: int = Field(default=3600, description="TTL in seconds for cached transform results (default: 1h)")
    cache_max_size: int = Field(default=2048, description="Maximum number of entries in the result cache")
    cache_enabled: bool = Field(default=True, description="Master switch for transform result caching")

    # ── Investigation Persistence ─────────────────────────────────────────────
    heimdall_persist: bool = Field(default=False, description="Persist investigation graphs to SQLite when True")
    sqlite_db_path: str = Field(default="heimdall_investigations.db", description="Path to the SQLite database file")

    # ── Webhook Alerting ──────────────────────────────────────────────────────
    alert_webhook_url: Optional[str] = Field(default=None, description="HTTP endpoint for webhook alert notifications")
    alert_threat_threshold: int = Field(default=75, description="Minimum threat score (0-100) that triggers a webhook alert")

    # ── HTTP Transport ────────────────────────────────────────────────────────
    rate_limit_requests_per_minute: int = Field(default=60, description="Max outbound OSINT requests per minute")
    http_timeout_seconds: float = Field(default=10.0, description="Per-request HTTP timeout in seconds")

    # ── Static UI ─────────────────────────────────────────────────────────────
    ui_enabled: bool = Field(default=True, description="Serve the web UI at /ui when True")

    # ── Phase 5: Active Recon (opt-in, disabled by default) ───────────────────
    active_recon: bool = Field(
        default=False,
        description="Enable active recon transforms (TLS handshakes, banner grabs). MUST be explicitly enabled.",
    )
    active_recon_rate_limit: float = Field(
        default=1.0,
        description="Maximum active connections per second during recon (default: 1.0 conn/s)",
    )
    active_recon_ports: List[int] = Field(
        default_factory=lambda: [21, 22, 25, 80, 110, 143, 443, 465, 587],
        description="Port list for banner grabbing (default covers common mail/web/ssh ports)",
    )

    # ── Phase 5: LLM Smart Pivot (generic OpenAI-compatible endpoint) ─────────
    llm_base_url: Optional[str] = Field(
        default=None,
        description="OpenAI-compatible LLM endpoint. Examples: http://localhost:11434/v1 (Ollama), "
                    "https://api.openai.com/v1 (OpenAI), "
                    "https://generativelanguage.googleapis.com/v1beta/openai/ (Gemini)",
    )
    llm_api_key: Optional[str] = Field(
        default=None,
        description="API key for the LLM endpoint. Leave blank for local Ollama (no auth required).",
    )
    llm_model: str = Field(
        default="gpt-4o-mini",
        description="Model identifier for the LLM ranker (e.g. gpt-4o-mini, gemma3, gemini-2.0-flash)",
    )

    # ── Phase 5: Smart Pivot Agent ────────────────────────────────────────────
    smart_pivot: bool = Field(
        default=False,
        description="Enable heuristic-guided transform selection instead of blind BFS crawl",
    )
    smart_pivot_top_k: int = Field(
        default=3,
        description="Max transforms to run per node when smart pivot is enabled",
    )
    pivot_rules_path: str = Field(
        default="config/pivot_rules.yaml",
        description="Path to YAML file defining custom smart pivot priority rules",
    )

    # ── Phase 5: Monitoring / Scheduling ─────────────────────────────────────
    monitor_enabled: bool = Field(
        default=True,
        description="Enable the background monitoring scheduler daemon",
    )


@functools.lru_cache(maxsize=1)
def get_settings() -> HeimdallSettings:
    """
    Returns the singleton settings instance, cached after first load.
    Call ``get_settings.cache_clear()`` in tests to reload from a new .env.
    """
    return HeimdallSettings()


# Convenience alias for import ergonomics
settings = get_settings()

"""
SOC Copilot configuration.

Only Azure OpenAI vars are required at startup — the app will refuse to start
without them. All other integration vars (Sentinel, Graph, Splunk, Slack,
Teams, Search) are optional at startup and validated lazily when the relevant
agent is first invoked via validate_for_agent().
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

# Maps each agent name to the settings fields it requires.
# Agents that only need Azure OpenAI (always required) have an empty list.
_AGENT_REQUIRED_FIELDS: dict[str, list[str]] = {
    "ingest": [
        "sentinel_workspace_id",
        "sentinel_subscription_id",
        "sentinel_resource_group",
    ],
    "enrich": [
        "graph_tenant_id",
        "graph_client_id",
        "graph_client_secret",
    ],
    "summarize": [],
    "guidance": [
        "azure_search_endpoint",
        "azure_search_api_key",
    ],
    "query": [],
    "delivery_slack": [
        "slack_bot_token",
        "slack_signing_secret",
    ],
    "delivery_teams": [
        "teams_app_id",
        "teams_app_password",
    ],
    "splunk": [
        "splunk_host",
        "splunk_token",
    ],
}

_KNOWN_AGENTS = set(_AGENT_REQUIRED_FIELDS.keys())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Required at startup — ValidationError raised immediately if missing
    # ------------------------------------------------------------------
    azure_openai_endpoint: str
    azure_openai_api_key: str
    azure_openai_deployment_name: str
    azure_openai_api_version: str = "2024-02-15-preview"

    # ------------------------------------------------------------------
    # Optional integrations — validated lazily per agent
    # ------------------------------------------------------------------

    # Microsoft Sentinel
    sentinel_workspace_id: Optional[str] = None
    sentinel_subscription_id: Optional[str] = None
    sentinel_resource_group: Optional[str] = None
    sentinel_api_key: Optional[str] = None  # prod uses Managed Identity

    # Microsoft Graph / Entra ID
    graph_tenant_id: Optional[str] = None
    graph_client_id: Optional[str] = None
    graph_client_secret: Optional[str] = None

    # Splunk
    splunk_host: Optional[str] = None
    splunk_token: Optional[str] = None

    # Slack
    slack_bot_token: Optional[str] = None
    slack_signing_secret: Optional[str] = None
    slack_app_token: Optional[str] = None
    slack_alert_channel: str = "#soc-alerts"

    # Microsoft Teams
    teams_app_id: Optional[str] = None
    teams_app_password: Optional[str] = None

    # Azure AI Search (RAG)
    azure_search_endpoint: Optional[str] = None
    azure_search_api_key: Optional[str] = None
    azure_search_index_name: str = "soc-copilot-playbooks"

    # App
    soc_copilot_api_url: str = "http://localhost:8000"

    def validate_for_agent(self, agent_name: str) -> None:
        """Assert that all settings required by *agent_name* are present.

        Call this at the top of each agent's run() before doing any work.
        Raises RuntimeError with a specific, actionable message if any
        required environment variable is missing.

        Raises:
            ValueError: If *agent_name* is not a recognised agent.
            RuntimeError: If one or more required settings are absent.
        """
        if agent_name not in _KNOWN_AGENTS:
            raise ValueError(
                f"Unknown agent '{agent_name}'. "
                f"Known agents: {', '.join(sorted(_KNOWN_AGENTS))}"
            )

        required = _AGENT_REQUIRED_FIELDS[agent_name]
        missing = [
            field for field in required if getattr(self, field, None) is None
        ]

        if missing:
            missing_vars = ", ".join(m.upper() for m in missing)
            raise RuntimeError(
                f"Agent '{agent_name}' cannot start: "
                f"missing required environment variables: {missing_vars}. "
                f"Set these in your .env file (see .env.example)."
            )


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings singleton.

    In tests, clear the cache with get_settings.cache_clear() after
    patching environment variables, or instantiate Settings() directly
    with _env_file=None to avoid reading the .env file.
    """
    return Settings()

"""Tests for src/config.py — Settings and validate_for_agent."""

import pytest
from pydantic import ValidationError

from src.config import Settings


def _minimal_settings(**overrides) -> Settings:
    """Return a Settings instance with only the required Azure OpenAI vars."""
    return Settings(
        azure_openai_endpoint="https://test.openai.azure.com/",
        azure_openai_api_key="test-key-123",
        azure_openai_deployment_name="gpt-4o",
        _env_file=None,
        **overrides,
    )


class TestStartupValidation:
    def test_fails_without_azure_openai_endpoint(self):
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                azure_openai_api_key="key",
                azure_openai_deployment_name="gpt-4o",
                _env_file=None,
            )
        fields = {e["loc"][0] for e in exc_info.value.errors()}
        assert "azure_openai_endpoint" in fields

    def test_fails_without_azure_openai_api_key(self):
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                azure_openai_endpoint="https://test.openai.azure.com/",
                azure_openai_deployment_name="gpt-4o",
                _env_file=None,
            )
        fields = {e["loc"][0] for e in exc_info.value.errors()}
        assert "azure_openai_api_key" in fields

    def test_fails_without_deployment_name(self):
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                azure_openai_endpoint="https://test.openai.azure.com/",
                azure_openai_api_key="key",
                _env_file=None,
            )
        fields = {e["loc"][0] for e in exc_info.value.errors()}
        assert "azure_openai_deployment_name" in fields

    def test_succeeds_with_only_azure_openai_vars(self):
        settings = _minimal_settings()
        assert settings.azure_openai_endpoint == "https://test.openai.azure.com/"
        assert settings.azure_openai_deployment_name == "gpt-4o"

    def test_optional_vars_default_to_none(self):
        settings = _minimal_settings()
        assert settings.sentinel_workspace_id is None
        assert settings.graph_tenant_id is None
        assert settings.splunk_host is None
        assert settings.slack_bot_token is None
        assert settings.teams_app_id is None
        assert settings.azure_search_endpoint is None

    def test_default_api_version(self):
        settings = _minimal_settings()
        assert settings.azure_openai_api_version == "2024-02-15-preview"

    def test_default_slack_channel(self):
        settings = _minimal_settings()
        assert settings.slack_alert_channel == "#soc-alerts"


class TestValidateForAgent:
    def test_summarize_agent_always_passes(self):
        """SummarizeAgent only needs Azure OpenAI which is always required."""
        settings = _minimal_settings()
        settings.validate_for_agent("summarize")  # should not raise

    def test_query_agent_always_passes(self):
        settings = _minimal_settings()
        settings.validate_for_agent("query")

    def test_enrich_agent_passes_when_graph_vars_set(self):
        settings = _minimal_settings(
            graph_tenant_id="tenant-123",
            graph_client_id="client-456",
            graph_client_secret="secret-789",
        )
        settings.validate_for_agent("enrich")  # should not raise

    def test_enrich_agent_raises_when_graph_vars_missing(self):
        settings = _minimal_settings()
        with pytest.raises(RuntimeError) as exc_info:
            settings.validate_for_agent("enrich")
        error = str(exc_info.value)
        assert "enrich" in error
        assert "GRAPH_TENANT_ID" in error
        assert "GRAPH_CLIENT_ID" in error
        assert "GRAPH_CLIENT_SECRET" in error

    def test_ingest_agent_raises_when_sentinel_vars_missing(self):
        settings = _minimal_settings()
        with pytest.raises(RuntimeError) as exc_info:
            settings.validate_for_agent("ingest")
        error = str(exc_info.value)
        assert "ingest" in error
        assert "SENTINEL_WORKSPACE_ID" in error

    def test_ingest_agent_passes_when_sentinel_vars_set(self):
        settings = _minimal_settings(
            sentinel_workspace_id="ws-001",
            sentinel_subscription_id="sub-001",
            sentinel_resource_group="rg-soc",
        )
        settings.validate_for_agent("ingest")

    def test_guidance_agent_raises_when_search_missing(self):
        settings = _minimal_settings()
        with pytest.raises(RuntimeError) as exc_info:
            settings.validate_for_agent("guidance")
        error = str(exc_info.value)
        assert "AZURE_SEARCH_ENDPOINT" in error

    def test_delivery_slack_raises_when_slack_missing(self):
        settings = _minimal_settings()
        with pytest.raises(RuntimeError) as exc_info:
            settings.validate_for_agent("delivery_slack")
        error = str(exc_info.value)
        assert "SLACK_BOT_TOKEN" in error

    def test_delivery_teams_raises_when_teams_missing(self):
        settings = _minimal_settings()
        with pytest.raises(RuntimeError) as exc_info:
            settings.validate_for_agent("delivery_teams")
        error = str(exc_info.value)
        assert "TEAMS_APP_ID" in error

    def test_unknown_agent_raises_value_error(self):
        settings = _minimal_settings()
        with pytest.raises(ValueError) as exc_info:
            settings.validate_for_agent("nonexistent_agent")
        assert "nonexistent_agent" in str(exc_info.value)

    def test_error_message_mentions_env_example(self):
        """Error messages should guide the developer to .env.example."""
        settings = _minimal_settings()
        with pytest.raises(RuntimeError) as exc_info:
            settings.validate_for_agent("enrich")
        assert ".env" in str(exc_info.value)

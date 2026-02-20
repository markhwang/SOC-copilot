"""Tests for src/agents/summarize.py — no live Azure OpenAI calls."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.agents import summarize
from src.config import Settings
from src.models.agent_io import SummarizeInput
from src.models.alert import AlertPayload, AlertSource, Severity, AlertEntities, AlertFile
from src.models.enrichment import EnrichmentResult, EntraUser, CMDBAsset, ThreatIntelHit


@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    """Provide minimal Settings for every test — no .env file needed."""
    settings = Settings(
        azure_openai_endpoint="https://test.openai.azure.com/",
        azure_openai_api_key="test-key-123",
        azure_openai_deployment_name="gpt-4o",
        _env_file=None,
    )
    monkeypatch.setattr("src.agents.summarize.get_settings", lambda: settings)
    return settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert(**overrides) -> AlertPayload:
    defaults = dict(
        alert_id="SENT-2025-01-30-0042",
        source=AlertSource.SENTINEL,
        timestamp=datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        title="Suspicious PowerShell execution following phishing email",
        description="User opened macro-enabled doc triggering PowerShell.",
        mitre_tactics=["TA0001", "TA0002"],
        mitre_techniques=["T1566.001", "T1059.001"],
        entities=AlertEntities(
            users=["john.doe@corp.com"],
            hosts=["WS-JD-001"],
            ips=["203.0.113.50"],
            files=[AlertFile(name="Q4_Report.docm", hash="a1b2c3d4")],
            domains=["malicious-c2.com"],
        ),
    )
    defaults.update(overrides)
    return AlertPayload(**defaults)


def make_enrichment(**overrides) -> EnrichmentResult:
    defaults = dict(alert_id="SENT-2025-01-30-0042")
    defaults.update(overrides)
    return EnrichmentResult(**defaults)


def make_valid_llm_response(**overrides) -> str:
    data = {
        "summary": "A Finance user opened a phishing attachment triggering PowerShell execution.",
        "risk_score": 9,
        "confidence_score": 0.85,
        "risk_reasoning": "Confirmed execution chain with known FIN7 C2 infrastructure.",
        "key_findings": [
            "Macro-enabled document triggered PowerShell",
            "C2 domain matches FIN7 infrastructure",
        ],
        "escalation_recommended": True,
        "escalation_reason": "Risk score 9 with confirmed execution and APT attribution.",
    }
    data.update(overrides)
    return json.dumps(data)


def make_input() -> SummarizeInput:
    return SummarizeInput(alert=make_alert(), enrichment=make_enrichment())


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_returns_summary_result():
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        output = await summarize.run(make_input())

    assert output.summary.alert_id == "SENT-2025-01-30-0042"
    assert output.summary.risk_score == 9
    assert output.summary.confidence_score == 0.85
    assert output.summary.escalation_recommended is True
    assert len(output.summary.key_findings) == 2


@pytest.mark.asyncio
async def test_run_alert_id_comes_from_input_not_model():
    """alert_id must be set from the input AlertPayload, not trusted from model output."""
    response_with_wrong_id = make_valid_llm_response()
    # Even if model returns no alert_id field (json_object mode), we inject it ourselves
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = response_with_wrong_id
        output = await summarize.run(make_input())

    assert output.summary.alert_id == "SENT-2025-01-30-0042"


@pytest.mark.asyncio
async def test_run_low_risk_no_escalation():
    response = make_valid_llm_response(
        risk_score=2,
        confidence_score=0.9,
        risk_reasoning="Matches known false positive pattern.",
        escalation_recommended=False,
        escalation_reason=None,
    )
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = response
        output = await summarize.run(make_input())

    assert output.summary.risk_score == 2
    assert output.summary.escalation_recommended is False
    assert output.summary.escalation_reason is None


@pytest.mark.asyncio
async def test_run_passes_both_prompts_to_openai():
    """_call_openai must receive a non-empty system and user prompt."""
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(make_input())

    mock_call.assert_awaited_once()
    system_prompt, user_prompt = mock_call.call_args.args
    assert len(system_prompt) > 100     # system prompt is substantial
    assert len(user_prompt) > 50        # user prompt has alert content


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_invalid_json_raises_value_error():
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = "not valid json {{"
        with pytest.raises(ValueError, match="invalid JSON"):
            await summarize.run(make_input())


@pytest.mark.asyncio
async def test_run_invalid_json_error_includes_raw_response():
    bad_raw = "I cannot process this request."
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = bad_raw
        with pytest.raises(ValueError) as exc_info:
            await summarize.run(make_input())
    assert bad_raw in str(exc_info.value)


@pytest.mark.asyncio
async def test_run_schema_violation_raises_value_error():
    """risk_score out of 1-10 range should raise ValueError, not silently pass."""
    bad_response = make_valid_llm_response(risk_score=99)
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = bad_response
        with pytest.raises(ValueError, match="schema"):
            await summarize.run(make_input())


@pytest.mark.asyncio
async def test_run_missing_required_field_raises_value_error():
    """Model omitting a required field should raise ValueError."""
    incomplete = json.dumps({
        "summary": "Test summary.",
        "risk_score": 5,
        # missing confidence_score, risk_reasoning, key_findings, escalation_recommended
    })
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = incomplete
        with pytest.raises(ValueError):
            await summarize.run(make_input())


# ---------------------------------------------------------------------------
# Prompt content verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_user_prompt_contains_alert_title():
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(make_input())

    _, user_prompt = mock_call.call_args.args
    assert "Suspicious PowerShell execution following phishing email" in user_prompt


@pytest.mark.asyncio
async def test_user_prompt_contains_mitre_tactics():
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(make_input())

    _, user_prompt = mock_call.call_args.args
    assert "TA0001" in user_prompt
    assert "T1566.001" in user_prompt


@pytest.mark.asyncio
async def test_user_prompt_contains_entities():
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(make_input())

    _, user_prompt = mock_call.call_args.args
    assert "john.doe@corp.com" in user_prompt
    assert "WS-JD-001" in user_prompt
    assert "203.0.113.50" in user_prompt
    assert "Q4_Report.docm" in user_prompt


@pytest.mark.asyncio
async def test_user_prompt_includes_enrichment_errors():
    enrichment_with_errors = make_enrichment(
        enrichment_errors=["CMDB timeout for WS-JD-001", "Graph API rate limit exceeded"],
    )
    inp = SummarizeInput(alert=make_alert(), enrichment=enrichment_with_errors)

    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(inp)

    _, user_prompt = mock_call.call_args.args
    assert "Enrichment Gaps" in user_prompt
    assert "CMDB timeout" in user_prompt
    assert "Graph API rate limit" in user_prompt


@pytest.mark.asyncio
async def test_user_prompt_includes_user_context():
    enrichment_with_user = make_enrichment(
        users={
            "john.doe@corp.com": EntraUser(
                upn="john.doe@corp.com",
                department="Finance",
                job_title="Senior Financial Analyst",
                mfa_enabled=True,
                risk_level="low",
            )
        }
    )
    inp = SummarizeInput(alert=make_alert(), enrichment=enrichment_with_user)

    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(inp)

    _, user_prompt = mock_call.call_args.args
    assert "Finance" in user_prompt
    assert "Senior Financial Analyst" in user_prompt
    assert "MFA" in user_prompt


@pytest.mark.asyncio
async def test_user_prompt_includes_threat_intel():
    enrichment_with_ti = make_enrichment(
        threat_intel=[
            ThreatIntelHit(
                ioc_value="203.0.113.50",
                ioc_type="ip",
                reputation="malicious",
                threat_actor="FIN7",
                confidence=0.78,
                source="misp",
            )
        ]
    )
    inp = SummarizeInput(alert=make_alert(), enrichment=enrichment_with_ti)

    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(inp)

    _, user_prompt = mock_call.call_args.args
    assert "FIN7" in user_prompt
    assert "203.0.113.50" in user_prompt
    assert "malicious" in user_prompt


@pytest.mark.asyncio
async def test_user_prompt_includes_asset_context():
    enrichment_with_asset = make_enrichment(
        assets={
            "WS-JD-001": CMDBAsset(
                hostname="WS-JD-001",
                criticality="high",
                business_unit="Corporate Finance",
                environment="prod",
            )
        }
    )
    inp = SummarizeInput(alert=make_alert(), enrichment=enrichment_with_asset)

    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(inp)

    _, user_prompt = mock_call.call_args.args
    assert "Corporate Finance" in user_prompt
    assert "prod" in user_prompt


@pytest.mark.asyncio
async def test_system_prompt_contains_rubric():
    with patch("src.agents.summarize._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = make_valid_llm_response()
        await summarize.run(make_input())

    system_prompt, _ = mock_call.call_args.args
    assert "risk_score" in system_prompt
    assert "confidence_score" in system_prompt
    assert "escalation_recommended" in system_prompt

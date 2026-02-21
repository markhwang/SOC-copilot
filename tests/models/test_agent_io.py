"""Tests for src/models/agent_io.py — all agent I/O contracts."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.models.agent_io import (
    DeliveryInput,
    DeliveryOutput,
    EnrichInput,
    EnrichOutput,
    GuidanceInput,
    GuidanceOutput,
    IngestInput,
    IngestOutput,
    QueryInput,
    QueryOutput,
    SummarizeInput,
    SummarizeOutput,
)
from src.models.alert import AlertPayload, AlertSource, Severity
from src.models.enrichment import EnrichmentResult
from src.models.response import GuidanceResult, SummaryResult, TriageResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_alert() -> AlertPayload:
    return AlertPayload(
        alert_id="test-001",
        source=AlertSource.SENTINEL,
        timestamp=datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        title="Test Alert",
        description="Test description.",
    )


def make_enrichment() -> EnrichmentResult:
    return EnrichmentResult(alert_id="test-001")


def make_summary() -> SummaryResult:
    return SummaryResult(
        alert_id="test-001",
        summary="Short summary.",
        risk_score=5,
        confidence_score=0.7,
        risk_reasoning="Medium risk — insufficient context.",
        escalation_recommended=False,
    )


def make_guidance() -> GuidanceResult:
    return GuidanceResult(alert_id="test-001")


def make_triage() -> TriageResult:
    return TriageResult(
        alert_id="test-001",
        alert=make_alert(),
        enrichment=make_enrichment(),
        summary=make_summary(),
        guidance=make_guidance(),
    )


# ---------------------------------------------------------------------------
# IngestAgent
# ---------------------------------------------------------------------------

class TestIngestIO:
    def test_input_minimal(self):
        inp = IngestInput(raw_payload={"name": "inc-001", "properties": {"severity": "High"}})
        assert inp.source_hint is None
        assert inp.raw_payload["name"] == "inc-001"

    def test_input_with_source_hint(self):
        inp = IngestInput(raw_payload={}, source_hint=AlertSource.SENTINEL)
        assert inp.source_hint == AlertSource.SENTINEL

    def test_input_with_splunk_hint(self):
        inp = IngestInput(raw_payload={}, source_hint=AlertSource.SPLUNK)
        assert inp.source_hint == AlertSource.SPLUNK

    def test_output_minimal(self):
        out = IngestOutput(alert=make_alert())
        assert out.alert.alert_id == "test-001"
        assert out.parse_warnings == []

    def test_output_with_warnings(self):
        out = IngestOutput(
            alert=make_alert(),
            parse_warnings=["mitre_tactics field missing — defaulting to []"],
        )
        assert len(out.parse_warnings) == 1

    def test_input_requires_raw_payload(self):
        with pytest.raises(ValidationError):
            IngestInput()


# ---------------------------------------------------------------------------
# EnrichAgent
# ---------------------------------------------------------------------------

class TestEnrichIO:
    def test_input(self):
        inp = EnrichInput(alert=make_alert())
        assert inp.alert.alert_id == "test-001"

    def test_output(self):
        out = EnrichOutput(enrichment=make_enrichment())
        assert out.enrichment.alert_id == "test-001"

    def test_input_requires_alert(self):
        with pytest.raises(ValidationError):
            EnrichInput()


# ---------------------------------------------------------------------------
# SummarizeAgent
# ---------------------------------------------------------------------------

class TestSummarizeIO:
    def test_input(self):
        inp = SummarizeInput(alert=make_alert(), enrichment=make_enrichment())
        assert inp.alert.alert_id == "test-001"
        assert inp.enrichment.alert_id == "test-001"

    def test_output(self):
        out = SummarizeOutput(summary=make_summary())
        assert out.summary.risk_score == 5

    def test_input_requires_both_fields(self):
        with pytest.raises(ValidationError):
            SummarizeInput(alert=make_alert())  # missing enrichment

    def test_output_risk_score_propagated(self):
        summary = SummaryResult(
            alert_id="test-001",
            summary="Critical threat.",
            risk_score=10,
            confidence_score=0.95,
            risk_reasoning="Confirmed APT activity.",
            escalation_recommended=True,
            escalation_reason="Active compromise.",
        )
        out = SummarizeOutput(summary=summary)
        assert out.summary.risk_score == 10
        assert out.summary.escalation_recommended is True


# ---------------------------------------------------------------------------
# GuidanceAgent
# ---------------------------------------------------------------------------

class TestGuidanceIO:
    def test_input_minimal(self):
        inp = GuidanceInput(alert=make_alert())
        assert inp.rag_context == []

    def test_input_with_rag_context(self):
        chunks = ["Playbook: Isolate endpoint immediately.", "ATT&CK T1566: Spearphishing..."]
        inp = GuidanceInput(alert=make_alert(), rag_context=chunks)
        assert len(inp.rag_context) == 2
        assert "Playbook" in inp.rag_context[0]

    def test_output(self):
        out = GuidanceOutput(guidance=make_guidance())
        assert out.guidance.alert_id == "test-001"

    def test_input_requires_alert(self):
        with pytest.raises(ValidationError):
            GuidanceInput()


# ---------------------------------------------------------------------------
# QueryAgent
# ---------------------------------------------------------------------------

class TestQueryIO:
    def test_input_minimal(self):
        inp = QueryInput(question="Show me failed logins for this user in the last 24 hours.")
        assert inp.target_platform == "both"
        assert inp.alert is None
        assert inp.execute is False

    def test_input_with_alert_context(self):
        inp = QueryInput(
            question="Did the C2 connection succeed?",
            alert=make_alert(),
            target_platform="kql",
        )
        assert inp.alert.alert_id == "test-001"
        assert inp.target_platform == "kql"

    def test_input_spl_platform(self):
        inp = QueryInput(question="Any lateral movement?", target_platform="spl")
        assert inp.target_platform == "spl"

    def test_input_execute_flag(self):
        inp = QueryInput(question="Show failed logins.", execute=True)
        assert inp.execute is True

    def test_output_with_both_queries(self):
        out = QueryOutput(
            kql="SigninLogs | where UserPrincipalName == 'user@corp.com'",
            spl="index=azure_signin user=user@corp.com",
            explanation="Retrieves sign-in events for the specified user.",
        )
        assert out.kql is not None
        assert out.spl is not None
        assert out.performance_notes is None
        assert out.results is None
        assert out.results_truncated is False

    def test_output_kql_only(self):
        out = QueryOutput(
            kql="DeviceNetworkEvents | where RemoteIP == '203.0.113.50'",
            explanation="Network connections to the C2 IP.",
        )
        assert out.kql is not None
        assert out.spl is None

    def test_output_requires_explanation(self):
        with pytest.raises(ValidationError):
            QueryOutput(kql="SecurityEvent | take 10")

    def test_output_with_performance_notes(self):
        out = QueryOutput(
            kql="SecurityEvent | where TimeGenerated > ago(30d)",
            explanation="30-day lookback.",
            performance_notes="This query scans a large time range — add a where clause to narrow scope.",
        )
        assert out.performance_notes is not None

    def test_output_with_executed_results(self):
        out = QueryOutput(
            kql="SigninLogs | take 2",
            explanation="Sign-in events.",
            results=[
                {"TimeGenerated": "2025-01-30T14:28:00Z", "UserPrincipalName": "john.doe@corp.com", "ResultType": 0},
                {"TimeGenerated": "2025-01-30T14:30:00Z", "UserPrincipalName": "john.doe@corp.com", "ResultType": 50126},
            ],
            results_truncated=False,
        )
        assert len(out.results) == 2
        assert out.results_truncated is False

    def test_output_results_truncated_flag(self):
        out = QueryOutput(
            kql="SecurityEvent | take 1000",
            explanation="Large result set.",
            results=[{"EventID": 4625}] * 500,
            results_truncated=True,
        )
        assert out.results_truncated is True


# ---------------------------------------------------------------------------
# DeliveryAgent
# ---------------------------------------------------------------------------

class TestDeliveryIO:
    def test_input_minimal(self):
        inp = DeliveryInput(triage_result=make_triage())
        assert inp.channels == []

    def test_input_with_explicit_channels(self):
        inp = DeliveryInput(triage_result=make_triage(), channels=["slack", "teams"])
        assert "slack" in inp.channels
        assert "teams" in inp.channels

    def test_output_successful_delivery(self):
        out = DeliveryOutput(
            delivered_to=["slack"],
            message_ids={"slack": "C123456.1706619135.000200"},
        )
        assert out.delivered_to == ["slack"]
        assert out.message_ids["slack"] == "C123456.1706619135.000200"
        assert out.delivery_errors == []

    def test_output_partial_failure(self):
        out = DeliveryOutput(
            delivered_to=["slack"],
            message_ids={"slack": "C123456.789"},
            delivery_errors=["Teams delivery failed: connection timeout"],
        )
        assert len(out.delivery_errors) == 1
        assert "Teams" in out.delivery_errors[0]

    def test_output_defaults(self):
        out = DeliveryOutput()
        assert out.delivered_to == []
        assert out.message_ids == {}
        assert out.delivery_errors == []

    def test_input_requires_triage_result(self):
        with pytest.raises(ValidationError):
            DeliveryInput()

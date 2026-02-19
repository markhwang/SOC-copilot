"""Tests for src/models/response.py."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.models.alert import AlertPayload, AlertSource, Severity
from src.models.enrichment import EnrichmentResult
from src.models.response import (
    GuidanceResult,
    MitreMapping,
    SummaryResult,
    TriageResponse,
    TriageResult,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def make_alert() -> AlertPayload:
    return AlertPayload(
        alert_id="SENT-2025-01-30-0042",
        source=AlertSource.SENTINEL,
        timestamp=datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        title="Suspicious PowerShell execution following phishing email",
        description="User opened macro-enabled doc triggering PowerShell.",
    )


def make_enrichment() -> EnrichmentResult:
    return EnrichmentResult(alert_id="SENT-2025-01-30-0042")


def make_summary(risk_score: int = 9, confidence: float = 0.85) -> SummaryResult:
    return SummaryResult(
        alert_id="SENT-2025-01-30-0042",
        summary="A Finance user opened a phishing attachment triggering PowerShell execution.",
        risk_score=risk_score,
        confidence_score=confidence,
        risk_reasoning="Confirmed execution chain with FIN7 C2 at 78% confidence.",
        key_findings=[
            "Macro-enabled doc (Q4_Report.docm) triggered PowerShell",
            "C2 domain matches known FIN7 infrastructure",
        ],
        escalation_recommended=True,
        escalation_reason="Risk score 9/10 with confirmed execution and FIN7 attribution.",
    )


def make_guidance() -> GuidanceResult:
    return GuidanceResult(
        alert_id="SENT-2025-01-30-0042",
        mitre_mappings=[
            MitreMapping(
                tactic_id="TA0001",
                tactic_name="Initial Access",
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
            ),
            MitreMapping(
                tactic_id="TA0002",
                tactic_name="Execution",
                technique_id="T1059.001",
                technique_name="PowerShell",
            ),
        ],
        investigation_steps=[
            "Isolate workstation WS-JD-001 via Defender for Endpoint",
            "Check DeviceNetworkEvents for successful C2 connection",
        ],
        suggested_actions=[
            "Block sender domain suspicious-domain.com at email gateway",
            "Purge email from all mailboxes organization-wide",
        ],
        relevant_playbooks=["phishing-attachment.md"],
        mitre_context="T1566.001 → T1059.001 → T1105: Classic FIN7 initial access pattern.",
    )


# ---------------------------------------------------------------------------
# MitreMapping tests
# ---------------------------------------------------------------------------

class TestMitreMapping:
    def test_construction(self):
        mapping = MitreMapping(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1566.001",
            technique_name="Spearphishing Attachment",
        )
        assert mapping.tactic_id == "TA0001"
        assert mapping.technique_id == "T1566.001"


# ---------------------------------------------------------------------------
# SummaryResult tests
# ---------------------------------------------------------------------------

class TestSummaryResult:
    def test_valid_summary(self):
        summary = make_summary()
        assert summary.risk_score == 9
        assert summary.confidence_score == 0.85
        assert summary.escalation_recommended is True

    def test_risk_score_minimum(self):
        summary = make_summary(risk_score=1)
        assert summary.risk_score == 1

    def test_risk_score_maximum(self):
        summary = make_summary(risk_score=10)
        assert summary.risk_score == 10

    def test_risk_score_above_max_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            make_summary(risk_score=11)
        errors = exc_info.value.errors()
        assert any("risk_score" in str(e["loc"]) for e in errors)

    def test_risk_score_below_min_raises(self):
        with pytest.raises(ValidationError):
            make_summary(risk_score=0)

    def test_confidence_score_zero(self):
        summary = make_summary(confidence=0.0)
        assert summary.confidence_score == 0.0

    def test_confidence_score_one(self):
        summary = make_summary(confidence=1.0)
        assert summary.confidence_score == 1.0

    def test_confidence_above_one_raises(self):
        with pytest.raises(ValidationError):
            make_summary(confidence=1.01)

    def test_confidence_below_zero_raises(self):
        with pytest.raises(ValidationError):
            make_summary(confidence=-0.01)

    def test_no_escalation_reason_when_not_escalating(self):
        summary = SummaryResult(
            alert_id="x",
            summary="Low-severity noise.",
            risk_score=2,
            confidence_score=0.9,
            risk_reasoning="Matches known false positive pattern.",
            escalation_recommended=False,
        )
        assert summary.escalation_reason is None


# ---------------------------------------------------------------------------
# GuidanceResult tests
# ---------------------------------------------------------------------------

class TestGuidanceResult:
    def test_empty_guidance(self):
        guidance = GuidanceResult(alert_id="test-001")
        assert guidance.mitre_mappings == []
        assert guidance.investigation_steps == []
        assert guidance.suggested_actions == []
        assert guidance.relevant_playbooks == []
        assert guidance.mitre_context is None

    def test_full_guidance(self):
        guidance = make_guidance()
        assert len(guidance.mitre_mappings) == 2
        assert guidance.mitre_mappings[0].tactic_id == "TA0001"
        assert len(guidance.investigation_steps) == 2
        assert "phishing-attachment.md" in guidance.relevant_playbooks


# ---------------------------------------------------------------------------
# TriageResult tests
# ---------------------------------------------------------------------------

class TestTriageResult:
    def test_construction(self):
        triage = TriageResult(
            alert_id="SENT-2025-01-30-0042",
            alert=make_alert(),
            enrichment=make_enrichment(),
            summary=make_summary(),
            guidance=make_guidance(),
        )
        assert triage.alert_id == "SENT-2025-01-30-0042"
        assert triage.summary.risk_score == 9
        assert triage.processing_time_ms == 0

    def test_triaged_at_is_timezone_aware(self):
        triage = TriageResult(
            alert_id="x",
            alert=make_alert(),
            enrichment=make_enrichment(),
            summary=make_summary(),
            guidance=make_guidance(),
        )
        assert triage.triaged_at.tzinfo is not None

    def test_processing_time_set(self):
        triage = TriageResult(
            alert_id="x",
            alert=make_alert(),
            enrichment=make_enrichment(),
            summary=make_summary(),
            guidance=make_guidance(),
            processing_time_ms=1234,
        )
        assert triage.processing_time_ms == 1234


# ---------------------------------------------------------------------------
# TriageResult.to_response() tests
# ---------------------------------------------------------------------------

class TestToResponse:
    def _make_triage(self, **kwargs) -> TriageResult:
        return TriageResult(
            alert_id="SENT-2025-01-30-0042",
            alert=make_alert(),
            enrichment=make_enrichment(),
            summary=make_summary(),
            guidance=make_guidance(),
            processing_time_ms=2340,
            **kwargs,
        )

    def test_returns_triage_response_type(self):
        response = self._make_triage().to_response()
        assert isinstance(response, TriageResponse)

    def test_alert_id_preserved(self):
        response = self._make_triage().to_response()
        assert response.alert_id == "SENT-2025-01-30-0042"

    def test_alert_source_flattened(self):
        response = self._make_triage().to_response()
        assert response.alert_source == "sentinel"

    def test_alert_severity_flattened(self):
        response = self._make_triage().to_response()
        assert response.alert_severity == "high"

    def test_alert_title_flattened(self):
        response = self._make_triage().to_response()
        assert response.alert_title == "Suspicious PowerShell execution following phishing email"

    def test_summary_fields_flattened(self):
        response = self._make_triage().to_response()
        assert response.risk_score == 9
        assert response.confidence_score == 0.85
        assert response.escalation_recommended is True
        assert "FIN7" in response.risk_reasoning

    def test_guidance_fields_flattened(self):
        response = self._make_triage().to_response()
        assert len(response.mitre_mappings) == 2
        assert response.mitre_mappings[0].tactic_id == "TA0001"
        assert "Isolate workstation" in response.investigation_steps[0]
        assert "phishing-attachment.md" in response.relevant_playbooks

    def test_processing_time_preserved(self):
        response = self._make_triage().to_response()
        assert response.processing_time_ms == 2340

    def test_enrichment_errors_surfaced(self):
        enrichment_with_errors = EnrichmentResult(
            alert_id="SENT-2025-01-30-0042",
            enrichment_errors=["CMDB timeout for WS-JD-001"],
        )
        triage = TriageResult(
            alert_id="SENT-2025-01-30-0042",
            alert=make_alert(),
            enrichment=enrichment_with_errors,
            summary=make_summary(),
            guidance=make_guidance(),
        )
        response = triage.to_response()
        assert "CMDB timeout for WS-JD-001" in response.enrichment_errors

    def test_no_suggested_queries_on_response(self):
        """TriageResponse must not have suggested_queries — QueryAgent is on-demand only."""
        response = self._make_triage().to_response()
        assert not hasattr(response, "suggested_queries")

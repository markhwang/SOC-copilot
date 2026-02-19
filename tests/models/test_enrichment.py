"""Tests for src/models/enrichment.py."""

from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from src.models.enrichment import CMDBAsset, EnrichmentResult, EntraUser, ThreatIntelHit


class TestEntraUser:
    def test_minimal_user(self):
        user = EntraUser(upn="john.doe@corp.com")
        assert user.upn == "john.doe@corp.com"
        assert user.display_name is None
        assert user.mfa_enabled is None

    def test_full_user(self):
        user = EntraUser(
            upn="john.doe@corp.com",
            display_name="John Doe",
            department="Finance",
            job_title="Senior Financial Analyst",
            manager_upn="jane.smith@corp.com",
            risk_level="low",
            risk_score=35,
            mfa_enabled=True,
            account_enabled=True,
        )
        assert user.department == "Finance"
        assert user.risk_score == 35
        assert user.mfa_enabled is True


class TestCMDBAsset:
    def test_minimal_asset(self):
        asset = CMDBAsset(hostname="WS-JD-001")
        assert asset.hostname == "WS-JD-001"
        assert asset.criticality is None
        assert asset.last_patched is None

    def test_full_asset(self):
        asset = CMDBAsset(
            hostname="WS-JD-001",
            criticality="high",
            business_unit="Corporate Finance",
            owner_upn="john.doe@corp.com",
            last_patched=date(2025, 1, 15),
            os="Windows 11",
            environment="prod",
        )
        assert asset.criticality == "high"
        assert asset.last_patched == date(2025, 1, 15)
        assert asset.environment == "prod"


class TestThreatIntelHit:
    def test_valid_hit(self):
        hit = ThreatIntelHit(
            ioc_value="203.0.113.50",
            ioc_type="ip",
            reputation="malicious",
            confidence=0.78,
            source="misp",
        )
        assert hit.confidence == 0.78
        assert hit.threat_actor is None
        assert hit.tags == []

    def test_confidence_lower_bound(self):
        hit = ThreatIntelHit(
            ioc_value="example.com",
            ioc_type="domain",
            reputation="suspicious",
            confidence=0.0,
            source="virustotal",
        )
        assert hit.confidence == 0.0

    def test_confidence_upper_bound(self):
        hit = ThreatIntelHit(
            ioc_value="example.com",
            ioc_type="domain",
            reputation="malicious",
            confidence=1.0,
            source="virustotal",
        )
        assert hit.confidence == 1.0

    def test_confidence_above_one_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            ThreatIntelHit(
                ioc_value="203.0.113.50",
                ioc_type="ip",
                reputation="malicious",
                confidence=1.5,
                source="misp",
            )
        errors = exc_info.value.errors()
        assert any("confidence" in str(e["loc"]) for e in errors)

    def test_confidence_below_zero_raises(self):
        with pytest.raises(ValidationError):
            ThreatIntelHit(
                ioc_value="203.0.113.50",
                ioc_type="ip",
                reputation="malicious",
                confidence=-0.1,
                source="misp",
            )

    def test_with_threat_actor_and_tags(self):
        hit = ThreatIntelHit(
            ioc_value="malicious-c2.com",
            ioc_type="domain",
            reputation="malicious",
            threat_actor="FIN7",
            confidence=0.85,
            source="misp",
            tags=["fin7", "financial", "c2"],
        )
        assert hit.threat_actor == "FIN7"
        assert "fin7" in hit.tags


class TestEnrichmentResult:
    def test_empty_result(self):
        result = EnrichmentResult(alert_id="test-001")
        assert result.alert_id == "test-001"
        assert result.users == {}
        assert result.assets == {}
        assert result.threat_intel == []
        assert result.historical_alert_count == 0
        assert result.similar_alert_ids == []
        assert result.enrichment_errors == []
        assert isinstance(result.enriched_at, datetime)

    def test_result_with_user(self):
        result = EnrichmentResult(
            alert_id="test-001",
            users={
                "john.doe@corp.com": EntraUser(
                    upn="john.doe@corp.com",
                    department="Finance",
                    mfa_enabled=True,
                )
            },
        )
        user = result.users["john.doe@corp.com"]
        assert user.department == "Finance"

    def test_result_with_asset(self):
        result = EnrichmentResult(
            alert_id="test-001",
            assets={
                "WS-JD-001": CMDBAsset(
                    hostname="WS-JD-001",
                    criticality="high",
                    environment="prod",
                )
            },
        )
        assert result.assets["WS-JD-001"].criticality == "high"

    def test_result_with_threat_intel(self):
        hit = ThreatIntelHit(
            ioc_value="203.0.113.50",
            ioc_type="ip",
            reputation="malicious",
            threat_actor="FIN7",
            confidence=0.78,
            source="misp",
        )
        result = EnrichmentResult(alert_id="test-001", threat_intel=[hit])
        assert len(result.threat_intel) == 1
        assert result.threat_intel[0].threat_actor == "FIN7"

    def test_non_fatal_enrichment_errors_captured(self):
        result = EnrichmentResult(
            alert_id="test-001",
            enrichment_errors=[
                "CMDB timeout for WS-JD-001",
                "Graph API rate limit exceeded",
            ],
        )
        assert len(result.enrichment_errors) == 2
        assert "CMDB timeout" in result.enrichment_errors[0]

    def test_historical_context(self):
        result = EnrichmentResult(
            alert_id="test-001",
            historical_alert_count=3,
            similar_alert_ids=["alert-100", "alert-101", "alert-102"],
        )
        assert result.historical_alert_count == 3
        assert len(result.similar_alert_ids) == 3

    def test_enriched_at_is_timezone_aware(self):
        result = EnrichmentResult(alert_id="test-001")
        assert result.enriched_at.tzinfo is not None

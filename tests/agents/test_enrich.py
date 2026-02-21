"""Tests for src/agents/enrich.py — EnrichAgent."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.enrich import _collect_iocs, run
from src.models.agent_io import EnrichInput, EnrichOutput
from src.models.alert import AlertEntities, AlertFile, AlertPayload, AlertSource, Severity
from src.models.enrichment import CMDBAsset, EnrichmentResult, EntraUser, ThreatIntelHit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_alert(entities: AlertEntities | None = None) -> AlertPayload:
    return AlertPayload(
        alert_id="test-001",
        source=AlertSource.SENTINEL,
        timestamp=datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        title="Test Alert",
        description="Test description.",
        entities=entities or AlertEntities(),
    )


def make_entra_user(upn: str = "alice@corp.com") -> EntraUser:
    return EntraUser(
        upn=upn,
        display_name="Alice Smith",
        department="Engineering",
        job_title="Software Engineer",
        risk_level="low",
        mfa_enabled=True,
        account_enabled=True,
    )


def make_cmdb_asset(hostname: str = "ws-alice-01") -> CMDBAsset:
    return CMDBAsset(
        hostname=hostname,
        criticality="high",
        business_unit="Engineering",
        owner_upn="alice@corp.com",
        environment="prod",
    )


def make_threat_hit(ioc_value: str = "203.0.113.50", ioc_type: str = "ip") -> ThreatIntelHit:
    return ThreatIntelHit(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        reputation="malicious",
        threat_actor="APT29",
        confidence=0.92,
        source="virustotal",
        tags=["c2", "apt"],
    )


# ---------------------------------------------------------------------------
# _collect_iocs helper
# ---------------------------------------------------------------------------

class TestCollectIocs:
    def test_empty_entities(self):
        entities = AlertEntities()
        assert _collect_iocs(entities) == []

    def test_ips_collected(self):
        entities = AlertEntities(ips=["1.2.3.4", "5.6.7.8"])
        iocs = _collect_iocs(entities)
        assert ("1.2.3.4", "ip") in iocs
        assert ("5.6.7.8", "ip") in iocs

    def test_domains_collected(self):
        entities = AlertEntities(domains=["evil.com"])
        iocs = _collect_iocs(entities)
        assert ("evil.com", "domain") in iocs

    def test_urls_collected(self):
        entities = AlertEntities(urls=["http://evil.com/payload"])
        iocs = _collect_iocs(entities)
        assert ("http://evil.com/payload", "url") in iocs

    def test_file_hash_collected_when_present(self):
        entities = AlertEntities(
            files=[AlertFile(name="malware.exe", hash="abc123")]
        )
        iocs = _collect_iocs(entities)
        assert ("abc123", "hash") in iocs

    def test_file_without_hash_skipped(self):
        entities = AlertEntities(
            files=[AlertFile(name="readme.txt", hash=None)]
        )
        assert _collect_iocs(entities) == []

    def test_mixed_entities(self):
        entities = AlertEntities(
            ips=["1.2.3.4"],
            domains=["evil.com"],
            files=[AlertFile(name="bad.exe", hash="deadbeef"), AlertFile(name="ok.txt")],
        )
        iocs = _collect_iocs(entities)
        assert len(iocs) == 3  # ip + domain + hash (no hash for ok.txt)
        types = {t for _, t in iocs}
        assert types == {"ip", "domain", "hash"}


# ---------------------------------------------------------------------------
# run() — happy path
# ---------------------------------------------------------------------------

class TestEnrichRunHappyPath:
    @pytest.mark.asyncio
    async def test_returns_enrich_output(self):
        alert = make_alert()
        with (
            patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock),
            patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock),
            patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock),
        ):
            result = await run(EnrichInput(alert=alert))
        assert isinstance(result, EnrichOutput)
        assert result.enrichment.alert_id == "test-001"

    @pytest.mark.asyncio
    async def test_no_entities_returns_empty_enrichment(self):
        alert = make_alert(AlertEntities())
        with (
            patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock),
            patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock),
            patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock),
        ):
            result = await run(EnrichInput(alert=alert))
        enrichment = result.enrichment
        assert enrichment.users == {}
        assert enrichment.assets == {}
        assert enrichment.threat_intel == []
        assert enrichment.enrichment_errors == []

    @pytest.mark.asyncio
    async def test_user_lookup_populates_users(self):
        entities = AlertEntities(users=["alice@corp.com"])
        alert = make_alert(entities)
        user = make_entra_user("alice@corp.com")

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock, return_value=user):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))

        assert "alice@corp.com" in result.enrichment.users
        assert result.enrichment.users["alice@corp.com"].display_name == "Alice Smith"

    @pytest.mark.asyncio
    async def test_asset_lookup_populates_assets(self):
        entities = AlertEntities(hosts=["ws-alice-01"])
        alert = make_alert(entities)
        asset = make_cmdb_asset("ws-alice-01")

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock, return_value=asset):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))

        assert "ws-alice-01" in result.enrichment.assets
        assert result.enrichment.assets["ws-alice-01"].criticality == "high"

    @pytest.mark.asyncio
    async def test_threat_intel_hit_included(self):
        entities = AlertEntities(ips=["203.0.113.50"])
        alert = make_alert(entities)
        hit = make_threat_hit("203.0.113.50", "ip")

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock, return_value=hit):
                    result = await run(EnrichInput(alert=alert))

        assert len(result.enrichment.threat_intel) == 1
        assert result.enrichment.threat_intel[0].reputation == "malicious"
        assert result.enrichment.threat_intel[0].threat_actor == "APT29"

    @pytest.mark.asyncio
    async def test_threat_intel_none_return_excluded(self):
        """When check_ioc returns None (clean IOC), no hit is added."""
        entities = AlertEntities(ips=["8.8.8.8"])
        alert = make_alert(entities)

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock, return_value=None):
                    result = await run(EnrichInput(alert=alert))

        assert result.enrichment.threat_intel == []

    @pytest.mark.asyncio
    async def test_multiple_users_all_enriched(self):
        entities = AlertEntities(users=["alice@corp.com", "bob@corp.com"])
        alert = make_alert(entities)

        async def fake_entra(upn: str) -> EntraUser:
            return make_entra_user(upn)

        with patch("src.agents.enrich._lookup_entra_user", side_effect=fake_entra):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))

        assert len(result.enrichment.users) == 2
        assert "alice@corp.com" in result.enrichment.users
        assert "bob@corp.com" in result.enrichment.users

    @pytest.mark.asyncio
    async def test_multiple_iocs_all_checked(self):
        entities = AlertEntities(ips=["1.2.3.4", "5.6.7.8"])
        alert = make_alert(entities)

        async def fake_ti(value: str, ioc_type: str) -> ThreatIntelHit:
            return make_threat_hit(value, ioc_type)

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", side_effect=fake_ti):
                    result = await run(EnrichInput(alert=alert))

        assert len(result.enrichment.threat_intel) == 2

    @pytest.mark.asyncio
    async def test_full_enrichment_combined(self):
        entities = AlertEntities(
            users=["alice@corp.com"],
            hosts=["ws-alice-01"],
            ips=["203.0.113.50"],
        )
        alert = make_alert(entities)

        with (
            patch("src.agents.enrich._lookup_entra_user", return_value=make_entra_user()),
            patch("src.agents.enrich._lookup_cmdb_asset", return_value=make_cmdb_asset()),
            patch("src.agents.enrich._lookup_threat_intel", return_value=make_threat_hit()),
        ):
            result = await run(EnrichInput(alert=alert))

        enrichment = result.enrichment
        assert len(enrichment.users) == 1
        assert len(enrichment.assets) == 1
        assert len(enrichment.threat_intel) == 1
        assert enrichment.enrichment_errors == []


# ---------------------------------------------------------------------------
# run() — error handling / best-effort behaviour
# ---------------------------------------------------------------------------

class TestEnrichRunErrors:
    @pytest.mark.asyncio
    async def test_entra_failure_captured_not_raised(self):
        entities = AlertEntities(users=["alice@corp.com"])
        alert = make_alert(entities)

        with patch("src.agents.enrich._lookup_entra_user", side_effect=RuntimeError("Graph API unavailable")):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))

        assert result.enrichment.users == {}
        assert len(result.enrichment.enrichment_errors) == 1
        assert "alice@corp.com" in result.enrichment.enrichment_errors[0]
        assert "Graph API unavailable" in result.enrichment.enrichment_errors[0]

    @pytest.mark.asyncio
    async def test_cmdb_failure_captured_not_raised(self):
        entities = AlertEntities(hosts=["ws-alice-01"])
        alert = make_alert(entities)

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock):
            with patch("src.agents.enrich._lookup_cmdb_asset", side_effect=ConnectionError("CMDB timeout")):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))

        assert result.enrichment.assets == {}
        assert any("ws-alice-01" in e for e in result.enrichment.enrichment_errors)
        assert any("CMDB timeout" in e for e in result.enrichment.enrichment_errors)

    @pytest.mark.asyncio
    async def test_threat_intel_failure_captured_not_raised(self):
        entities = AlertEntities(ips=["203.0.113.50"])
        alert = make_alert(entities)

        with patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", side_effect=TimeoutError("TI feed timeout")):
                    result = await run(EnrichInput(alert=alert))

        assert result.enrichment.threat_intel == []
        assert any("203.0.113.50" in e for e in result.enrichment.enrichment_errors)

    @pytest.mark.asyncio
    async def test_partial_user_failures_still_returns_successes(self):
        """If one of two user lookups fails, the successful one is still returned."""
        entities = AlertEntities(users=["alice@corp.com", "bob@corp.com"])
        alert = make_alert(entities)

        async def fake_entra(upn: str) -> EntraUser:
            if upn == "bob@corp.com":
                raise RuntimeError("user not found")
            return make_entra_user(upn)

        with patch("src.agents.enrich._lookup_entra_user", side_effect=fake_entra):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))

        assert "alice@corp.com" in result.enrichment.users
        assert "bob@corp.com" not in result.enrichment.users
        assert len(result.enrichment.enrichment_errors) == 1
        assert "bob@corp.com" in result.enrichment.enrichment_errors[0]

    @pytest.mark.asyncio
    async def test_all_sources_fail_returns_empty_enrichment_with_errors(self):
        entities = AlertEntities(users=["alice@corp.com"], hosts=["ws-alice-01"], ips=["1.2.3.4"])
        alert = make_alert(entities)

        with (
            patch("src.agents.enrich._lookup_entra_user", side_effect=RuntimeError("Entra down")),
            patch("src.agents.enrich._lookup_cmdb_asset", side_effect=RuntimeError("CMDB down")),
            patch("src.agents.enrich._lookup_threat_intel", side_effect=RuntimeError("TI down")),
        ):
            result = await run(EnrichInput(alert=alert))

        enrichment = result.enrichment
        assert enrichment.users == {}
        assert enrichment.assets == {}
        assert enrichment.threat_intel == []
        assert len(enrichment.enrichment_errors) == 3

    @pytest.mark.asyncio
    async def test_enrichment_errors_do_not_affect_alert_id(self):
        """alert_id always correctly set even when all enrichment fails."""
        alert = make_alert(AlertEntities(users=["alice@corp.com"]))
        with patch("src.agents.enrich._lookup_entra_user", side_effect=Exception("boom")):
            with patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock):
                with patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock):
                    result = await run(EnrichInput(alert=alert))
        assert result.enrichment.alert_id == "test-001"


# ---------------------------------------------------------------------------
# EnrichmentResult model — enriched_at timestamp
# ---------------------------------------------------------------------------

class TestEnrichmentResultTimestamp:
    @pytest.mark.asyncio
    async def test_enriched_at_is_set(self):
        alert = make_alert()
        with (
            patch("src.agents.enrich._lookup_entra_user", new_callable=AsyncMock),
            patch("src.agents.enrich._lookup_cmdb_asset", new_callable=AsyncMock),
            patch("src.agents.enrich._lookup_threat_intel", new_callable=AsyncMock),
        ):
            result = await run(EnrichInput(alert=alert))
        assert result.enrichment.enriched_at is not None
        assert result.enrichment.enriched_at.tzinfo is not None  # timezone-aware

"""Tests for src/agents/ingest.py — pure normalizer, no network calls."""

from datetime import datetime, timezone

import pytest

from src.agents import ingest
from src.models.agent_io import IngestInput
from src.models.alert import AlertSource, Severity


# ---------------------------------------------------------------------------
# Realistic source fixtures
# ---------------------------------------------------------------------------

SENTINEL_INCIDENT = {
    "id": "/subscriptions/sub-123/resourceGroups/rg-soc/providers/Microsoft.SecurityInsights/incidents/inc-12345",
    "name": "inc-12345",
    "properties": {
        "incidentNumber": 12345,
        "title": "Suspicious PowerShell execution following phishing email",
        "description": "User john.doe@corp.com received a phishing email with macro-enabled attachment.",
        "severity": "High",
        "status": "New",
        "createdTimeUtc": "2025-01-30T14:32:15Z",
        "tactics": ["InitialAccess", "Execution"],
        "techniques": ["T1566.001", "T1059.001", "T1105"],
        "alerts": [
            {
                "properties": {
                    "systemAlertId": "alert-abc-123",
                    "entities": [
                        {"kind": "Account", "properties": {"accountName": "john.doe", "upnSuffix": "corp.com"}},
                        {"kind": "Host", "properties": {"hostName": "WS-JD-001"}},
                        {"kind": "Ip", "properties": {"address": "203.0.113.50"}},
                        {"kind": "File", "properties": {"fileName": "Q4_Report.docm", "fileHashValue": "a1b2c3d4"}},
                        {"kind": "Url", "properties": {"url": "https://malicious-c2.com/payload"}},
                    ],
                }
            }
        ],
    },
}

SPLUNK_NOTABLE = {
    "sid": "rt_scheduler_notable_001",
    "result": {
        "event_id": "notableEvent-67890",
        "rule_name": "Suspicious PowerShell After Email Attachment",
        "rule_description": "PowerShell spawned from Word process after email attachment detected.",
        "severity": "high",
        "urgency": "high",
        "_time": "1738247535.000",  # 2025-01-30T14:32:15Z
        "src_user": "john.doe@corp.com",
        "dest": "WS-JD-001",
        "src": "203.0.113.50",
        "file_name": "Q4_Report.docm",
        "file_hash": "a1b2c3d4",
        "mitre_technique_id": "T1566.001",
    },
}

DEFENDER_ALERT = {
    "id": "da637571816255829180_-1324023023",
    "title": "Suspicious PowerShell commandline",
    "description": "PowerShell process created by Word with encoded command.",
    "severity": "High",
    "status": "New",
    "creationTime": "2025-01-30T14:32:15Z",
    "detectionSource": "WindowsDefenderAv",
    "mitreTechniques": ["T1059.001"],
    "entities": [
        {
            "entityType": "User",
            "accountName": "john.doe",
            "domainName": "corp.com",
            "userPrincipalName": "john.doe@corp.com",
        },
        {"entityType": "Machine", "computerDnsName": "WS-JD-001"},
        {"entityType": "Ip", "ipAddress": "203.0.113.50"},
        {"entityType": "File", "fileName": "Q4_Report.docm", "sha256": "a1b2c3d4e5f6"},
    ],
}


# ---------------------------------------------------------------------------
# Sentinel tests
# ---------------------------------------------------------------------------

class TestSentinelParsing:
    @pytest.mark.asyncio
    async def test_alert_id_uses_incident_number(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.alert.alert_id == "SENT-12345"

    @pytest.mark.asyncio
    async def test_source_is_sentinel(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.alert.source == AlertSource.SENTINEL

    @pytest.mark.asyncio
    async def test_timestamp_parsed(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.alert.timestamp == datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_severity_mapped(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.alert.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_title_and_description(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.alert.title == "Suspicious PowerShell execution following phishing email"
        assert "john.doe@corp.com" in out.alert.description

    @pytest.mark.asyncio
    async def test_mitre_tactics_mapped_to_ids(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert "TA0001" in out.alert.mitre_tactics
        assert "TA0002" in out.alert.mitre_tactics

    @pytest.mark.asyncio
    async def test_mitre_techniques_preserved(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert "T1566.001" in out.alert.mitre_techniques
        assert "T1059.001" in out.alert.mitre_techniques

    @pytest.mark.asyncio
    async def test_entities_extracted(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert "john.doe@corp.com" in out.alert.entities.users
        assert "WS-JD-001" in out.alert.entities.hosts
        assert "203.0.113.50" in out.alert.entities.ips
        assert out.alert.entities.files[0].name == "Q4_Report.docm"
        assert out.alert.entities.files[0].hash == "a1b2c3d4"
        assert "https://malicious-c2.com/payload" in out.alert.entities.urls

    @pytest.mark.asyncio
    async def test_raw_data_preserved(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.alert.raw_data == SENTINEL_INCIDENT

    @pytest.mark.asyncio
    async def test_account_name_plus_suffix_fallback(self):
        """Account entities with accountName + upnSuffix should produce a UPN."""
        payload = {
            "properties": {
                "incidentNumber": 1,
                "title": "Test",
                "description": "",
                "severity": "Low",
                "createdTimeUtc": "2025-01-30T00:00:00Z",
                "tactics": [],
                "techniques": [],
                "alerts": [
                    {
                        "properties": {
                            "entities": [
                                {"kind": "Account", "properties": {"accountName": "jsmith", "upnSuffix": "example.com"}},
                            ]
                        }
                    }
                ],
            }
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SENTINEL))
        assert "jsmith@example.com" in out.alert.entities.users

    @pytest.mark.asyncio
    async def test_unknown_tactic_name_produces_warning(self):
        payload = {
            "properties": {
                "incidentNumber": 2,
                "title": "Test",
                "description": "",
                "severity": "Low",
                "createdTimeUtc": "2025-01-30T00:00:00Z",
                "tactics": ["UnknownFutureTactic"],
                "techniques": [],
                "alerts": [],
            }
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SENTINEL))
        assert out.alert.mitre_tactics == []
        assert any("UnknownFutureTactic" in w for w in out.parse_warnings)

    @pytest.mark.asyncio
    async def test_missing_timestamp_produces_warning(self):
        payload = {
            "properties": {
                "incidentNumber": 3,
                "title": "Test",
                "description": "",
                "severity": "Low",
                "tactics": [],
                "techniques": [],
                "alerts": [],
            }
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SENTINEL))
        assert any("timestamp" in w.lower() for w in out.parse_warnings)
        assert isinstance(out.alert.timestamp, datetime)


# ---------------------------------------------------------------------------
# Splunk tests
# ---------------------------------------------------------------------------

class TestSplunkParsing:
    @pytest.mark.asyncio
    async def test_alert_id_from_event_id(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.alert_id == "notableEvent-67890"

    @pytest.mark.asyncio
    async def test_source_is_splunk(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.source == AlertSource.SPLUNK

    @pytest.mark.asyncio
    async def test_epoch_timestamp_parsed(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.timestamp == datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_severity_from_severity_field(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_title_from_rule_name(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.title == "Suspicious PowerShell After Email Attachment"

    @pytest.mark.asyncio
    async def test_entities_from_flat_cim_fields(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert "john.doe@corp.com" in out.alert.entities.users
        assert "WS-JD-001" in out.alert.entities.hosts
        assert "203.0.113.50" in out.alert.entities.ips
        assert out.alert.entities.files[0].name == "Q4_Report.docm"
        assert out.alert.entities.files[0].hash == "a1b2c3d4"

    @pytest.mark.asyncio
    async def test_mitre_technique_from_field(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert "T1566.001" in out.alert.mitre_techniques

    @pytest.mark.asyncio
    async def test_no_mitre_tactics_splunk(self):
        """Splunk ES doesn't reliably surface tactic IDs — tactics list should be empty."""
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.mitre_tactics == []

    @pytest.mark.asyncio
    async def test_invalid_epoch_produces_warning(self):
        payload = {
            "result": {
                "event_id": "evt-001",
                "rule_name": "Test",
                "severity": "low",
                "_time": "not-a-number",
            }
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SPLUNK))
        assert any("_time" in w for w in out.parse_warnings)

    @pytest.mark.asyncio
    async def test_raw_data_preserved(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE, source_hint=AlertSource.SPLUNK))
        assert out.alert.raw_data == SPLUNK_NOTABLE


# ---------------------------------------------------------------------------
# Defender tests
# ---------------------------------------------------------------------------

class TestDefenderParsing:
    @pytest.mark.asyncio
    async def test_alert_id_from_id_field(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert out.alert.alert_id == "da637571816255829180_-1324023023"

    @pytest.mark.asyncio
    async def test_source_is_defender(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert out.alert.source == AlertSource.DEFENDER

    @pytest.mark.asyncio
    async def test_timestamp_parsed(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert out.alert.timestamp == datetime(2025, 1, 30, 14, 32, 15, tzinfo=timezone.utc)

    @pytest.mark.asyncio
    async def test_severity_mapped(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert out.alert.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_entities_extracted(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert "john.doe@corp.com" in out.alert.entities.users
        assert "WS-JD-001" in out.alert.entities.hosts
        assert "203.0.113.50" in out.alert.entities.ips
        assert out.alert.entities.files[0].name == "Q4_Report.docm"
        assert out.alert.entities.files[0].hash == "a1b2c3d4e5f6"

    @pytest.mark.asyncio
    async def test_user_from_account_plus_domain_fallback(self):
        """User entities without UPN should be constructed from accountName + domainName."""
        payload = {
            **DEFENDER_ALERT,
            "entities": [
                {"entityType": "User", "accountName": "jsmith", "domainName": "corp.com"},
            ],
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.DEFENDER))
        assert "jsmith@corp.com" in out.alert.entities.users

    @pytest.mark.asyncio
    async def test_mitre_techniques_from_mitre_techniques_field(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert "T1059.001" in out.alert.mitre_techniques

    @pytest.mark.asyncio
    async def test_no_mitre_tactics_defender(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER))
        assert out.alert.mitre_tactics == []

    @pytest.mark.asyncio
    async def test_unknown_entity_type_produces_warning(self):
        payload = {
            **DEFENDER_ALERT,
            "entities": [{"entityType": "CloudApplication", "appId": 11161}],
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.DEFENDER))
        assert any("CloudApplication" in w for w in out.parse_warnings)


# ---------------------------------------------------------------------------
# Auto-detection tests
# ---------------------------------------------------------------------------

class TestSourceAutoDetection:
    @pytest.mark.asyncio
    async def test_detects_sentinel_from_properties_incidentnumber(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT))
        assert out.alert.source == AlertSource.SENTINEL

    @pytest.mark.asyncio
    async def test_detects_splunk_from_result_time(self):
        out = await ingest.run(IngestInput(raw_payload=SPLUNK_NOTABLE))
        assert out.alert.source == AlertSource.SPLUNK

    @pytest.mark.asyncio
    async def test_detects_defender_from_mitre_techniques_key(self):
        out = await ingest.run(IngestInput(raw_payload=DEFENDER_ALERT))
        assert out.alert.source == AlertSource.DEFENDER

    @pytest.mark.asyncio
    async def test_unrecognisable_payload_raises(self):
        with pytest.raises(ValueError, match="cannot determine alert source"):
            await ingest.run(IngestInput(raw_payload={"foo": "bar"}))

    @pytest.mark.asyncio
    async def test_source_hint_overrides_detection(self):
        """source_hint takes precedence — useful for disambiguation."""
        # DEFENDER_ALERT could auto-detect as Defender; hint forces it
        out = await ingest.run(
            IngestInput(raw_payload=DEFENDER_ALERT, source_hint=AlertSource.DEFENDER)
        )
        assert out.alert.source == AlertSource.DEFENDER


# ---------------------------------------------------------------------------
# Severity normalisation tests
# ---------------------------------------------------------------------------

class TestSeverityNormalization:
    @pytest.mark.asyncio
    async def test_critical_sentinel(self):
        payload = {**SENTINEL_INCIDENT, "properties": {**SENTINEL_INCIDENT["properties"], "severity": "Critical"}}
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SENTINEL))
        assert out.alert.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_informational_sentinel(self):
        payload = {**SENTINEL_INCIDENT, "properties": {**SENTINEL_INCIDENT["properties"], "severity": "Informational"}}
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SENTINEL))
        assert out.alert.severity == Severity.INFORMATIONAL

    @pytest.mark.asyncio
    async def test_unspecified_defender_maps_to_informational(self):
        payload = {**DEFENDER_ALERT, "severity": "UnSpecified"}
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.DEFENDER))
        assert out.alert.severity == Severity.INFORMATIONAL

    @pytest.mark.asyncio
    async def test_unknown_severity_defaults_to_medium_with_warning(self):
        payload = {**DEFENDER_ALERT, "severity": "EXTREME"}
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.DEFENDER))
        assert out.alert.severity == Severity.MEDIUM
        assert any("EXTREME" in w for w in out.parse_warnings)


# ---------------------------------------------------------------------------
# parse_warnings passthrough test
# ---------------------------------------------------------------------------

class TestParseWarnings:
    @pytest.mark.asyncio
    async def test_clean_payload_has_no_warnings(self):
        out = await ingest.run(IngestInput(raw_payload=SENTINEL_INCIDENT, source_hint=AlertSource.SENTINEL))
        assert out.parse_warnings == []

    @pytest.mark.asyncio
    async def test_warnings_collected_not_raised(self):
        """Non-fatal issues should produce warnings, not exceptions."""
        payload = {
            "properties": {
                "incidentNumber": 99,
                "title": "Test",
                "description": "",
                "severity": "WeirdValue",
                "tactics": ["NotARealTactic"],
                "techniques": [],
                "alerts": [],
            }
        }
        out = await ingest.run(IngestInput(raw_payload=payload, source_hint=AlertSource.SENTINEL))
        assert len(out.parse_warnings) >= 2   # unknown severity + unknown tactic
        assert isinstance(out.alert, object)  # still produced a result

"""Tests for src/models/alert.py."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.models.alert import AlertEntities, AlertFile, AlertPayload, AlertSource, Severity


def _minimal() -> dict:
    return {
        "alert_id": "SENT-2025-01-30-0042",
        "source": "sentinel",
        "timestamp": "2025-01-30T14:32:15Z",
        "severity": "high",
        "title": "Suspicious PowerShell execution following phishing email",
        "description": "User opened macro-enabled doc triggering PowerShell.",
    }


class TestAlertSource:
    def test_all_valid_sources(self):
        for source in ("sentinel", "splunk", "defender"):
            payload = AlertPayload(**{**_minimal(), "source": source})
            assert payload.source.value == source

    def test_invalid_source_raises(self):
        with pytest.raises(ValidationError):
            AlertPayload(**{**_minimal(), "source": "crowdstrike"})

    def test_invalid_source_raises_unknown(self):
        with pytest.raises(ValidationError):
            AlertPayload(**{**_minimal(), "source": "unknown_siem"})


class TestSeverity:
    def test_all_valid_severities(self):
        for sev in ("critical", "high", "medium", "low", "informational"):
            payload = AlertPayload(**{**_minimal(), "severity": sev})
            assert payload.severity.value == sev

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            AlertPayload(**{**_minimal(), "severity": "extreme"})


class TestAlertPayloadDefaults:
    def test_minimal_payload_parses(self):
        payload = AlertPayload(**_minimal())
        assert payload.alert_id == "SENT-2025-01-30-0042"
        assert payload.source == AlertSource.SENTINEL
        assert payload.severity == Severity.HIGH

    def test_empty_collections_by_default(self):
        payload = AlertPayload(**_minimal())
        assert payload.mitre_tactics == []
        assert payload.mitre_techniques == []
        assert payload.entities.users == []
        assert payload.entities.hosts == []
        assert payload.entities.ips == []
        assert payload.entities.files == []
        assert payload.entities.urls == []
        assert payload.entities.domains == []
        assert payload.raw_data == {}

    def test_timestamp_parsed_as_datetime(self):
        payload = AlertPayload(**_minimal())
        assert isinstance(payload.timestamp, datetime)


class TestAlertPayloadFull:
    def test_full_payload_from_sample_file(self):
        """Verify the schema handles the shape from examples/sample_alerts/phishing_with_execution.json."""
        data = {
            **_minimal(),
            "mitre_tactics": ["TA0001", "TA0002"],
            "mitre_techniques": ["T1566.001", "T1059.001", "T1105"],
            "entities": {
                "users": ["john.doe@company.com"],
                "hosts": ["WS-JD-001"],
                "ips": ["203.0.113.50"],
                "files": [{"name": "Q4_Report.docm", "hash": "a1b2c3d4e5f6"}],
                "urls": ["hxxps://malicious-c2.com/payload"],
                "domains": ["malicious-c2.com"],
            },
            "raw_data": {"sentinel_incident_id": "inc-12345", "workspace_id": "abc-123-def"},
        }
        payload = AlertPayload(**data)

        assert len(payload.mitre_tactics) == 2
        assert "TA0001" in payload.mitre_tactics
        assert payload.entities.users == ["john.doe@company.com"]
        assert payload.entities.hosts == ["WS-JD-001"]
        assert payload.entities.files[0].name == "Q4_Report.docm"
        assert payload.entities.files[0].hash == "a1b2c3d4e5f6"
        assert payload.entities.domains == ["malicious-c2.com"]
        assert payload.raw_data["sentinel_incident_id"] == "inc-12345"

    def test_file_without_hash_is_valid(self):
        data = {**_minimal(), "entities": {"files": [{"name": "report.pdf"}]}}
        payload = AlertPayload(**data)
        assert payload.entities.files[0].hash is None

    def test_splunk_source(self):
        payload = AlertPayload(**{**_minimal(), "source": "splunk"})
        assert payload.source == AlertSource.SPLUNK

    def test_defender_source(self):
        payload = AlertPayload(**{**_minimal(), "source": "defender"})
        assert payload.source == AlertSource.DEFENDER

    def test_raw_data_preserved_verbatim(self):
        raw = {"custom_field": "custom_value", "nested": {"key": 42}}
        payload = AlertPayload(**{**_minimal(), "raw_data": raw})
        assert payload.raw_data == raw


class TestAlertEntitiesIsolated:
    def test_empty_entities(self):
        entities = AlertEntities()
        assert entities.users == []
        assert entities.domains == []

    def test_file_model(self):
        f = AlertFile(name="malware.exe", hash="deadbeef", path="C:\\Users\\temp")
        assert f.name == "malware.exe"
        assert f.hash == "deadbeef"
        assert f.path == "C:\\Users\\temp"

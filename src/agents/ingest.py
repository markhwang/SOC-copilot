"""
IngestAgent — raw source payload → normalized AlertPayload.

Handles three source formats:
  - Microsoft Sentinel  (incident/alert webhook, properties-wrapped JSON)
  - Splunk ES           (notable event webhook, result-wrapped JSON, epoch timestamps)
  - Microsoft Defender  (alert API payload, flat JSON)

Entry point: async def run(input: IngestInput) -> IngestOutput

No external API calls are made here — IngestAgent is a pure normalizer.
Network I/O lives in src/integrations/sentinel_ingest.py and splunk_ingest.py.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.models.agent_io import IngestInput, IngestOutput
from src.models.alert import AlertEntities, AlertFile, AlertPayload, AlertSource, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK tactic name → ID
# Sentinel returns human-readable CamelCase names; we normalize to TA IDs.
# ---------------------------------------------------------------------------
_SENTINEL_TACTIC_IDS: dict[str, str] = {
    "InitialAccess": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "PrivilegeEscalation": "TA0004",
    "DefenseEvasion": "TA0005",
    "CredentialAccess": "TA0006",
    "Discovery": "TA0007",
    "LateralMovement": "TA0008",
    "Collection": "TA0009",
    "Exfiltration": "TA0010",
    "CommandAndControl": "TA0011",
    "Impact": "TA0040",
    "ResourceDevelopment": "TA0042",
    "Reconnaissance": "TA0043",
    "PreAttack": "TA0043",  # legacy Sentinel label
}

# Canonical severity mapping — handles all casing variants across sources
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "unspecified": Severity.INFORMATIONAL,  # Defender default when unknown
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _normalize_severity(raw: str, warnings: list[str]) -> Severity:
    normalized = raw.strip().lower()
    if normalized in _SEVERITY_MAP:
        return _SEVERITY_MAP[normalized]
    warnings.append(f"Unknown severity value '{raw}' — defaulting to MEDIUM")
    return Severity.MEDIUM


def _detect_source(raw: dict[str, Any]) -> AlertSource | None:
    """Infer alert source from payload structure when source_hint is absent."""
    props = raw.get("properties", {})
    if "incidentNumber" in props or "alerts" in props or "tactics" in props:
        return AlertSource.SENTINEL
    if "result" in raw and "_time" in raw.get("result", {}):
        return AlertSource.SPLUNK
    if "mitreTechniques" in raw or "detectionSource" in raw or "alertId" in raw:
        return AlertSource.DEFENDER
    return None


# ---------------------------------------------------------------------------
# Sentinel parser
# ---------------------------------------------------------------------------

def _extract_sentinel_entities(
    props: dict[str, Any], warnings: list[str]
) -> AlertEntities:
    """Walk nested Sentinel alert entities and normalize to AlertEntities."""
    users: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []
    files: list[AlertFile] = []
    urls: list[str] = []
    domains: list[str] = []

    for alert in props.get("alerts", []):
        alert_props = alert.get("properties", alert)
        for entity in alert_props.get("entities", []):
            kind = entity.get("kind", "")
            ep = entity.get("properties", entity)

            if kind == "Account":
                upn = ep.get("userPrincipalName")
                if not upn:
                    account = ep.get("accountName", "")
                    suffix = ep.get("upnSuffix", "")
                    upn = f"{account}@{suffix}" if account and suffix else None
                if upn:
                    users.append(upn)

            elif kind == "Host":
                hostname = ep.get("hostName") or ep.get("dnsDomain")
                if hostname:
                    hosts.append(hostname)

            elif kind == "Ip":
                ip = ep.get("address")
                if ip:
                    ips.append(ip)

            elif kind == "File":
                name = ep.get("fileName") or ep.get("name", "")
                hash_val = ep.get("fileHashValue") or ep.get("sha256") or ep.get("sha1")
                if name:
                    files.append(AlertFile(name=name, hash=hash_val))

            elif kind == "Url":
                url = ep.get("url")
                if url:
                    urls.append(url)

            else:
                if kind:
                    warnings.append(f"Sentinel: unhandled entity kind '{kind}' — skipped")

    return AlertEntities(
        users=users, hosts=hosts, ips=ips, files=files, urls=urls, domains=domains
    )


def _parse_sentinel(raw: dict[str, Any], warnings: list[str]) -> AlertPayload:
    props = raw.get("properties", raw)

    # Alert ID — prefer human-readable incident number
    incident_num = props.get("incidentNumber")
    alert_id = f"SENT-{incident_num}" if incident_num else raw.get("name", raw.get("id", "unknown"))

    # Timestamp
    ts_raw = (
        props.get("createdTimeUtc")
        or props.get("firstActivityTimeUtc")
        or props.get("createdTime")
    )
    if ts_raw:
        timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    else:
        warnings.append("Sentinel: no timestamp field found — using current UTC time")
        timestamp = datetime.now(timezone.utc)

    severity = _normalize_severity(props.get("severity", "Medium"), warnings)
    title = props.get("title", "Sentinel Alert")
    description = props.get("description", "")

    # MITRE tactics — Sentinel uses names ("InitialAccess"), not IDs ("TA0001")
    mitre_tactics: list[str] = []
    for tactic_name in props.get("tactics", []):
        tactic_id = _SENTINEL_TACTIC_IDS.get(tactic_name)
        if tactic_id:
            mitre_tactics.append(tactic_id)
        else:
            warnings.append(f"Sentinel: unrecognised tactic name '{tactic_name}' — skipped")

    # MITRE techniques — Sentinel already uses IDs (e.g. "T1566.001")
    mitre_techniques: list[str] = props.get("techniques", [])

    entities = _extract_sentinel_entities(props, warnings)

    return AlertPayload(
        alert_id=str(alert_id),
        source=AlertSource.SENTINEL,
        timestamp=timestamp,
        severity=severity,
        title=title,
        description=description,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        entities=entities,
        raw_data=raw,
    )


# ---------------------------------------------------------------------------
# Splunk parser
# ---------------------------------------------------------------------------

def _parse_splunk(raw: dict[str, Any], warnings: list[str]) -> AlertPayload:
    result = raw.get("result", raw)

    alert_id = result.get("event_id") or result.get("_cd") or result.get("sid", "unknown")

    # Splunk timestamps are Unix epoch — string or float
    time_raw = result.get("_time")
    if time_raw:
        try:
            timestamp = datetime.fromtimestamp(float(time_raw), tz=timezone.utc)
        except (ValueError, TypeError):
            warnings.append(f"Splunk: couldn't parse _time '{time_raw}' — using current UTC time")
            timestamp = datetime.now(timezone.utc)
    else:
        warnings.append("Splunk: no _time field — using current UTC time")
        timestamp = datetime.now(timezone.utc)

    severity_raw = result.get("severity") or result.get("urgency", "medium")
    severity = _normalize_severity(severity_raw, warnings)

    title = result.get("rule_name") or result.get("search_name") or result.get("source", "Splunk Alert")
    description = result.get("rule_description") or result.get("description", "")

    # MITRE — Splunk ES stores technique IDs in various fields depending on version
    mitre_techniques: list[str] = []
    for field in ("mitre_technique_id", "mitre_technique", "annotations.mitre_attack.technique_id"):
        val = result.get(field)
        if val:
            if isinstance(val, list):
                mitre_techniques.extend(val)
            else:
                mitre_techniques.append(val)
            break

    # Entities — Splunk uses flat CIM-compliant field names
    users: list[str] = []
    if src_user := result.get("src_user") or result.get("user"):
        users.append(src_user)

    hosts: list[str] = []
    for field in ("dest", "dest_host", "dvc", "hostname"):
        if host := result.get(field):
            hosts.append(host)
            break

    ips: list[str] = []
    for field in ("src", "src_ip"):
        if ip := result.get(field):
            ips.append(ip)
            break

    files: list[AlertFile] = []
    if file_name := result.get("file_name") or result.get("file_path"):
        files.append(AlertFile(name=file_name, hash=result.get("file_hash")))

    urls: list[str] = []
    if url := result.get("url") or result.get("dest_url"):
        urls.append(url)

    entities = AlertEntities(users=users, hosts=hosts, ips=ips, files=files, urls=urls)

    return AlertPayload(
        alert_id=str(alert_id),
        source=AlertSource.SPLUNK,
        timestamp=timestamp,
        severity=severity,
        title=title,
        description=description,
        mitre_tactics=[],        # Splunk ES doesn't reliably surface tactic IDs
        mitre_techniques=mitre_techniques,
        entities=entities,
        raw_data=raw,
    )


# ---------------------------------------------------------------------------
# Defender parser
# ---------------------------------------------------------------------------

def _extract_defender_entities(
    raw_entities: list[dict[str, Any]], warnings: list[str]
) -> AlertEntities:
    users: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []
    files: list[AlertFile] = []
    urls: list[str] = []
    domains: list[str] = []

    for entity in raw_entities:
        entity_type = entity.get("entityType", "")

        if entity_type == "User":
            upn = entity.get("userPrincipalName")
            if not upn:
                account = entity.get("accountName", "")
                domain = entity.get("domainName", "")
                upn = f"{account}@{domain}" if account and domain else None
            if upn:
                users.append(upn)

        elif entity_type == "Machine":
            hostname = entity.get("computerDnsName") or entity.get("hostName")
            if hostname:
                hosts.append(hostname)

        elif entity_type == "Ip":
            ip = entity.get("ipAddress")
            if ip:
                ips.append(ip)

        elif entity_type == "File":
            name = entity.get("fileName") or entity.get("name", "")
            hash_val = entity.get("sha256") or entity.get("sha1") or entity.get("md5")
            if name:
                files.append(AlertFile(name=name, hash=hash_val))

        elif entity_type == "Url":
            url = entity.get("url")
            if url:
                urls.append(url)

        else:
            if entity_type:
                warnings.append(f"Defender: unhandled entity type '{entity_type}' — skipped")

    return AlertEntities(
        users=users, hosts=hosts, ips=ips, files=files, urls=urls, domains=domains
    )


def _parse_defender(raw: dict[str, Any], warnings: list[str]) -> AlertPayload:
    alert_id = raw.get("id") or raw.get("alertId", "unknown")

    ts_raw = (
        raw.get("creationTime")
        or raw.get("alertCreationTime")
        or raw.get("firstEventTime")
    )
    if ts_raw:
        timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    else:
        warnings.append("Defender: no timestamp field found — using current UTC time")
        timestamp = datetime.now(timezone.utc)

    severity = _normalize_severity(raw.get("severity", "Medium"), warnings)
    title = raw.get("title", "Defender Alert")
    description = raw.get("description", "")
    mitre_techniques: list[str] = raw.get("mitreTechniques", [])

    entities = _extract_defender_entities(raw.get("entities", []), warnings)

    return AlertPayload(
        alert_id=str(alert_id),
        source=AlertSource.DEFENDER,
        timestamp=timestamp,
        severity=severity,
        title=title,
        description=description,
        mitre_tactics=[],        # Defender doesn't return tactic IDs; GuidanceAgent maps these
        mitre_techniques=mitre_techniques,
        entities=entities,
        raw_data=raw,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_PARSERS = {
    AlertSource.SENTINEL: _parse_sentinel,
    AlertSource.SPLUNK: _parse_splunk,
    AlertSource.DEFENDER: _parse_defender,
}


async def run(input: IngestInput) -> IngestOutput:
    """Normalize a raw source payload into an AlertPayload.

    Args:
        input: IngestInput with raw_payload dict and optional source_hint.

    Returns:
        IngestOutput with normalized AlertPayload and any parse_warnings.

    Raises:
        ValueError: If the source cannot be determined from hint or payload shape.
    """
    warnings: list[str] = []
    raw = input.raw_payload

    source = input.source_hint or _detect_source(raw)
    if source is None:
        raise ValueError(
            "IngestAgent: cannot determine alert source from payload structure. "
            "Pass source_hint=AlertSource.SENTINEL/SPLUNK/DEFENDER explicitly, "
            "or ensure the payload matches a known format."
        )

    logger.info("ingest_agent.start", extra={"source": source.value})

    alert = _PARSERS[source](raw, warnings)

    if warnings:
        logger.warning("ingest_agent.warnings", extra={"count": len(warnings), "warnings": warnings})

    logger.info(
        "ingest_agent.complete",
        extra={"alert_id": alert.alert_id, "source": source.value, "warnings": len(warnings)},
    )
    return IngestOutput(alert=alert, parse_warnings=warnings)

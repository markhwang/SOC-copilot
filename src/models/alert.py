"""
Alert models — normalized representation of security alerts.

AlertPayload is the canonical internal format. IngestAgent translates
raw Sentinel / Splunk / Defender payloads into this schema.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    SENTINEL = "sentinel"
    SPLUNK = "splunk"
    DEFENDER = "defender"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertFile(BaseModel):
    name: str
    hash: Optional[str] = None
    path: Optional[str] = None


class AlertEntities(BaseModel):
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    files: list[AlertFile] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)  # separated from URLs for threat intel lookups


class AlertPayload(BaseModel):
    alert_id: str
    source: AlertSource
    timestamp: datetime
    severity: Severity
    title: str
    description: str
    mitre_tactics: list[str] = Field(default_factory=list)    # e.g. "TA0001"
    mitre_techniques: list[str] = Field(default_factory=list)  # e.g. "T1566.001"
    entities: AlertEntities = Field(default_factory=AlertEntities)
    raw_data: dict[str, Any] = Field(default_factory=dict)     # source-specific fields preserved verbatim

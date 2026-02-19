"""
Enrichment models — context added to an alert before LLM processing.

EnrichAgent populates EnrichmentResult by querying Entra ID (users),
CMDB (assets), and threat intelligence feeds (IOCs). Enrichment is
best-effort: partial results are acceptable and errors are captured in
enrichment_errors rather than raising exceptions.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class EntraUser(BaseModel):
    """User context retrieved from Microsoft Entra ID (formerly Azure AD)."""

    upn: str  # user principal name — primary key
    display_name: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    manager_upn: Optional[str] = None
    risk_level: Optional[str] = None    # none / low / medium / high (Entra ID Protection)
    risk_score: Optional[int] = None    # 0–100 (Entra ID Protection)
    mfa_enabled: Optional[bool] = None
    account_enabled: Optional[bool] = None


class CMDBAsset(BaseModel):
    """Asset context retrieved from CMDB."""

    hostname: str  # primary key
    criticality: Optional[str] = None    # critical / high / medium / low
    business_unit: Optional[str] = None
    owner_upn: Optional[str] = None
    last_patched: Optional[date] = None
    os: Optional[str] = None
    environment: Optional[str] = None   # prod / staging / dev


class ThreatIntelHit(BaseModel):
    """A single IOC match from a threat intelligence source."""

    ioc_value: str
    ioc_type: str       # ip / domain / hash / url
    reputation: str     # malicious / suspicious / clean / unknown
    threat_actor: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    source: str         # misp / virustotal / abuseipdb
    tags: list[str] = Field(default_factory=list)


class EnrichmentResult(BaseModel):
    """All enrichment data gathered for a single alert."""

    alert_id: str
    users: dict[str, EntraUser] = Field(default_factory=dict)        # keyed by UPN
    assets: dict[str, CMDBAsset] = Field(default_factory=dict)       # keyed by hostname
    threat_intel: list[ThreatIntelHit] = Field(default_factory=list)
    historical_alert_count: int = 0                                   # alerts for same entities in last 30 days
    similar_alert_ids: list[str] = Field(default_factory=list)
    enrichment_errors: list[str] = Field(default_factory=list)       # non-fatal; partial results acceptable
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

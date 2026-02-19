"""
Agent I/O contracts — typed inputs and outputs for every agent.

The orchestrator fans work out across agents using these types. Agents must
never be called with raw dicts — all data crosses agent boundaries as
validated Pydantic models.

Import hierarchy (no circular dependencies):
  alert.py          <- no internal imports
  enrichment.py     <- no internal imports
  response.py       <- alert.py, enrichment.py
  agent_io.py       <- alert.py, enrichment.py, response.py
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from src.models.alert import AlertPayload, AlertSource
from src.models.enrichment import EnrichmentResult
from src.models.response import GuidanceResult, SummaryResult, TriageResult


# ---------------------------------------------------------------------------
# IngestAgent — raw source payload → normalized AlertPayload
# ---------------------------------------------------------------------------

class IngestInput(BaseModel):
    raw_payload: dict[str, Any]
    source_hint: Optional[AlertSource] = None  # if known from webhook routing


class IngestOutput(BaseModel):
    alert: AlertPayload
    parse_warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# EnrichAgent — AlertPayload → EnrichmentResult
# ---------------------------------------------------------------------------

class EnrichInput(BaseModel):
    alert: AlertPayload


class EnrichOutput(BaseModel):
    enrichment: EnrichmentResult


# ---------------------------------------------------------------------------
# SummarizeAgent — AlertPayload + EnrichmentResult → SummaryResult
# ---------------------------------------------------------------------------

class SummarizeInput(BaseModel):
    alert: AlertPayload
    enrichment: EnrichmentResult


class SummarizeOutput(BaseModel):
    summary: SummaryResult


# ---------------------------------------------------------------------------
# GuidanceAgent — AlertPayload + RAG context → GuidanceResult
# ---------------------------------------------------------------------------

class GuidanceInput(BaseModel):
    alert: AlertPayload
    rag_context: list[str] = Field(default_factory=list)  # retrieved document chunks


class GuidanceOutput(BaseModel):
    guidance: GuidanceResult


# ---------------------------------------------------------------------------
# QueryAgent — analyst natural language → KQL / SPL (on-demand only)
# ---------------------------------------------------------------------------

class QueryInput(BaseModel):
    question: str
    alert: Optional[AlertPayload] = None   # optional alert context
    target_platform: str = "both"          # "kql" | "spl" | "both"


class QueryOutput(BaseModel):
    kql: Optional[str] = None
    spl: Optional[str] = None
    explanation: str
    performance_notes: Optional[str] = None


# ---------------------------------------------------------------------------
# DeliveryAgent — TriageResult → Slack / Teams
# ---------------------------------------------------------------------------

class DeliveryInput(BaseModel):
    triage_result: TriageResult
    channels: list[str] = Field(default_factory=list)  # empty = auto-route by severity


class DeliveryOutput(BaseModel):
    delivered_to: list[str] = Field(default_factory=list)
    message_ids: dict[str, str] = Field(default_factory=dict)   # channel → message id
    delivery_errors: list[str] = Field(default_factory=list)

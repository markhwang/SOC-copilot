"""
Response models — outputs from LLM agents and the final orchestrator result.

Internal model hierarchy:
  SummaryResult   — output of SummarizeAgent
  GuidanceResult  — output of GuidanceAgent
  TriageResult    — orchestrator's merged result (internal; not exposed directly)

External API model:
  TriageResponse  — flat shape returned by the /triage endpoint.
                    Produced by TriageResult.to_response().

The two models evolve independently: internal structure can change to support
new agents without breaking the API contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel, Field

from src.models.alert import AlertPayload
from src.models.enrichment import EnrichmentResult


class MitreMapping(BaseModel):
    """A single MITRE ATT&CK tactic + technique pair."""

    tactic_id: str       # e.g. "TA0001"
    tactic_name: str     # e.g. "Initial Access"
    technique_id: str    # e.g. "T1566.001"
    technique_name: str  # e.g. "Spearphishing Attachment"


class SummaryResult(BaseModel):
    """Output of SummarizeAgent — LLM-generated assessment of a single alert."""

    alert_id: str
    summary: str                              # 2–3 sentence plain-language description
    risk_score: int = Field(ge=1, le=10)      # 1 (almost certainly FP) → 10 (confirmed critical)
    confidence_score: float = Field(ge=0.0, le=1.0)  # how confident the model is in the assessment
    risk_reasoning: str                       # explanation of the score
    key_findings: list[str] = Field(default_factory=list)
    escalation_recommended: bool
    escalation_reason: Optional[str] = None


class GuidanceResult(BaseModel):
    """Output of GuidanceAgent — RAG-grounded investigation guidance."""

    alert_id: str
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    suggested_actions: list[str] = Field(default_factory=list)
    relevant_playbooks: list[str] = Field(default_factory=list)  # playbook names from RAG retrieval
    mitre_context: Optional[str] = None


class TriageResult(BaseModel):
    """Orchestrator's internal merged result combining all agent outputs.

    Not returned directly from the API — call .to_response() for the
    flat external representation.
    """

    alert_id: str
    alert: AlertPayload
    enrichment: EnrichmentResult
    summary: SummaryResult
    guidance: GuidanceResult
    processing_time_ms: int = 0
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_response(self) -> TriageResponse:
        """Produce the flat external API model from this internal result."""
        return TriageResponse(
            alert_id=self.alert_id,
            alert_source=self.alert.source.value,
            alert_severity=self.alert.severity.value,
            alert_title=self.alert.title,
            summary=self.summary.summary,
            risk_score=self.summary.risk_score,
            confidence_score=self.summary.confidence_score,
            risk_reasoning=self.summary.risk_reasoning,
            key_findings=self.summary.key_findings,
            escalation_recommended=self.summary.escalation_recommended,
            escalation_reason=self.summary.escalation_reason,
            mitre_mappings=self.guidance.mitre_mappings,
            investigation_steps=self.guidance.investigation_steps,
            suggested_actions=self.guidance.suggested_actions,
            relevant_playbooks=self.guidance.relevant_playbooks,
            mitre_context=self.guidance.mitre_context,
            enrichment_errors=self.enrichment.enrichment_errors,
            processing_time_ms=self.processing_time_ms,
            triaged_at=self.triaged_at,
        )


class TriageResponse(BaseModel):
    """Flat external API response returned by POST /triage.

    Mirrors the shape in examples/sample_outputs/triage_response.json.
    Suggested queries are absent — QueryAgent is strictly on-demand via
    the separate /query endpoint.
    """

    alert_id: str
    alert_source: str
    alert_severity: str
    alert_title: str
    summary: str
    risk_score: int
    confidence_score: float
    risk_reasoning: str
    key_findings: list[str] = Field(default_factory=list)
    escalation_recommended: bool
    escalation_reason: Optional[str] = None
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)
    suggested_actions: list[str] = Field(default_factory=list)
    relevant_playbooks: list[str] = Field(default_factory=list)
    mitre_context: Optional[str] = None
    enrichment_errors: list[str] = Field(default_factory=list)
    processing_time_ms: int = 0
    triaged_at: datetime

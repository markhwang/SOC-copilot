"""
SOC Copilot - Main API Server

FastAPI application providing AI-powered alert triage capabilities.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from openai import AzureOpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="SOC Copilot API",
    description="AI-powered Security Operations Center triage assistant",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")

# Initialize Azure OpenAI client
client = AzureOpenAI(
    azure_endpoint=AZURE_OPENAI_ENDPOINT,
    api_key=AZURE_OPENAI_API_KEY,
    api_version=AZURE_OPENAI_API_VERSION
)


# ============================================================================
# Data Models
# ============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertSource(str, Enum):
    SENTINEL = "sentinel"
    SPLUNK = "splunk"
    DEFENDER = "defender"
    CROWDSTRIKE = "crowdstrike"


class AlertEntity(BaseModel):
    """Entities extracted from the alert."""
    users: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    files: List[Dict[str, str]] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)


class UserContext(BaseModel):
    """User context from Entra ID."""
    department: Optional[str] = None
    title: Optional[str] = None
    manager: Optional[str] = None
    risk_score: Optional[int] = None
    mfa_enabled: Optional[bool] = None


class AssetContext(BaseModel):
    """Asset context from CMDB."""
    criticality: Optional[str] = None
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    last_patched: Optional[str] = None


class ThreatIntel(BaseModel):
    """Threat intelligence context."""
    ip_reputation: Optional[str] = None
    threat_actor: Optional[str] = None
    confidence: Optional[float] = None
    ioc_matches: List[str] = Field(default_factory=list)


class AlertEnrichment(BaseModel):
    """Enrichment data added to the alert."""
    user_context: Optional[UserContext] = None
    asset_context: Optional[AssetContext] = None
    threat_intel: Optional[ThreatIntel] = None
    historical_alerts_count: int = 0
    similar_alert_ids: List[str] = Field(default_factory=list)


class Alert(BaseModel):
    """Normalized security alert."""
    alert_id: str
    source: AlertSource
    timestamp: datetime
    severity: Severity
    title: str
    description: str
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    entities: AlertEntity = Field(default_factory=AlertEntity)
    enrichment: Optional[AlertEnrichment] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class TriageRequest(BaseModel):
    """Request for alert triage."""
    alert: Alert
    include_queries: bool = True
    max_investigation_steps: int = 5


class TriageResponse(BaseModel):
    """AI-generated triage response."""
    alert_id: str
    summary: str
    risk_score: int
    risk_reasoning: str
    key_findings: List[str]
    investigation_steps: List[str]
    suggested_queries: Dict[str, str] = Field(default_factory=dict)  # {"kql": "...", "spl": "..."}
    mitre_context: Optional[str] = None
    suggested_actions: List[str] = Field(default_factory=list)
    escalation_recommended: bool = False
    escalation_reason: Optional[str] = None
    processing_time_ms: int = 0


class QueryRequest(BaseModel):
    """Request for natural language to query translation."""
    question: str
    alert_context: Optional[Alert] = None
    target_platform: Optional[str] = "both"  # "kql", "spl", or "both"


class QueryResponse(BaseModel):
    """Generated queries from natural language."""
    question: str
    kql_query: Optional[str] = None
    spl_query: Optional[str] = None
    explanation: str
    performance_notes: Optional[str] = None


class FeedbackRequest(BaseModel):
    """Analyst feedback on triage response."""
    alert_id: str
    triage_helpful: bool
    rating: int = Field(ge=1, le=5)
    comments: Optional[str] = None
    actual_disposition: Optional[str] = None


# ============================================================================
# System Prompts
# ============================================================================

TRIAGE_SYSTEM_PROMPT = """You are SOC Copilot, an AI assistant for Security Operations Center analysts. Your role is to help analysts triage security alerts faster and more consistently.

## Your Capabilities
- Summarize complex security alerts in plain language
- Assess risk based on alert severity, asset criticality, user context, and threat intelligence
- Recommend investigation steps based on MITRE ATT&CK and organizational playbooks
- Generate KQL or SPL queries to support investigation
- Identify when escalation is warranted

## Your Constraints
- You NEVER take autonomous actions. All response actions require analyst approval.
- You acknowledge uncertainty. If you're not confident, say so.
- You cite your sources when referencing MITRE ATT&CK techniques.
- You do not make up information. If context is missing, note the gap.
- You prioritize security. When in doubt, recommend escalation.

## Risk Scoring Guidelines (1-10)
- 9-10: Critical - Confirmed compromise, active exfiltration, C-level target, known APT
- 7-8: High - Likely true positive, critical asset, matches threat intel
- 5-6: Medium - Possible true positive, needs investigation
- 3-4: Low - Likely false positive, matches known benign pattern
- 1-2: Informational - Almost certainly false positive

## Escalation Triggers
Recommend escalation if: Risk score ≥ 8, VIP user involved, active data exfiltration, matches APT TTPs, or multiple related alerts.

Respond in JSON format with the following structure:
{
    "summary": "2-3 sentence plain-language summary",
    "risk_score": 1-10,
    "risk_reasoning": "explanation for the score",
    "key_findings": ["finding 1", "finding 2"],
    "investigation_steps": ["step 1", "step 2"],
    "suggested_queries": {"kql": "query", "spl": "query"},
    "mitre_context": "relevant ATT&CK context",
    "suggested_actions": ["action 1", "action 2"],
    "escalation_recommended": true/false,
    "escalation_reason": "reason if escalation recommended"
}"""


QUERY_SYSTEM_PROMPT = """You are a security query expert. Translate natural language questions into KQL (Microsoft Sentinel) and SPL (Splunk) queries.

## Guidelines
1. Always provide both KQL and SPL versions
2. Include time bounds (default: last 24 hours)
3. Add comments explaining query logic
4. Warn about performance if query might be expensive
5. Use specific field names, avoid wildcards

## Common Table Mappings
| Data Type | Sentinel Table | Splunk Index |
|-----------|---------------|--------------|
| Sign-in logs | SigninLogs | index=azure_signin |
| Security events | SecurityEvent | index=wineventlog |
| Process events | DeviceProcessEvents | index=endpoint |
| Network events | DeviceNetworkEvents | index=firewall |

Respond in JSON format:
{
    "kql_query": "KQL query with comments",
    "spl_query": "SPL query with comments", 
    "explanation": "what the query does",
    "performance_notes": "any warnings"
}"""


# ============================================================================
# Helper Functions
# ============================================================================

def format_alert_for_prompt(alert: Alert) -> str:
    """Format alert data for inclusion in LLM prompt."""
    alert_text = f"""
## Alert Details
- **ID**: {alert.alert_id}
- **Source**: {alert.source.value}
- **Severity**: {alert.severity.value}
- **Time**: {alert.timestamp.isoformat()}
- **Title**: {alert.title}

## Description
{alert.description}

## MITRE ATT&CK
- Tactics: {', '.join(alert.mitre_tactics) if alert.mitre_tactics else 'None identified'}
- Techniques: {', '.join(alert.mitre_techniques) if alert.mitre_techniques else 'None identified'}

## Entities
- Users: {', '.join(alert.entities.users) if alert.entities.users else 'None'}
- Hosts: {', '.join(alert.entities.hosts) if alert.entities.hosts else 'None'}
- IPs: {', '.join(alert.entities.ips) if alert.entities.ips else 'None'}
- Files: {json.dumps(alert.entities.files) if alert.entities.files else 'None'}
- URLs: {', '.join(alert.entities.urls) if alert.entities.urls else 'None'}
"""
    
    if alert.enrichment:
        alert_text += "\n## Enrichment Context\n"
        
        if alert.enrichment.user_context:
            uc = alert.enrichment.user_context
            alert_text += f"""
### User Context
- Department: {uc.department or 'Unknown'}
- Title: {uc.title or 'Unknown'}
- Manager: {uc.manager or 'Unknown'}
- Risk Score: {uc.risk_score or 'Unknown'}
- MFA Enabled: {uc.mfa_enabled}
"""
        
        if alert.enrichment.asset_context:
            ac = alert.enrichment.asset_context
            alert_text += f"""
### Asset Context
- Criticality: {ac.criticality or 'Unknown'}
- Business Unit: {ac.business_unit or 'Unknown'}
- Owner: {ac.owner or 'Unknown'}
"""
        
        if alert.enrichment.threat_intel:
            ti = alert.enrichment.threat_intel
            alert_text += f"""
### Threat Intelligence
- IP Reputation: {ti.ip_reputation or 'Unknown'}
- Threat Actor: {ti.threat_actor or 'Unknown'}
- Confidence: {ti.confidence or 'Unknown'}
- IOC Matches: {', '.join(ti.ioc_matches) if ti.ioc_matches else 'None'}
"""
        
        alert_text += f"""
### Historical Context
- Alerts in last 30 days: {alert.enrichment.historical_alerts_count}
- Similar alerts: {', '.join(alert.enrichment.similar_alert_ids) if alert.enrichment.similar_alert_ids else 'None'}
"""
    
    return alert_text


def call_azure_openai(system_prompt: str, user_prompt: str, temperature: float = 0.3) -> str:
    """Call Azure OpenAI API and return the response."""
    try:
        response = client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=temperature,
            max_tokens=2000,
            response_format={"type": "json_object"}
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Azure OpenAI API error: {e}")
        raise HTTPException(status_code=500, detail=f"LLM processing error: {str(e)}")


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "service": "SOC Copilot API", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "azure_openai_configured": bool(AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY)
    }


@app.post("/api/v1/triage", response_model=TriageResponse)
async def triage_alert(request: TriageRequest):
    """
    Generate AI-powered triage for a security alert.
    
    Takes a normalized alert with optional enrichment and returns:
    - Plain-language summary
    - Risk assessment with reasoning
    - Recommended investigation steps
    - Suggested queries (KQL/SPL)
    - Escalation recommendation
    """
    import time
    start_time = time.time()
    
    # Format alert for prompt
    alert_text = format_alert_for_prompt(request.alert)
    
    user_prompt = f"""Please triage the following security alert and provide your analysis in JSON format.

{alert_text}

Provide:
1. A clear summary of what happened
2. Risk score (1-10) with reasoning
3. Key findings
4. Up to {request.max_investigation_steps} investigation steps
5. {"Relevant KQL and SPL queries" if request.include_queries else "Skip query generation"}
6. Suggested response actions
7. Whether escalation is recommended
"""
    
    # Call LLM
    response_text = call_azure_openai(TRIAGE_SYSTEM_PROMPT, user_prompt)
    
    try:
        response_data = json.loads(response_text)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response: {e}")
        raise HTTPException(status_code=500, detail="Failed to parse AI response")
    
    processing_time = int((time.time() - start_time) * 1000)
    
    return TriageResponse(
        alert_id=request.alert.alert_id,
        summary=response_data.get("summary", "Unable to generate summary"),
        risk_score=response_data.get("risk_score", 5),
        risk_reasoning=response_data.get("risk_reasoning", ""),
        key_findings=response_data.get("key_findings", []),
        investigation_steps=response_data.get("investigation_steps", []),
        suggested_queries=response_data.get("suggested_queries", {}),
        mitre_context=response_data.get("mitre_context"),
        suggested_actions=response_data.get("suggested_actions", []),
        escalation_recommended=response_data.get("escalation_recommended", False),
        escalation_reason=response_data.get("escalation_reason"),
        processing_time_ms=processing_time
    )


@app.post("/api/v1/query", response_model=QueryResponse)
async def generate_query(request: QueryRequest):
    """
    Translate natural language question to KQL/SPL query.
    
    Optionally include alert context for more specific queries.
    """
    user_prompt = f"Translate this question to security queries: {request.question}"
    
    if request.alert_context:
        alert_text = format_alert_for_prompt(request.alert_context)
        user_prompt += f"\n\nAlert context for reference:\n{alert_text}"
    
    response_text = call_azure_openai(QUERY_SYSTEM_PROMPT, user_prompt)
    
    try:
        response_data = json.loads(response_text)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse AI response")
    
    return QueryResponse(
        question=request.question,
        kql_query=response_data.get("kql_query") if request.target_platform in ["kql", "both"] else None,
        spl_query=response_data.get("spl_query") if request.target_platform in ["spl", "both"] else None,
        explanation=response_data.get("explanation", ""),
        performance_notes=response_data.get("performance_notes")
    )


@app.post("/api/v1/feedback")
async def submit_feedback(request: FeedbackRequest, background_tasks: BackgroundTasks):
    """
    Submit analyst feedback on triage quality.
    
    Used for continuous improvement of prompts and model performance.
    """
    # In production, this would store feedback in a database
    logger.info(f"Feedback received for alert {request.alert_id}: rating={request.rating}, helpful={request.triage_helpful}")
    
    # Background task to process feedback (e.g., update metrics, trigger retraining)
    background_tasks.add_task(process_feedback, request)
    
    return {"status": "acknowledged", "alert_id": request.alert_id}


async def process_feedback(feedback: FeedbackRequest):
    """Background task to process feedback."""
    # Placeholder for feedback processing logic
    # In production: store in database, update dashboards, trigger alerts on low ratings
    logger.info(f"Processing feedback for {feedback.alert_id}")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

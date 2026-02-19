# SOC Copilot: Design Document

## 1. Executive Summary

SOC Copilot is an LLM-powered triage assistant designed to reduce L1 analyst workload by 75% through intelligent alert summarization, contextual enrichment, and guided investigation workflows. The system augments—not replaces—human analysts by handling repetitive cognitive tasks while preserving human judgment for critical decisions.

### Problem Statement

Modern SOCs face:
- **Alert fatigue**: 10,000+ alerts/day, 45% are false positives
- **Analyst burnout**: High turnover, 6-12 month ramp-up time
- **Inconsistent triage**: Quality varies by analyst experience
- **Skill shortage**: Not enough senior analysts to mentor juniors

### Solution

An AI assistant that:
1. Reads and summarizes alerts in plain language
2. Enriches alerts with relevant context automatically
3. Recommends investigation steps based on playbooks and ATT&CK
4. Generates queries (KQL/SPL) from natural language
5. Drafts response actions for analyst approval

### Success Criteria

| Metric | Current State | Target | Timeline |
|--------|---------------|--------|----------|
| Mean Time to Triage (MTTT) | 15 minutes | 4 minutes | 6 months |
| Alerts per analyst per shift | 20 | 50 | 6 months |
| L1 → L2 escalation rate | 40% | 25% | 6 months |
| Analyst satisfaction (NPS) | +10 | +40 | 12 months |

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Data Sources                                 │
├─────────────────────────────────────────────────────────────────────┤
│  Sentinel  │  Splunk ES  │  Defender  │  CrowdStrike  │  Chronicle  │
└─────┬──────┴──────┬──────┴─────┬──────┴───────┬───────┴──────┬──────┘
      │             │            │              │              │
      └─────────────┴────────────┼──────────────┴──────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │   Ingestion Service    │
                    │   (Azure Functions)    │
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Message Queue        │
                    │   (Service Bus)        │
                    └───────────┬────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Enrichment     │  │  RAG Service    │  │  LLM Service    │
│  Service        │  │  (AI Search)    │  │  (Azure OpenAI) │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Orchestrator     │
                    │   (FastAPI)        │
                    └─────────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  Slack   │   │  Teams   │   │   Web    │
        │   Bot    │   │   Bot    │   │   App    │
        └──────────┘   └──────────┘   └──────────┘
```

### 2.2 Component Details

#### 2.2.1 Ingestion Service

**Purpose**: Receive alerts from multiple security platforms and normalize to common format.

**Technology**: Azure Functions (Python)

**Inputs**:
- Sentinel Analytics Rules (via webhook)
- Splunk ES Notable Events (via webhook)
- Defender for Endpoint Alerts (via API polling)

**Outputs**:
- Normalized alert JSON to Service Bus queue

**Normalization Schema**:
```json
{
  "alert_id": "string",
  "source": "sentinel|splunk|defender",
  "timestamp": "ISO8601",
  "severity": "critical|high|medium|low|informational",
  "title": "string",
  "description": "string",
  "mitre_tactics": ["TA0001", "TA0002"],
  "mitre_techniques": ["T1566.001"],
  "entities": {
    "users": ["user@domain.com"],
    "hosts": ["hostname"],
    "ips": ["192.168.1.1"],
    "files": [{"name": "malware.exe", "hash": "abc123"}],
    "urls": ["https://malicious.com"]
  },
  "raw_data": {}
}
```

#### 2.2.2 Enrichment Service

**Purpose**: Add context to alerts before LLM processing.

**Enrichment Sources**:

| Source | Data | Use Case |
|--------|------|----------|
| Entra ID | User role, department, manager, risk score | Determine if behavior is anomalous for role |
| CMDB | Asset criticality, owner, business unit | Prioritize alerts on critical assets |
| Threat Intel (MISP) | IOC reputation, threat actor attribution | Identify known malicious indicators |
| Historical Alerts | Previous alerts for same user/host | Detect patterns, repeat offenders |
| Sentinel Watchlists | VIPs, high-risk users, exception lists | Apply business context |

**Enriched Alert Schema** (additions):
```json
{
  "enrichment": {
    "user_context": {
      "department": "Finance",
      "title": "Senior Accountant",
      "manager": "jane.doe@company.com",
      "risk_score": 45,
      "last_password_change": "2024-01-15",
      "mfa_enabled": true
    },
    "asset_context": {
      "criticality": "high",
      "business_unit": "Treasury",
      "owner": "john.smith@company.com",
      "last_patched": "2024-01-20"
    },
    "threat_intel": {
      "ip_reputation": "malicious",
      "threat_actor": "APT29",
      "confidence": 0.85
    },
    "historical": {
      "alerts_30d": 3,
      "similar_alerts": ["alert-123", "alert-456"],
      "previous_disposition": "true_positive"
    }
  }
}
```

#### 2.2.3 RAG Service

**Purpose**: Retrieve relevant playbooks, procedures, and ATT&CK context for the alert.

**Technology**: Azure AI Search + Azure OpenAI Embeddings

**Document Corpus**:
1. **Incident Response Playbooks** (~50 documents)
   - Phishing response
   - Malware containment
   - Account compromise
   - Data exfiltration
   
2. **MITRE ATT&CK** (~200 documents)
   - Technique descriptions
   - Detection guidance
   - Mitigation recommendations
   
3. **Organization Procedures** (~30 documents)
   - Escalation criteria
   - Business hours contacts
   - Exception handling
   
4. **Historical Incidents** (~100 documents, anonymized)
   - Past incident summaries
   - Lessons learned
   - False positive patterns

**Retrieval Strategy**:
1. Generate embedding for alert (title + description + MITRE techniques)
2. Vector search against document corpus (top 5)
3. Keyword search for specific entities (hostnames, alert names)
4. Combine and deduplicate results
5. Return relevant chunks with source attribution

#### 2.2.4 LLM Service

**Purpose**: Generate analyst-facing outputs using GPT-4o.

**Technology**: Azure OpenAI Service (GPT-4o deployment)

**Functions**:

| Function | Input | Output |
|----------|-------|--------|
| Summarize | Enriched alert + RAG context | Plain-language summary |
| Assess Risk | Enriched alert | Risk score (1-10) with reasoning |
| Recommend Steps | Alert + playbook | Numbered investigation steps |
| Generate Query | Natural language question | KQL or SPL query |
| Draft Response | Alert + selected action | Response action draft |

**Token Management**:
- Input limit: 8,000 tokens (alert + enrichment + RAG)
- Output limit: 2,000 tokens
- Chunking strategy for large alerts

#### 2.2.5 Orchestrator (API)

**Purpose**: Coordinate services and expose REST API.

**Technology**: FastAPI (Python)

**Endpoints**:

```
POST /api/v1/alerts/triage
  - Input: alert_id
  - Output: {summary, risk_score, recommended_steps, suggested_queries}

POST /api/v1/alerts/query
  - Input: {alert_id, natural_language_question}
  - Output: {kql_query, spl_query, explanation}

POST /api/v1/alerts/action
  - Input: {alert_id, action_type, parameters}
  - Output: {draft_action, requires_approval: true}

POST /api/v1/feedback
  - Input: {alert_id, rating, comments}
  - Output: {acknowledged: true}
```

#### 2.2.6 Analyst Interfaces

**Slack Bot**:
- Receives alert notifications with triage summary
- Interactive buttons: "Investigate", "Close as FP", "Escalate"
- Thread-based conversation for follow-up questions
- `/soc-query` slash command for natural language queries

**Teams Bot**:
- Adaptive Cards for alert display
- Similar functionality to Slack bot
- Integration with Sentinel Incidents (link back)

**Web Dashboard**:
- Queue view of pending alerts
- Triage interface with AI recommendations
- Query builder with natural language input
- Feedback submission

---

## 3. Data Flow

### 3.1 Alert Triage Flow

```
1. Alert fires in Sentinel
   │
2. Webhook triggers Azure Function
   │
3. Function normalizes alert → Service Bus
   │
4. Orchestrator picks up alert
   │
5. Parallel enrichment:
   ├── User context (Entra ID)
   ├── Asset context (CMDB)
   ├── Threat intel (MISP)
   └── Historical alerts (Sentinel)
   │
6. RAG retrieval:
   ├── Playbooks matching alert type
   ├── ATT&CK techniques referenced
   └── Similar past incidents
   │
7. LLM processing:
   ├── Generate summary
   ├── Assess risk
   └── Recommend investigation steps
   │
8. Deliver to analyst:
   ├── Slack notification
   ├── Teams notification
   └── Dashboard update
   │
9. Analyst reviews and takes action
   │
10. Feedback captured for model improvement
```

### 3.2 Natural Language Query Flow

```
1. Analyst asks: "Show me all failed logins for this user in the last 24 hours"
   │
2. Orchestrator receives request with alert context
   │
3. LLM generates query:
   ├── KQL: SigninLogs | where UserPrincipalName == "user@domain.com" | where ResultType != 0 | where TimeGenerated > ago(24h)
   └── SPL: index=azure_signin user="user@domain.com" status=failure earliest=-24h
   │
4. Query validated (syntax check, guardrails)
   │
5. Optional: Execute query and return results
   │
6. Display to analyst with explanation
```

---

## 4. Security Controls

### 4.1 Data Protection

| Control | Implementation |
|---------|----------------|
| Data minimization | Only send required fields to LLM |
| PII redaction | Regex-based redaction before logging |
| Encryption in transit | TLS 1.3 for all API calls |
| Encryption at rest | Azure Storage encryption (AES-256) |
| Data residency | Azure OpenAI in same region as data |

### 4.2 Access Control

| Control | Implementation |
|---------|----------------|
| Authentication | Azure AD / Entra ID |
| Authorization | RBAC based on SOC tier |
| API authentication | Managed Identity + API keys |
| Audit logging | All actions logged to Log Analytics |

### 4.3 LLM-Specific Controls

| Risk | Mitigation |
|------|------------|
| Prompt injection | Input validation, output filtering |
| Data leakage | No customer data in training |
| Hallucination | RAG grounding, confidence scores |
| Overreliance | All actions require human approval |

### 4.4 Compliance

- SOC 2 Type II audit logging
- GDPR: PII handling documented
- Data retention: 90 days for LLM interactions

---

## 5. Implementation Phases

### Phase 1: Foundation (Weeks 1-4)
- [ ] Set up Azure OpenAI service
- [ ] Build alert ingestion for Sentinel
- [ ] Implement basic summarization
- [ ] Deploy Slack bot (read-only)

### Phase 2: Enrichment (Weeks 5-8)
- [ ] Integrate Entra ID for user context
- [ ] Integrate CMDB for asset context
- [ ] Add threat intelligence enrichment
- [ ] Build RAG pipeline with playbooks

### Phase 3: Intelligence (Weeks 9-12)
- [ ] Implement risk scoring
- [ ] Add investigation recommendations
- [ ] Build natural language query generation
- [ ] Add response action drafting

### Phase 4: Scale (Weeks 13-16)
- [ ] Add Splunk and Defender ingestion
- [ ] Deploy Teams bot
- [ ] Build web dashboard
- [ ] Implement feedback loop

### Phase 5: Optimization (Ongoing)
- [ ] Fine-tune prompts based on feedback
- [ ] Expand RAG corpus
- [ ] Add new alert sources
- [ ] Measure and report metrics

---

## 6. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| LLM hallucination leads to missed threat | Medium | High | RAG grounding, human approval required |
| API rate limits during incident surge | Medium | Medium | Queue-based processing, retry logic |
| Analyst over-reliance on AI | Medium | Medium | Training, require justification for actions |
| Data exposure via LLM | Low | High | Data minimization, no PII in prompts |
| Cost overrun from token usage | Medium | Low | Token budgets, caching, prompt optimization |

---

## 7. Cost Estimate

### Azure OpenAI (Monthly)

| Component | Volume | Unit Cost | Monthly Cost |
|-----------|--------|-----------|--------------|
| GPT-4o Input | 10M tokens | $0.005/1K | $50 |
| GPT-4o Output | 2M tokens | $0.015/1K | $30 |
| Embeddings | 5M tokens | $0.0001/1K | $0.50 |
| **Subtotal** | | | **$80.50** |

### Azure Infrastructure (Monthly)

| Component | SKU | Monthly Cost |
|-----------|-----|--------------|
| Azure Functions | Consumption | $20 |
| Service Bus | Standard | $10 |
| AI Search | Basic | $70 |
| App Service | B2 | $55 |
| Storage | Standard | $5 |
| **Subtotal** | | **$160** |

### Total Estimated Monthly Cost: **~$250**

*(Based on 1,000 alerts/day, 30-day month)*

---

## 8. Success Metrics Dashboard

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOC Copilot Metrics                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  MTTT (Mean Time to Triage)         Alerts Triaged Today        │
│  ┌──────────────────────┐           ┌──────────────────────┐   │
│  │   4.2 min            │           │   847                │   │
│  │   ▼ 72% from 15 min  │           │   ▲ 23% from avg     │   │
│  └──────────────────────┘           └──────────────────────┘   │
│                                                                 │
│  L1 Escalation Rate                 Analyst Satisfaction        │
│  ┌──────────────────────┐           ┌──────────────────────┐   │
│  │   28%                │           │   NPS: +35           │   │
│  │   ▼ from 40%         │           │   ▲ from +10         │   │
│  └──────────────────────┘           └──────────────────────┘   │
│                                                                 │
│  AI Accuracy (7-day rolling)                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Helpful: 78%  │  Neutral: 15%  │  Not Helpful: 7%       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Appendix

### A. Glossary

| Term | Definition |
|------|------------|
| MTTT | Mean Time to Triage - time from alert creation to analyst disposition |
| RAG | Retrieval-Augmented Generation - grounding LLM with relevant documents |
| KQL | Kusto Query Language - query language for Sentinel |
| SPL | Search Processing Language - query language for Splunk |

### B. References

- [Azure OpenAI Service Documentation](https://learn.microsoft.com/en-us/azure/ai-services/openai/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### C. Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-30 | Mark Hwang | Initial design document |

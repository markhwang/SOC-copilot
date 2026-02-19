# SOC Copilot: LLM-Powered Alert Triage Assistant

An AI-powered Security Operations Center (SOC) triage tool built on Azure OpenAI to assist analysts with alert investigation. Designed to reduce L1 analyst workload by up to 75% through intelligent alert summarization, contextual enrichment, and guided investigation workflows.

## Overview

SOC Copilot augments human analysts by:
- **Summarizing alerts** in plain language with key context
- **Enriching alerts** with threat intelligence, asset context, and historical patterns
- **Recommending investigation steps** based on alert type and MITRE ATT&CK mapping
- **Drafting response actions** for common scenarios
- **Querying security data** using natural language (translates to KQL/SPL)

This is **not** an autonomous response system. All actions require analyst approval. The goal is to accelerate triage, not replace human judgment.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SOC Copilot Architecture                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │   Sentinel   │    │  Splunk ES   │    │   Defender for Endpoint  │  │
│  │   Alerts     │    │   Alerts     │    │       Alerts             │  │
│  └──────┬───────┘    └──────┬───────┘    └────────────┬─────────────┘  │
│         │                   │                         │                 │
│         └───────────────────┼─────────────────────────┘                 │
│                             ▼                                           │
│                 ┌───────────────────────┐                               │
│                 │   Alert Ingestion     │                               │
│                 │   (Azure Function)    │                               │
│                 └───────────┬───────────┘                               │
│                             │                                           │
│                             ▼                                           │
│                 ┌───────────────────────┐                               │
│                 │   Enrichment Layer    │                               │
│                 │  - Asset Context      │                               │
│                 │  - User Context       │                               │
│                 │  - Threat Intel       │                               │
│                 │  - Historical Alerts  │                               │
│                 └───────────┬───────────┘                               │
│                             │                                           │
│                             ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Azure OpenAI Service                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │  │
│  │  │   GPT-4o    │  │  Embedding  │  │   RAG: Playbooks,       │  │  │
│  │  │   Model     │  │   Model     │  │   TTPs, Procedures      │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                           │
│                             ▼                                           │
│                 ┌───────────────────────┐                               │
│                 │   SOC Copilot API     │                               │
│                 │   (FastAPI Backend)   │                               │
│                 └───────────┬───────────┘                               │
│                             │                                           │
│                             ▼                                           │
│                 ┌───────────────────────┐                               │
│                 │   Analyst Interface   │                               │
│                 │  - Slack Bot          │                               │
│                 │  - Teams Bot          │                               │
│                 │  - Web Dashboard      │                               │
│                 └───────────────────────┘                               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Alert Ingestion
- Webhook receivers for Sentinel, Splunk, and Defender alerts
- Normalization layer to standardize alert format
- Priority queue based on severity and asset criticality

### 2. Enrichment Layer
- Asset context from CMDB/ServiceNow
- User context from Entra ID (role, department, risk score)
- Threat intelligence from MISP, Anomali ThreatStream
- Historical alert patterns for the same user/asset

### 3. RAG (Retrieval-Augmented Generation)
- Incident response playbooks
- MITRE ATT&CK technique descriptions
- Organization-specific procedures
- Historical incident summaries (anonymized)

### 4. LLM Processing
- Alert summarization and risk assessment
- Investigation step recommendations
- KQL/SPL query generation from natural language
- Response action drafting

### 5. Analyst Interface
- Slack/Teams integration for alert delivery
- Interactive buttons for common actions
- Feedback loop for model improvement

## Target Metrics

| Metric | Before | Target | Measurement |
|--------|--------|--------|-------------|
| Mean Time to Triage | 15 min | 4 min | Alert open → disposition |
| L1 Escalation Rate | 40% | 25% | Alerts requiring L2 review |
| Analyst Throughput | 20 alerts/shift | 50 alerts/shift | Alerts triaged per 8hr shift |
| False Positive Closure | 25 min | 5 min | Time to close confirmed FP |

**Overall target: 75% reduction in L1 analyst time per alert**

## Repository Structure

```
soc-copilot/
├── README.md
├── architecture/
│   ├── design-doc.md          # Detailed design document
│   ├── data-flow.md           # Data flow diagrams
│   └── security-controls.md   # Security & privacy controls
├── src/
│   ├── ingestion/             # Alert ingestion functions
│   ├── enrichment/            # Context enrichment modules
│   ├── llm/                   # Azure OpenAI integration
│   ├── api/                   # FastAPI backend
│   └── interfaces/            # Slack/Teams bots
├── prompts/
│   ├── system_prompt.md       # Core system prompt
│   ├── triage_prompt.md       # Alert triage prompt
│   ├── query_generation.md    # KQL/SPL generation prompt
│   └── response_draft.md      # Response action prompt
├── rag_documents/
│   ├── playbooks/             # IR playbooks
│   ├── mitre/                 # ATT&CK technique docs
│   └── procedures/            # Org-specific procedures
├── examples/
│   ├── sample_alerts/         # Example alert payloads
│   └── sample_outputs/        # Example LLM responses
└── docs/
    ├── deployment.md          # Deployment guide
    ├── configuration.md       # Configuration options
    └── feedback-loop.md       # Analyst feedback system
```

## Quick Start

### Prerequisites
- Azure subscription with OpenAI Service enabled
- Python 3.10+
- Access to Sentinel/Splunk/Defender APIs

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/soc-copilot.git
cd soc-copilot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Azure OpenAI credentials
```

### Configuration

```bash
# Set environment variables
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/"
export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_DEPLOYMENT="gpt-4o"
export SENTINEL_WORKSPACE_ID="your-workspace-id"
```

### Run locally

```bash
# Start the API server
uvicorn src.api.main:app --reload

# In another terminal, start the Slack bot
python src/interfaces/slack_bot.py
```

## Security Considerations

- **No sensitive data in prompts**: Alert payloads are sanitized before LLM processing
- **PII redaction**: Automated redaction of names, emails, IPs before logging
- **Audit logging**: All LLM interactions logged for compliance
- **Role-based access**: Analysts can only access alerts for their scope
- **Data residency**: Azure OpenAI deployed in same region as security data

## Contributing

This project is open for contributions. Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Built with lessons learned from implementing security automation at enterprise scale. Special thanks to the Microsoft Security community for architecture guidance.

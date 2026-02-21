# CLAUDE.md — SOC Copilot

## What this project is

SOC Copilot is an LLM-powered Security Operations Center (SOC) triage assistant built for enterprise financial services environments. It sits between security platforms (Microsoft Sentinel, Splunk, Defender) and L1 analysts, accelerating alert investigation and reducing analyst fatigue.

**North star metric:** 75% reduction in L1 analyst time-per-alert.

Core capabilities:
- **Alert summarization** — translates raw security alerts into plain-language summaries with risk scores
- **Contextual enrichment** — pulls user context from Entra ID, asset criticality from CMDB, and threat intel from external feeds
- **Investigation guidance** — recommends next steps via RAG over MITRE ATT&CK and internal playbooks
- **NL-to-query translation** — converts analyst questions into KQL (Sentinel) and SPL (Splunk) queries
- **Bot delivery** — Slack and Microsoft Teams bots for real-time alert triage

Humans remain in the loop for all response actions. The tool augments, not replaces, analysts.

---

## Architecture: multi-agent orchestration

SOC Copilot is built as a **multi-agent system**, not a sequential pipeline. Each stage is a discrete agent with typed inputs and outputs. The orchestrator fans work out in parallel, collects results, and hands off to delivery.

```
Ingest Agent
     │  normalizes raw alert → AlertPayload
     ▼
Orchestrator
     │  fans out in parallel:
     ├──▶ Enrich Agent     →  EnrichmentResult  (Entra ID + CMDB + threat intel, all async)
     ├──▶ Summarize Agent  →  SummaryResult     (GPT-4o call, structured output)
     └──▶ Guidance Agent   →  GuidanceResult    (RAG over MITRE ATT&CK + playbooks)
     │  collects & merges into TriageResult
     ▼
Query Agent          (on-demand, analyst-triggered: NL → KQL/SPL)
     ▼
Delivery Agent       (routes TriageResult to Slack or Teams by severity)
```

**Why agents, not a pipeline?**
- Enrich, Summarize, and Guidance run in parallel — no sequential waiting
- Each agent is independently testable and replaceable
- Different models per agent: cheaper/faster for lookup and routing, GPT-4o only for summarization and guidance
- Orchestrator manages retries, timeouts, and fallback logic cleanly per-agent
- Maps directly onto the Claude Agent SDK `Task` pattern

---

## Tech stack

| Layer | Technology |
|---|---|
| LLM | Azure OpenAI GPT-4o (`openai` Python SDK, Azure endpoint) |
| Agent orchestration | Claude Agent SDK (subagents via `Task` pattern) |
| RAG / Vector store | Azure AI Search (prod) or Chroma (local dev) |
| Alert sources | Microsoft Sentinel (REST API), Splunk (REST API), Microsoft Defender |
| Enrichment | Microsoft Graph API (Entra ID), ServiceNow or custom CMDB REST API |
| Threat intel | MISP, VirusTotal, or AbuseIPDB |
| Bot delivery | Slack Bolt SDK, Microsoft Bot Framework (Teams) |
| API layer | FastAPI |
| Auth | Azure Managed Identity (prod), service principal (dev) |
| Config | pydantic-settings, `.env` file |
| Testing | pytest + pytest-asyncio |

---

## `src/` structure

```
src/
  main.py                    # FastAPI app — mounts routes, wires agents
  config.py                  # pydantic-settings: load + validate all env vars, fail fast

  models/
    alert.py                 # AlertPayload — normalized schema for Sentinel/Splunk/Defender alerts
    enrichment.py            # EnrichmentResult — Entra ID user, CMDB asset, threat intel hits
    response.py              # SummaryResult, GuidanceResult, TriageResult (final merged output)
    agent_io.py              # Typed input/output contracts for every agent

  agents/
    orchestrator.py          # Fans out to Enrich/Summarize/Guidance in parallel, merges results
    ingest.py                # IngestAgent: raw alert → AlertPayload (handles Sentinel, Splunk, Defender)
    enrich.py                # EnrichAgent: AlertPayload → EnrichmentResult (parallel async lookups)
    summarize.py             # SummarizeAgent: AlertPayload + EnrichmentResult → SummaryResult
    guidance.py              # GuidanceAgent: AlertPayload → GuidanceResult (RAG, MITRE ATT&CK)
    query.py                 # QueryAgent: natural language → KQL or SPL (on-demand)
    delivery.py              # DeliveryAgent: TriageResult → Slack or Teams (by severity)

  rag/
    loader.py                # Load and chunk documents from rag_documents/
    index.py                 # Build and query vector index (Chroma local, AI Search prod)

  integrations/
    sentinel_ingest.py       # Sentinel: validate webhook signature, normalize alert → AlertPayload
    sentinel_query.py        # Sentinel: execute KQL against Log Analytics API → results (on-demand)
    splunk_ingest.py         # Splunk: normalize inbound notable event → AlertPayload
    splunk_query.py          # Splunk: execute SPL search job against Splunk REST API → results (on-demand)
    defender.py              # Microsoft Defender API client (alert polling)
    graph.py                 # Microsoft Graph API (Entra ID user lookups)
    cmdb.py                  # CMDB REST API client (asset criticality)
    threat_intel.py          # MISP / VirusTotal / AbuseIPDB client
    slack.py                 # Slack Bolt event handler
    teams.py                 # Teams Bot Framework adapter

  utils/
    logging.py               # Structured JSON logging — no bare print()
    retry.py                 # Exponential backoff decorator for all external API calls
```

---

## Agent interface contract

Every agent follows this pattern — enforce it from the start:

```python
# agent_io.py defines all typed I/O
class IngestInput(BaseModel): ...
class IngestOutput(BaseModel): ...

# Each agent exposes a single async entry point
async def run(input: IngestInput) -> IngestOutput: ...
```

Agents are called by the orchestrator using the Claude Agent SDK `Task` primitive. Never call agents directly from FastAPI routes — always go through the orchestrator.

---

## Prompts

All LLM prompts live in `prompts/` as `.jinja2` files. Never hardcode prompt strings in Python.

```
prompts/
  summarize.jinja2       # Alert summarization + risk scoring
  guidance.jinja2        # MITRE ATT&CK mapping + next-step recommendations
  query_kql.jinja2       # NL → KQL translation
  query_spl.jinja2       # NL → SPL translation
```

---

## Priority build order

Build and test each stage independently before wiring agents together.

1. **`src/config.py`** — pydantic-settings, fail fast on missing env vars
2. **`src/models/`** — all Pydantic schemas including `agent_io.py` contracts
3. **`src/agents/summarize.py`** + `prompts/summarize.jinja2` — first real GPT-4o call
4. **`src/agents/ingest.py`** — normalize Sentinel and Splunk alert formats
5. **`src/agents/enrich.py`** — Entra ID + CMDB + threat intel (async, parallel)
6. **`src/agents/guidance.py`** + RAG pipeline (`src/rag/`) + seed `rag_documents/`
7. **`src/agents/orchestrator.py`** — fan-out, parallel execution, result merging
8. **`src/main.py`** — FastAPI app wiring orchestrator to HTTP routes
9. **`src/agents/query.py`** + `prompts/query_kql.jinja2` + `prompts/query_spl.jinja2`
10. **`src/agents/delivery.py`** + `src/integrations/slack.py` + `src/integrations/teams.py`

---

## Dev-time agents (use these while building)

Invoke these as Claude Code subagents during development:

| Agent | When to use |
|---|---|
| **test-runner** | After every code change — run `pytest`, return structured pass/fail |
| **bug-fixer** | Given a failing test, trace to root cause, fix, re-run until green |
| **schema-validator** | Feed a real Sentinel/Splunk payload — verify models parse correctly |
| **prompt-evaluator** | Run batch of example alerts through `summarize.py`, score output quality |

Pattern: write the test spec → bug-fixer writes code and fixes until tests pass → commit.

---

## Development setup

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Fill in .env with real values before running anything

uvicorn src.main:app --reload   # Local API
pytest tests/ -v                # Run tests
```

---

## Environment variables (see `.env.example`)

- `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT_NAME`
- `SENTINEL_WORKSPACE_ID`, `SENTINEL_API_KEY`
- `SPLUNK_HOST`, `SPLUNK_TOKEN`
- `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`
- `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`
- `TEAMS_APP_ID`, `TEAMS_APP_PASSWORD`

Never commit `.env`. It is gitignored.

---

## Coding conventions

- Python 3.11+
- Type hints on every function signature
- Pydantic models for all data structures — no raw dicts across agent boundaries
- `async`/`await` everywhere I/O is involved
- All external API calls use the `retry.py` exponential backoff decorator
- Structured JSON logging via `logging.py` — no `print()`
- Prompts in `prompts/` as `.jinja2` — never hardcoded in Python
- One function, one responsibility — agents must be independently runnable and testable
- Financial services constraint: all LLM calls go through Azure OpenAI, never direct OpenAI API

---

## Domain context

- Sentinel/Splunk alerts are noisy — expect high false-positive rates. The summarizer must output a confidence score, not just a risk score.
- Use MITRE ATT&CK tactic/technique IDs (e.g., T1078 Valid Accounts, TA0001 Initial Access) in all guidance output.
- No alert data leaves approved Azure cloud boundaries — this is a hard compliance requirement.
- Seed `rag_documents/` with realistic playbook examples early — RAG is useless without content.
- KQL (Sentinel) and SPL (Splunk) are different languages — the query agent must detect which platform the analyst is working in and route accordingly.

---

## Git sync

```bash
git push origin main   # gh CLI handles auth — no PAT needed
```
Repo: https://github.com/markhwang/SOC-copilot

---

## Session logging (required)

At the **start** of every session:
1. Read `memory/MEMORY.md` and `memory/sessions.md` to restore context on project state, last commit, and next steps.

At the **end** of every session (or after any meaningful block of work):
1. Append a new entry to `memory/sessions.md` with: date, commit hash, files created/modified, and design decisions made.
2. Update `memory/MEMORY.md` to reflect the new project state (last commit, build order progress, next step).

Memory files live at:
```
~/.claude/projects/-Users-markhwang-Library-Mobile-Documents-com-apple-CloudDocs-dev-SOC-copilot-soc-copilot/memory/
  MEMORY.md      # project state snapshot — loaded into context each session
  sessions.md    # append-only change log — one entry per session
```

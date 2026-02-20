"""
SummarizeAgent — AlertPayload + EnrichmentResult → SummaryResult.

Calls Azure OpenAI GPT-4o with a Jinja2-rendered prompt and validates
the response into a typed SummaryResult. This is the core LLM call in
the triage pipeline.

Entry point: async def run(input: SummarizeInput) -> SummarizeOutput
"""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncAzureOpenAI

from src.config import get_settings
from src.models.agent_io import SummarizeInput, SummarizeOutput
from src.models.response import SummaryResult
from src.utils.prompts import render_template

logger = logging.getLogger(__name__)

_TEMPERATURE = 0.2
_MAX_TOKENS = 1000


async def _call_openai(system_prompt: str, user_prompt: str) -> str:
    """Call Azure OpenAI and return the raw response string.

    Extracted as a standalone function so tests can patch it without
    touching the OpenAI client directly.
    """
    settings = get_settings()
    client = AsyncAzureOpenAI(
        azure_endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
    )
    response = await client.chat.completions.create(
        model=settings.azure_openai_deployment_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=_TEMPERATURE,
        max_tokens=_MAX_TOKENS,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


async def run(input: SummarizeInput) -> SummarizeOutput:
    """Summarize a security alert using GPT-4o.

    Args:
        input: SummarizeInput containing the normalized alert and enrichment.

    Returns:
        SummarizeOutput with a fully validated SummaryResult.

    Raises:
        RuntimeError: If required settings are missing (from validate_for_agent).
        ValueError: If the model returns invalid JSON or a response that doesn't
                    match the SummaryResult schema.
    """
    settings = get_settings()
    settings.validate_for_agent("summarize")

    alert_id = input.alert.alert_id
    logger.info("summarize_agent.start", extra={"alert_id": alert_id})

    system_prompt = render_template("summarize_system.jinja2")
    user_prompt = render_template(
        "summarize_user.jinja2",
        alert=input.alert,
        enrichment=input.enrichment,
    )

    raw = await _call_openai(system_prompt, user_prompt)

    data: dict[str, Any] = _parse_json(raw, alert_id)
    summary = _build_summary(data, alert_id)

    logger.info(
        "summarize_agent.complete",
        extra={
            "alert_id": alert_id,
            "risk_score": summary.risk_score,
            "confidence_score": summary.confidence_score,
            "escalation_recommended": summary.escalation_recommended,
        },
    )
    return SummarizeOutput(summary=summary)


def _parse_json(raw: str, alert_id: str) -> dict[str, Any]:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"SummarizeAgent: model returned invalid JSON for alert '{alert_id}': {e}\n"
            f"Raw response:\n{raw}"
        ) from e


def _build_summary(data: dict[str, Any], alert_id: str) -> SummaryResult:
    try:
        return SummaryResult(alert_id=alert_id, **data)
    except Exception as e:
        raise ValueError(
            f"SummarizeAgent: model response doesn't match SummaryResult schema "
            f"for alert '{alert_id}': {e}\n"
            f"Data: {data}"
        ) from e

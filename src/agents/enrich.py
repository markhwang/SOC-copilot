"""
EnrichAgent — AlertPayload → EnrichmentResult.

Queries three integration sources in parallel:
  1. Microsoft Entra ID   — user context (risk level, MFA, department)
  2. CMDB                 — asset criticality, owner, environment
  3. Threat intelligence  — IOC reputation for IPs, domains, hashes, URLs

All lookups are best-effort. Partial results are acceptable; failures are
captured in EnrichmentResult.enrichment_errors rather than raised.

Entry point: async def run(input: EnrichInput) -> EnrichOutput

Network I/O lives in src/integrations/graph.py, src/integrations/cmdb.py,
and src/integrations/threat_intel.py. The three _lookup_* functions below
are the patchable seams for tests.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.models.agent_io import EnrichInput, EnrichOutput
from src.models.alert import AlertEntities, AlertFile
from src.models.enrichment import CMDBAsset, EnrichmentResult, EntraUser, ThreatIntelHit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Patchable integration seams — tests replace these with AsyncMock
# ---------------------------------------------------------------------------

async def _lookup_entra_user(upn: str) -> EntraUser:
    """Fetch user context from Microsoft Entra ID (Graph API)."""
    from src.integrations.graph import get_user  # type: ignore[import]
    return await get_user(upn)


async def _lookup_cmdb_asset(hostname: str) -> CMDBAsset:
    """Fetch asset context from CMDB."""
    from src.integrations.cmdb import get_asset  # type: ignore[import]
    return await get_asset(hostname)


async def _lookup_threat_intel(ioc_value: str, ioc_type: str) -> ThreatIntelHit | None:
    """Check IOC reputation against threat intelligence feeds. Returns None if clean/unknown."""
    from src.integrations.threat_intel import check_ioc  # type: ignore[import]
    return await check_ioc(ioc_value, ioc_type)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_iocs(entities: AlertEntities) -> list[tuple[str, str]]:
    """Return (value, ioc_type) tuples for all enrichable IOCs in entities."""
    iocs: list[tuple[str, str]] = []
    for ip in entities.ips:
        iocs.append((ip, "ip"))
    for domain in entities.domains:
        iocs.append((domain, "domain"))
    for url in entities.urls:
        iocs.append((url, "url"))
    for file in entities.files:
        if file.hash:
            iocs.append((file.hash, "hash"))
    return iocs


async def _enrich_users(
    upns: list[str], errors: list[str]
) -> dict[str, EntraUser]:
    """Fetch all users in parallel; capture per-user errors without failing the batch."""
    if not upns:
        return {}

    results = await asyncio.gather(
        *[_lookup_entra_user(upn) for upn in upns],
        return_exceptions=True,
    )

    users: dict[str, EntraUser] = {}
    for upn, result in zip(upns, results):
        if isinstance(result, BaseException):
            errors.append(f"Entra ID lookup failed for '{upn}': {result}")
            logger.warning("enrich_agent.entra_error", extra={"upn": upn, "error": str(result)})
        else:
            users[upn] = result

    return users


async def _enrich_assets(
    hostnames: list[str], errors: list[str]
) -> dict[str, CMDBAsset]:
    """Fetch all assets in parallel; capture per-asset errors without failing the batch."""
    if not hostnames:
        return {}

    results = await asyncio.gather(
        *[_lookup_cmdb_asset(hostname) for hostname in hostnames],
        return_exceptions=True,
    )

    assets: dict[str, CMDBAsset] = {}
    for hostname, result in zip(hostnames, results):
        if isinstance(result, BaseException):
            errors.append(f"CMDB lookup failed for '{hostname}': {result}")
            logger.warning("enrich_agent.cmdb_error", extra={"hostname": hostname, "error": str(result)})
        else:
            assets[hostname] = result

    return assets


async def _enrich_threat_intel(
    iocs: list[tuple[str, str]], errors: list[str]
) -> list[ThreatIntelHit]:
    """Check all IOCs in parallel; collect hits (non-None returns); capture errors."""
    if not iocs:
        return []

    results = await asyncio.gather(
        *[_lookup_threat_intel(value, ioc_type) for value, ioc_type in iocs],
        return_exceptions=True,
    )

    hits: list[ThreatIntelHit] = []
    for (value, ioc_type), result in zip(iocs, results):
        if isinstance(result, BaseException):
            errors.append(f"Threat intel lookup failed for '{value}' ({ioc_type}): {result}")
            logger.warning(
                "enrich_agent.threat_intel_error",
                extra={"ioc": value, "type": ioc_type, "error": str(result)},
            )
        elif result is not None:
            hits.append(result)

    return hits


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run(input: EnrichInput) -> EnrichOutput:
    """Enrich an alert with user, asset, and threat intelligence context.

    Args:
        input: EnrichInput containing the normalized AlertPayload.

    Returns:
        EnrichOutput with a fully (or partially) populated EnrichmentResult.
        Never raises — all lookup failures are captured in enrichment_errors.
    """
    alert = input.alert
    entities = alert.entities
    errors: list[str] = []

    logger.info(
        "enrich_agent.start",
        extra={
            "alert_id": alert.alert_id,
            "users": len(entities.users),
            "hosts": len(entities.hosts),
        },
    )

    iocs = _collect_iocs(entities)

    # Fan out all three enrichment sources in parallel
    users, assets, threat_intel = await asyncio.gather(
        _enrich_users(entities.users, errors),
        _enrich_assets(entities.hosts, errors),
        _enrich_threat_intel(iocs, errors),
    )

    enrichment = EnrichmentResult(
        alert_id=alert.alert_id,
        users=users,
        assets=assets,
        threat_intel=threat_intel,
        enrichment_errors=errors,
    )

    logger.info(
        "enrich_agent.complete",
        extra={
            "alert_id": alert.alert_id,
            "users_enriched": len(users),
            "assets_enriched": len(assets),
            "threat_intel_hits": len(threat_intel),
            "errors": len(errors),
        },
    )

    return EnrichOutput(enrichment=enrichment)

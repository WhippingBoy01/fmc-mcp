"""Cisco FMC MCP server (Streamable HTTP / stdio) using FastMCP.

Exposes read tools and gated CRUD tools for core FMC objects and access policies/rules.
Mutating operations require FMC_ALLOW_WRITES=true.

FMC REST payloads vary by version. Confirm write payloads and field names in:
https://<fmc-host>/api/api-explorer
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

from fastmcp import FastMCP

from .analysis import (
    analyze_opening,
    audit_access_policy_inspection as audit_inspection,
    find_unused_access_rules as _find_unused_access_rules,
    find_unused_objects as _find_unused_objects,
    trace_access_policy,
)
from .config import ConfigError, Settings, load_settings, require_writes
from .fmc_client import FMCAPIError, FMCClient

logging.basicConfig(
    stream=sys.stderr,
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("fmc_mcp")

_settings: Settings | None = None
_client: FMCClient | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
        logging.getLogger().setLevel(_settings.log_level)
    return _settings


async def get_client() -> FMCClient:
    global _client
    if _client is None:
        s = get_settings()
        _client = FMCClient(
            s.base_url,
            s.username,
            s.password,
            verify=s.verify,
            timeout=s.timeout,
            domain_uuid=s.domain_uuid,
        )
        await _client.login()
        logger.info("Connected to FMC at %s (domain=%s)", s.base_url, await _client.domain_uuid())
    return _client


try:
    mcp = FastMCP(
        name="cisco-fmc-mcp",
        instructions=(
            "Tools for Cisco Secure Firewall Management Center (FMC). "
            "Read tools query FMC objects, policies, rules, devices, and deployment status. "
            "Use investigate_firewall_opening for human firewall-opening tickets "
            "(source/destination as IP, CIDR/subnet, IP range a-b, or FQDN; protocol/port). "
            "Use trace_packet_access_rules to simulate packet evaluation through access rules in order "
            "(rule-criteria trace, not full FTD datapath). Use list_policy_assignments/list_devices to find the applied ACP. "
            "Use audit_access_policy_inspection for implicit deny/default action and IPS/IDS (intrusion policy) checks. "
            "Use find_unused_access_rules and find_unused_objects for unused-candidate cleanup analysis (best-effort). "
            "Create/update/delete tools require FMC_ALLOW_WRITES=true and should be used only after reviewing payloads. "
            "Confirm write payloads in FMC API Explorer."
        ),
    )
except TypeError:
    mcp = FastMCP("cisco-fmc-mcp")


def ok(**data: Any) -> dict[str, Any]:
    return {"ok": True, **data}


def fail(exc: Exception) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
    details = getattr(exc, "details", None)
    if details is not None:
        payload["details"] = details
    status = getattr(exc, "status_code", None)
    if status is not None:
        payload["status_code"] = status
    return payload


def _clean(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None and v != ""}


# ---------- Read / status ----------


@mcp.tool
async def get_fmc_status() -> dict[str, Any]:
    """Return FMC connection/domain info and server write mode."""
    try:
        s = get_settings()
        client = await get_client()
        domain = await client.domain_uuid()
        return ok(
            fmc_host=s.base_url,
            domain_uuid=domain,
            writes_enabled=s.allow_writes,
            transport=s.mcp_transport,
        )
    except (ConfigError, FMCAPIError, Exception) as exc:
        return fail(exc)


@mcp.tool
async def get_deployment_status() -> dict[str, Any]:
    """List devices with undeployed/pending configuration changes."""
    try:
        client = await get_client()
        path = await client.config_path("/deployment/deployabledevices")
        items = await client.get_all(path)
        return ok(pending_device_count=len(items), pending_devices=items)
    except (FMCAPIError, Exception) as exc:
        return fail(exc)


# ---------- Generic object helpers ----------


OBJECT_ENDPOINTS = {
    "hosts": "/object/hosts",
    "networks": "/object/networks",
    "ranges": "/object/ranges",
    "fqdns": "/object/fqdns",
    "ports": "/object/protocolportobjects",
    "port_object_groups": "/object/portobjectgroups",
    "network_groups": "/object/networkgroups",
    "urls": "/object/urls",
}


async def _list_objects(kind: str, expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    try:
        client = await get_client()
        suffix = OBJECT_ENDPOINTS[kind]
        items = await client.get_all(await client.config_path(suffix), expanded=expanded, limit=limit)
        return ok(kind=kind, count=len(items), items=items)
    except Exception as exc:
        return fail(exc)


async def _get_object(kind: str, object_id: str) -> dict[str, Any]:
    try:
        client = await get_client()
        path = await client.config_path(f"{OBJECT_ENDPOINTS[kind]}/{object_id}")
        return ok(item=await client.get(path))
    except Exception as exc:
        return fail(exc)


async def _create_object(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        require_writes(get_settings())
        client = await get_client()
        path = await client.config_path(OBJECT_ENDPOINTS[kind])
        return ok(item=await client.post(path, payload))
    except Exception as exc:
        return fail(exc)


async def _update_object(kind: str, object_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        require_writes(get_settings())
        client = await get_client()
        path = await client.config_path(f"{OBJECT_ENDPOINTS[kind]}/{object_id}")
        body = dict(payload)
        body.setdefault("id", object_id)
        return ok(item=await client.put(path, body))
    except Exception as exc:
        return fail(exc)


async def _delete_object(kind: str, object_id: str) -> dict[str, Any]:
    try:
        require_writes(get_settings())
        client = await get_client()
        path = await client.config_path(f"{OBJECT_ENDPOINTS[kind]}/{object_id}")
        return ok(result=await client.delete(path))
    except Exception as exc:
        return fail(exc)


# ---------- Hosts ----------


@mcp.tool
async def list_hosts(expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    """List FMC host objects."""
    return await _list_objects("hosts", expanded=expanded, limit=limit)


@mcp.tool
async def get_host(object_id: str) -> dict[str, Any]:
    """Get a host object by ID."""
    return await _get_object("hosts", object_id)


@mcp.tool
async def create_host(
    name: str,
    value: str,
    description: str | None = None,
    overridable: bool = False,
) -> dict[str, Any]:
    """Create a host object. Requires FMC_ALLOW_WRITES=true."""
    payload = _clean(
        {"name": name, "type": "Host", "value": value, "description": description, "overridable": overridable}
    )
    return await _create_object("hosts", payload)


@mcp.tool
async def update_host(
    object_id: str,
    name: str,
    value: str,
    description: str | None = None,
    overridable: bool = False,
) -> dict[str, Any]:
    """Update a host object. Requires FMC_ALLOW_WRITES=true. FMC typically expects id, name, type, and value."""
    payload = _clean(
        {
            "id": object_id,
            "name": name,
            "type": "Host",
            "value": value,
            "description": description,
            "overridable": overridable,
        }
    )
    return await _update_object("hosts", object_id, payload)


@mcp.tool
async def delete_host(object_id: str) -> dict[str, Any]:
    """Delete a host object by ID. Requires FMC_ALLOW_WRITES=true."""
    return await _delete_object("hosts", object_id)


# ---------- Networks ----------


@mcp.tool
async def list_networks(expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    """List FMC network objects."""
    return await _list_objects("networks", expanded=expanded, limit=limit)


@mcp.tool
async def get_network(object_id: str) -> dict[str, Any]:
    """Get a network object by ID."""
    return await _get_object("networks", object_id)


@mcp.tool
async def create_network(
    name: str,
    value: str,
    description: str | None = None,
    overridable: bool = False,
) -> dict[str, Any]:
    """Create a network object (CIDR). Requires FMC_ALLOW_WRITES=true."""
    payload = _clean(
        {"name": name, "type": "Network", "value": value, "description": description, "overridable": overridable}
    )
    return await _create_object("networks", payload)


@mcp.tool
async def update_network(
    object_id: str,
    name: str,
    value: str,
    description: str | None = None,
    overridable: bool = False,
) -> dict[str, Any]:
    """Update a network object. Requires FMC_ALLOW_WRITES=true."""
    payload = _clean(
        {
            "id": object_id,
            "name": name,
            "type": "Network",
            "value": value,
            "description": description,
            "overridable": overridable,
        }
    )
    return await _update_object("networks", object_id, payload)


@mcp.tool
async def delete_network(object_id: str) -> dict[str, Any]:
    """Delete a network object by ID. Requires FMC_ALLOW_WRITES=true."""
    return await _delete_object("networks", object_id)


# ---------- Port / service objects ----------


@mcp.tool
async def list_port_objects(expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    """List FMC protocol/port (service) objects."""
    return await _list_objects("ports", expanded=expanded, limit=limit)


@mcp.tool
async def get_port_object(object_id: str) -> dict[str, Any]:
    """Get a protocol/port object by ID."""
    return await _get_object("ports", object_id)


@mcp.tool
async def create_port_object(
    name: str,
    protocol: str,
    port: str | None = None,
    description: str | None = None,
    overridable: bool = False,
) -> dict[str, Any]:
    """Create a protocol/port object. protocol is typically TCP or UDP. port can be '443' or '1024-2048'. Requires FMC_ALLOW_WRITES=true."""
    payload = _clean(
        {
            "name": name,
            "type": "ProtocolPortObject",
            "protocol": protocol.upper(),
            "port": port,
            "description": description,
            "overridable": overridable,
        }
    )
    return await _create_object("ports", payload)


@mcp.tool
async def update_port_object(
    object_id: str,
    name: str,
    protocol: str,
    port: str | None = None,
    description: str | None = None,
    overridable: bool = False,
) -> dict[str, Any]:
    """Update a protocol/port object. Requires FMC_ALLOW_WRITES=true."""
    payload = _clean(
        {
            "id": object_id,
            "name": name,
            "type": "ProtocolPortObject",
            "protocol": protocol.upper(),
            "port": port,
            "description": description,
            "overridable": overridable,
        }
    )
    return await _update_object("ports", object_id, payload)


@mcp.tool
async def delete_port_object(object_id: str) -> dict[str, Any]:
    """Delete a protocol/port object by ID. Requires FMC_ALLOW_WRITES=true."""
    return await _delete_object("ports", object_id)


# ---------- Devices / assignments ----------


@mcp.tool
async def list_devices(expanded: bool = True, limit: int = 1000) -> dict[str, Any]:
    """List FMC managed device records (FTD, etc.)."""
    try:
        client = await get_client()
        items = await client.get_all(await client.config_path("/devices/devicerecords"), expanded=expanded, limit=limit)
        return ok(count=len(items), items=items)
    except Exception as exc:
        return fail(exc)


@mcp.tool
async def list_policy_assignments(expanded: bool = True, limit: int = 1000) -> dict[str, Any]:
    """List policy assignments (which policies are assigned to which devices/device groups/templates)."""
    try:
        client = await get_client()
        items = await client.get_all(await client.config_path("/assignment/policyassignments"), expanded=expanded, limit=limit)
        return ok(count=len(items), items=items)
    except Exception as exc:
        return fail(exc)


# ---------- Access policies ----------


@mcp.tool
async def list_access_policies(expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    """List FMC access control policies."""
    try:
        client = await get_client()
        items = await client.get_all(await client.config_path("/policy/accesspolicies"), expanded=expanded, limit=limit)
        return ok(count=len(items), items=items)
    except Exception as exc:
        return fail(exc)


@mcp.tool
async def get_access_policy(policy_id: str) -> dict[str, Any]:
    """Get an access control policy by ID."""
    try:
        client = await get_client()
        return ok(item=await client.get(await client.config_path(f"/policy/accesspolicies/{policy_id}")))
    except Exception as exc:
        return fail(exc)


# ---------- Access rules ----------


async def _rules_path(policy_id: str, rule_id: str | None = None) -> str:
    client = await get_client()
    suffix = f"/policy/accesspolicies/{policy_id}/accessrules"
    if rule_id:
        suffix += f"/{rule_id}"
    return await client.config_path(suffix)


@mcp.tool
async def list_access_rules(
    policy_id: str,
    expanded: bool = False,
    limit: int = 100,
    offset: int = 0,
    name_contains: str | None = None,
    action: str | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """List access rules in an access control policy (token-friendly defaults).

    Args:
        expanded: Include full rule details (larger). Default false for compact output.
        limit/offset: Pagination over filtered results (default limit 100).
        name_contains: Case-insensitive substring filter on rule name.
        action: Filter by action (e.g. ALLOW, BLOCK).
        enabled: Filter by enabled state.
    """
    try:
        client = await get_client()
        # fetch enough for filtering; use API paging caps
        items = await client.get_all(await _rules_path(policy_id), expanded=expanded, limit=1000)
        if name_contains:
            nc = name_contains.lower()
            items = [r for r in items if nc in str(r.get("name") or "").lower()]
        if action:
            a = action.upper()
            items = [r for r in items if str(r.get("action") or "").upper() == a]
        if enabled is not None:
            items = [r for r in items if (r.get("enabled") is not False) == enabled]
        page = items[offset: offset + max(0, limit)]
        if not expanded:
            page = [{"id": r.get("id"), "name": r.get("name"), "action": r.get("action"), "enabled": r.get("enabled"), "index": (r.get("metadata") or {}).get("ruleIndex") if isinstance(r.get("metadata"), dict) else None} for r in page]
        return ok(policy_id=policy_id, total=len(items), returned=len(page), offset=offset, limit=limit, items=page)
    except Exception as exc:
        return fail(exc)


@mcp.tool
async def get_access_rule(policy_id: str, rule_id: str) -> dict[str, Any]:
    """Get a single access rule by policy ID and rule ID."""
    try:
        client = await get_client()
        return ok(item=await client.get(await _rules_path(policy_id, rule_id)))
    except Exception as exc:
        return fail(exc)


@mcp.tool
async def create_access_rule(
    policy_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Create an access rule in a policy. Requires FMC_ALLOW_WRITES=true.

    `payload` is sent to FMC's accessrules endpoint (you control the full rule structure).
    Common fields include: name, type='AccessRule', action (ALLOW/BLOCK/TRUST/MONITOR),
    enabled, sourceNetworks, destinationNetworks, destinationPorts, sourceZones,
    destinationZones, logBegin, logEnd, sendEventsToFMC, etc. Confirm exact schema in
    FMC API Explorer for your version.
    """
    try:
        require_writes(get_settings())
        client = await get_client()
        body = {"type": "AccessRule", **payload}
        body.setdefault("enabled", True)
        return ok(item=await client.post(await _rules_path(policy_id), body))
    except Exception as exc:
        return fail(exc)


@mcp.tool
async def update_access_rule(
    policy_id: str,
    rule_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update an access rule. Requires FMC_ALLOW_WRITES=true.

    FMC updates generally require a complete/valid rule payload including id and type.
    A safe pattern is: get_access_rule, modify fields, then pass the updated object as payload.
    """
    try:
        require_writes(get_settings())
        client = await get_client()
        body = {"type": "AccessRule", "id": rule_id, **payload}
        return ok(item=await client.put(await _rules_path(policy_id, rule_id), body))
    except Exception as exc:
        return fail(exc)


@mcp.tool
async def delete_access_rule(policy_id: str, rule_id: str) -> dict[str, Any]:
    """Delete an access rule. Requires FMC_ALLOW_WRITES=true."""
    try:
        require_writes(get_settings())
        client = await get_client()
        return ok(result=await client.delete(await _rules_path(policy_id, rule_id)))
    except Exception as exc:
        return fail(exc)


# ---------- Ticket / firewall opening investigation ----------


@mcp.tool
async def list_ranges(expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    """List FMC range objects (IPv4/IPv6 ranges)."""
    return await _list_objects("ranges", expanded=expanded, limit=limit)


@mcp.tool
async def get_range(object_id: str) -> dict[str, Any]:
    """Get a range object by ID."""
    return await _get_object("ranges", object_id)


@mcp.tool
async def list_fqdns(expanded: bool = False, limit: int = 1000) -> dict[str, Any]:
    """List FMC FQDN objects."""
    return await _list_objects("fqdns", expanded=expanded, limit=limit)


@mcp.tool
async def get_fqdn(object_id: str) -> dict[str, Any]:
    """Get an FQDN object by ID."""
    return await _get_object("fqdns", object_id)


@mcp.tool
async def investigate_firewall_opening(
    source: str,
    destination: str,
    protocol: str | None = None,
    port: Any = None,
    policy_id: str | None = None,
    include_disabled: bool = False,
    max_policies: int = 25,
    max_rules_per_policy: int = 2000,
    max_results: int = 25,
    include_evidence: bool = False,
    detail_level: str = "compact",
) -> dict[str, Any]:
    """Investigate a firewall-opening ticket against FMC access policies (read-only, best effort). Token-friendly by default.

    Use for human tickets like "allow source X to destination Y on TCP/443".
    Endpoints: IP, CIDR/subnet, IP range (a-b), or FQDN/hostname.

    Args:
        policy_id: Recommended. If omitted, scans policies (up to max_policies) — can be slow/noisy.
        max_results: Max matching/possible rules returned (default 25).
        include_evidence: Include reference-resolution evidence (increases tokens; default false).
        detail_level: `summary` (counts/first match only), `compact` (default), or `full`-ish with evidence if enabled.

    Returns parsed request, scanned counts, first_matching_rule, match_count, and (unless summary) matches. Verify in FMC.
    """
    try:
        client = await get_client()
        result = await analyze_opening(
            client,
            source=source,
            destination=destination,
            protocol=protocol,
            port=port,
            policy_id=policy_id,
            include_disabled=include_disabled,
            max_policies=max_policies,
            max_rules_per_policy=max_rules_per_policy,
            max_results=max_results,
            include_evidence=include_evidence,
            detail_level=detail_level,
        )
        return ok(**result)
    except (ConfigError, FMCAPIError, Exception) as exc:
        return fail(exc)


@mcp.tool
async def trace_packet_access_rules(
    policy_id: str,
    source: str,
    destination: str,
    protocol: str | None = None,
    port: Any = None,
    source_zone: str | None = None,
    destination_zone: str | None = None,
    rule_id: str | None = None,
    rule_name: str | None = None,
    include_disabled: bool = False,
    stop_on_first_match: bool = True,
    max_rules: int = 500,
    include_evidence: bool = False,
    detail_level: str = "compact",
    max_trace_steps: int = 50,
) -> dict[str, Any]:
    """Packet-tracker style simulation through access rules in an FMC ACP (read-only). Token-friendly defaults.

    ACCESS-RULE CRITERIA SIMULATION only (not full FTD/LINA datapath: no NAT/routing/interface/identity/app engine).
    Evaluates rules in order; reports MATCH/NO_MATCH/INDETERMINATE with reasons, stops at first match by default.

    Args:
        source_zone, destination_zone: Provide for zone-aware evaluation; otherwise zone-constrained rules may be indeterminate.
        rule_id/rule_name: Focus on a specific rule.
        include_evidence: Include reference evidence (increases tokens; default false).
        detail_level: `summary` (minimal), `compact` (default), or richer checks.
        max_trace_steps: Max trace steps returned (default 50).

    Returns policy/defaultAction (if available), verdict, and trace.
    """
    try:
        client = await get_client()
        result = await trace_access_policy(
            client,
            policy_id=policy_id,
            source=source,
            destination=destination,
            protocol=protocol,
            port=port,
            source_zone=source_zone,
            destination_zone=destination_zone,
            rule_id=rule_id,
            rule_name=rule_name,
            include_disabled=include_disabled,
            stop_on_first_match=stop_on_first_match,
            max_rules=max_rules,
            include_evidence=include_evidence,
            detail_level=detail_level,
            max_trace_steps=max_trace_steps,
        )
        return ok(**result)
    except (ConfigError, FMCAPIError, Exception) as exc:
        return fail(exc)


@mcp.tool
async def audit_access_policy_inspection(
    policy_id: str | None = None,
    include_rules: bool = True,
    rule_detail_limit: int = 25,
    include_disabled_rules: bool = False,
    max_policies: int = 100,
    max_rules_per_policy: int = 5000,
    summary_only: bool = False,
    only_issues: bool = False,
) -> dict[str, Any]:
    """Audit ACP default action (implicit deny/block) and IPS/IDS (intrusion policy) on rules. Token-friendly options.

    Reports per ACP: defaultAction deny/block interpretation; rule intrusion policy presence + inspectionMode (DETECTION/PREVENTION-like).
    Args:
        summary_only: Counts only, omit per-rule lists (saves tokens).
        only_issues: Return only policies with issues (non-block default action or allow-like rules missing intrusion policy).
        rule_detail_limit: Max rule detail rows per policy when not summary_only (default 25).
        include_rules: Set false for a fast default-action-only audit across all ACPs.
    """
    try:
        client = await get_client()
        result = await audit_inspection(
            client,
            policy_id=policy_id,
            include_rules=include_rules,
            rule_detail_limit=rule_detail_limit,
            include_disabled_rules=include_disabled_rules,
            max_policies=max_policies,
            max_rules_per_policy=max_rules_per_policy,
            summary_only=summary_only,
            only_issues=only_issues,
        )
        return ok(**result)
    except (ConfigError, FMCAPIError, Exception) as exc:
        return fail(exc)


@mcp.tool
async def find_unused_access_rules(
    policy_id: str,
    device_id: str | None = None,
    include_hit_counts: bool = True,
    include_disabled: bool = True,
    max_rules: int = 5000,
    name_contains: str | None = None,
    name_regex: str | None = None,
    zero_hit_only: bool = False,
    disabled_only: bool = False,
    results_limit: int = 50,
    offset: int = 0,
    summary_only: bool = False,
) -> dict[str, Any]:
    """Find unused-candidate access rules (disabled and/or zero-hit). Read-only, token-friendly filters.

    Hit counts via FMC operational `hitcounts` (requires device; auto-resolved from policy assignment when unique).
    Args:
        name_contains/name_regex: Filter rule names.
        zero_hit_only/disabled_only: Narrow to specific candidate types.
        results_limit/offset: Paginate candidates (default 50).
        summary_only: Counts/metadata only, no candidate list.
    Caveats: zero hits != always unused; not shadow analysis.
    """
    try:
        client = await get_client()
        result = await _find_unused_access_rules(
            client,
            policy_id=policy_id,
            device_id=device_id,
            include_hit_counts=include_hit_counts,
            include_disabled=include_disabled,
            max_rules=max_rules,
            name_contains=name_contains,
            name_regex=name_regex,
            zero_hit_only=zero_hit_only,
            disabled_only=disabled_only,
            results_limit=results_limit,
            offset=offset,
            summary_only=summary_only,
        )
        return ok(**result)
    except (ConfigError, FMCAPIError, Exception) as exc:
        return fail(exc)


@mcp.tool
async def find_unused_objects(
    object_types: list[str] | None = None,
    policy_id: str | None = None,
    max_policies: int = 50,
    max_rules_per_policy: int = 5000,
    max_objects_per_type: int = 5000,
    include_used: bool = False,
    name_contains: str | None = None,
    name_regex: str | None = None,
    results_limit: int = 50,
    offset: int = 0,
    summary_only: bool = False,
) -> dict[str, Any]:
    """Find objects not directly referenced by scanned access rules (best-effort). Read-only, token-friendly filters.

    Args:
        object_types: e.g. ["hosts","networks","network_groups","ports","port_groups","security_zones"] (defaults to common types).
        policy_id: Limit rule scan to one ACP (recommended). Omitted scans ACPs up to max_policies.
        name_contains/name_regex: Filter reported object names.
        results_limit/offset: Paginate per-type unused lists (default 50) — avoids huge token output.
        summary_only: Counts only, no object lists.
        include_used: Also report used/reference counts (larger).

    Caveats: direct access-rule refs only; objects may be used by NAT/prefilter/VPN/platform/non-scanned policies or transitive cases. Verify before deleting.
    """
    try:
        client = await get_client()
        result = await _find_unused_objects(
            client,
            object_types=object_types,
            policy_id=policy_id,
            max_policies=max_policies,
            max_rules_per_policy=max_rules_per_policy,
            max_objects_per_type=max_objects_per_type,
            include_used=include_used,
            name_contains=name_contains,
            name_regex=name_regex,
            results_limit=results_limit,
            offset=offset,
            summary_only=summary_only,
        )
        return ok(**result)
    except (ConfigError, FMCAPIError, Exception) as exc:
        return fail(exc)


# ---------- Entrypoint ----------



def main() -> None:
    s = get_settings()
    transport = s.mcp_transport
    if transport == "stdio":
        logger.info("Starting Cisco FMC MCP server (stdio)")
        mcp.run(transport="stdio")
    else:
        # FastMCP HTTP transport serves Streamable HTTP MCP at /mcp.
        logger.info(
            "Starting Cisco FMC MCP server (HTTP/Streamable) on %s:%s",
            s.mcp_host,
            s.mcp_port,
        )
        try:
            mcp.run(transport="http", host=s.mcp_host, port=s.mcp_port)
        except TypeError:
            # Compatibility fallback for FastMCP variants using transport="streamable-http".
            mcp.run(transport="streamable-http", host=s.mcp_host, port=s.mcp_port)


if __name__ == "__main__":
    main()

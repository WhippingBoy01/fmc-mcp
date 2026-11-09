"""Helpers for analyzing firewall-opening tickets against FMC access policies.

This is a best-effort analysis for common cases (IP/CIDR/range/FQDN endpoints and
TCP/UDP ports). FMC access control has additional dimensions not fully modeled here
(zones, applications, users, SGTs, dynamic attributes, URL categories, time ranges,
prefilter/cluster behavior, rule sectioning edge cases). Treat results as an
investigation aid and verify in FMC.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from .fmc_client import FMCClient


def _name_matches(name: str | None, name_contains: str | None = None, name_regex: str | None = None) -> bool:
    n = str(name or "")
    if name_contains and name_contains.lower() not in n.lower():
        return False
    if name_regex:
        try:
            if not re.search(name_regex, n, re.IGNORECASE):
                return False
        except re.error:
            # invalid regex: treat as literal contains fallback
            if name_regex.lower() not in n.lower():
                return False
    return True


@dataclass
class ParsedEndpoint:
    raw: str
    kind: str  # ipv4, ipv6, network, range, fqdn, any, unknown
    value: str
    start: int | None = None
    end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"raw": self.raw, "kind": self.kind, "value": self.value}


def parse_endpoint(value: str | None) -> ParsedEndpoint:
    raw = (value or "").strip()
    if not raw or raw.lower() in {"any", "any-ipv4", "any-ipv6"}:
        return ParsedEndpoint(raw=raw or "any", kind="any", value="any")
    # Range form: 10.0.0.1-10.0.0.10
    if "-" in raw and "/" not in raw:
        left, right = raw.split("-", 1)
        try:
            a = ipaddress.ip_address(left.strip())
            b = ipaddress.ip_address(right.strip())
            if a.version == b.version:
                return ParsedEndpoint(
                    raw=raw,
                    kind="range",
                    value=f"{a}-{b}",
                    start=int(a),
                    end=int(b),
                )
        except ValueError:
            pass
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return ParsedEndpoint(
                raw=raw,
                kind="network",
                value=str(net),
                start=int(net.network_address),
                end=int(net.broadcast_address),
            )
        ip = ipaddress.ip_address(raw)
        return ParsedEndpoint(
            raw=raw,
            kind=f"ipv{ip.version}",
            value=str(ip),
            start=int(ip),
            end=int(ip),
        )
    except ValueError:
        # FQDN / hostname-like token (best-effort)
        if re.match(r"^[A-Za-z0-9*._-]+$", raw):
            return ParsedEndpoint(raw=raw, kind="fqdn", value=raw.lower())
    return ParsedEndpoint(raw=raw, kind="unknown", value=raw)


def endpoint_overlaps(request: ParsedEndpoint, candidate_value: str | None, candidate_type: str | None = None) -> tuple[bool, str]:
    if request.kind == "any":
        return True, "request is any"
    cand = parse_endpoint(candidate_value)
    if request.kind == "fqdn" or cand.kind == "fqdn":
        rv = request.value.lower().rstrip(".")
        cv = (candidate_value or "").lower().rstrip(".")
        if rv and cv and (rv == cv or cv == "*" or rv.replace("*", "") in cv or cv.replace("*", "") in rv):
            return True, "fqdn match"
        return False, "fqdn does not match"
    if cand.kind == "unknown":
        return False, "candidate value not parseable as IP/range/network"
    if request.start is None or cand.start is None or request.end is None or cand.end is None:
        return False, "missing numeric bounds"
    # overlap / containment in either direction (useful for ticket-vs-object comparison)
    overlaps = request.start <= cand.end and cand.start <= request.end
    if not overlaps:
        return False, "no overlap"
    if cand.start <= request.start and request.end <= cand.end:
        return True, "candidate covers request"
    if request.start <= cand.start and cand.end <= request.end:
        return True, "request covers candidate"
    return True, "partial overlap"


def parse_port(value: Any) -> tuple[int | None, int | None, str]:
    if value is None:
        return None, None, "any"
    s = str(value).strip().upper()
    if not s or s == "ANY":
        return None, None, "any"
    if "-" in s:
        a, b = s.split("-", 1)
        try:
            return int(a), int(b), s
        except ValueError:
            return None, None, s
    try:
        p = int(s)
        return p, p, s
    except ValueError:
        return None, None, s


def port_matches(request_port: Any, request_protocol: str | None, obj: dict[str, Any]) -> tuple[bool | None, str]:
    """Return (matches?, reason). None means indeterminate."""
    rp = (request_protocol or "any").strip().upper()
    if rp in {"", "ANY", "IP"}:
        rp = "ANY"
    oproto = str(obj.get("protocol") or obj.get("Protocol") or "ANY").upper()
    rstart, rend, rdisp = parse_port(request_port)
    ostart, oend, odisp = parse_port(obj.get("port") or obj.get("Port"))
    if rp != "ANY" and oproto != "ANY" and rp != oproto:
        return False, f"protocol mismatch ({oproto} vs {rp})"
    if rstart is None:  # request any port
        return True, f"request any port; object {oproto}/{odisp}"
    if ostart is None:
        return True, f"object any port ({oproto})"
    if ostart <= rend and rstart <= oend:  # type: ignore[operator]
        return True, f"port overlap {oproto}/{odisp} matches requested {rp}/{rdisp}"
    return False, f"port mismatch {oproto}/{odisp} vs requested {rp}/{rdisp}"


def _iter_refs(container: dict[str, Any] | None) -> Iterable[dict[str, Any]]:
    if not container:
        return []
    refs: list[dict[str, Any]] = []
    for key in ("objects", "literals"):
        vals = container.get(key)
        if isinstance(vals, list):
            refs.extend([v for v in vals if isinstance(v, dict)])
    return refs


async def load_object_index(client: "FMCClient") -> dict[str, dict[str, dict[str, Any]]]:
    """Load common network/service objects into indexes for analysis."""
    endpoints: list[tuple[str, str]] = [
        ("hosts", "/object/hosts"),
        ("networks", "/object/networks"),
        ("ranges", "/object/ranges"),
        ("fqdns", "/object/fqdns"),
        ("network_groups", "/object/networkgroups"),
    ]
    services: list[tuple[str, str]] = [
        ("ports", "/object/protocolportobjects"),
        ("port_groups", "/object/portobjectgroups"),
        ("icmpv4", "/object/icmpv4objects"),
    ]
    by_id: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    for kind, suffix in endpoints + services:
        try:
            items = await client.get_all(await client.config_path(suffix), expanded=True)
        except Exception:
            items = []
        for item in items:
            item = dict(item)
            item["_kind"] = kind
            if item.get("id"):
                by_id[str(item["id"])] = item
            if item.get("name"):
                by_name[str(item["name"]).lower()] = item
    return {"by_id": by_id, "by_name": by_name}


def _ref_matches_endpoint(ref: dict[str, Any], request: ParsedEndpoint, index: dict[str, dict[str, dict[str, Any]]], depth: int = 0) -> tuple[bool, str, dict[str, Any] | None]:
    if depth > 4:
        return False, "max group depth reached", None
    # Literal network in rule
    if ref.get("value") and ref.get("type") in {None, "Host", "Network", "Range", "FQDN"}:
        ok, reason = endpoint_overlaps(request, str(ref.get("value")), str(ref.get("type")))
        return ok, f"literal {ref.get('type') or 'value'}: {reason}", ref
    obj = None
    if ref.get("id") and str(ref["id"]) in index["by_id"]:
        obj = index["by_id"][str(ref["id"])]
    elif ref.get("name") and str(ref["name"]).lower() in index["by_name"]:
        obj = index["by_name"][str(ref["name"]).lower()]
    if not obj:
        # Unknown reference; be conservative.
        return False, f"unresolved object reference ({ref.get('name') or ref.get('id')})", ref
    kind = obj.get("_kind") or obj.get("type")
    if kind in {"network_groups", "NetworkGroup"}:
        members = list(_iter_refs({"objects": obj.get("objects"), "literals": obj.get("literals")}))
        for member in members:
            ok, reason, detail = _ref_matches_endpoint(member, request, index, depth + 1)
            if ok:
                return True, f"group {obj.get('name')} member match: {reason}", detail or obj
        return False, f"group {obj.get('name')} has no matching member (checked {len(members)} members)", obj
    if obj.get("value"):
        ok, reason = endpoint_overlaps(request, str(obj.get("value")), str(obj.get("type") or kind))
        return ok, f"{kind} {obj.get('name')}: {reason}", obj
    return False, f"object {obj.get('name')} has no comparable value", obj


def _port_ref_matches(ref: dict[str, Any], protocol: str | None, port: Any, index: dict[str, dict[str, dict[str, Any]]], depth: int = 0) -> tuple[bool | None, str, dict[str, Any] | None]:
    if depth > 4:
        return None, "max group depth reached", None
    # literal port in rule
    if ref.get("protocol") or ref.get("port"):
        ok, reason = port_matches(port, protocol, ref)
        return ok, f"literal: {reason}", ref
    obj = None
    if ref.get("id") and str(ref["id"]) in index["by_id"]:
        obj = index["by_id"][str(ref["id"])]
    elif ref.get("name") and str(ref["name"]).lower() in index["by_name"]:
        obj = index["by_name"][str(ref["name"]).lower()]
    if not obj:
        return None, f"unresolved port reference ({ref.get('name') or ref.get('id')})", ref
    kind = obj.get("_kind") or obj.get("type")
    if kind in {"port_groups", "PortObjectGroup"}:
        members = list(_iter_refs({"objects": obj.get("objects"), "literals": obj.get("literals")}))
        if not members:
            return None, f"port group {obj.get('name')} has no expanded members loaded", obj
        saw_unknown = False
        for member in members:
            ok, reason, detail = _port_ref_matches(member, protocol, port, index, depth + 1)
            if ok is True:
                return True, f"port group {obj.get('name')} member match: {reason}", detail or obj
            if ok is None:
                saw_unknown = True
        return (None, f"port group {obj.get('name')} member match indeterminate", obj) if saw_unknown else (False, f"port group {obj.get('name')} no matching members", obj)
    ok, reason = port_matches(port, protocol, obj)
    return ok, f"{kind} {obj.get('name')}: {reason}", obj


def _network_container_matches(container: dict[str, Any] | None, request: ParsedEndpoint, index: dict[str, dict[str, dict[str, Any]]]) -> tuple[bool | None, list[dict[str, Any]], str]:
    if not container:
        return True, [], "any (field absent)"
    refs = list(_iter_refs(container))
    if not refs:
        return True, [], "any (no objects/literals)"
    evidence: list[dict[str, Any]] = []
    saw_unknown = False
    for ref in refs:
        ok, reason, detail = _ref_matches_endpoint(ref, request, index)
        evidence.append({"ref": {k: ref.get(k) for k in ("id", "name", "type", "value") if ref.get(k) is not None}, "matches": ok, "reason": reason, "resolved": {k: (detail or {}).get(k) for k in ("id", "name", "type", "value", "_kind") if (detail or {}).get(k) is not None}})
        if ok:
            return True, evidence, reason
    # unresolved refs make this indeterminate rather than a clean miss
    if any("unresolved" in e["reason"] or "no comparable value" in e["reason"] for e in evidence):
        saw_unknown = True
    return (None, evidence, "indeterminate (unresolved references)") if saw_unknown else (False, evidence, "no matching source/destination references")


def _port_container_matches(container: dict[str, Any] | None, protocol: str | None, port: Any, index: dict[str, dict[str, dict[str, Any]]]) -> tuple[bool | None, list[dict[str, Any]], str]:
    if protocol and protocol.upper() == "ICMP":
        return True, [], "ICMP requested; port match not applicable (best-effort)"
    if not container:
        return True, [], "any (field absent)"
    refs = list(_iter_refs(container))
    if not refs:
        return True, [], "any (no objects/literals)"
    evidence = []
    saw_unknown = False
    for ref in refs:
        ok, reason, detail = _port_ref_matches(ref, protocol, port, index)
        evidence.append({"ref": {k: ref.get(k) for k in ("id", "name", "type", "protocol", "port") if ref.get(k) is not None}, "matches": ok, "reason": reason, "resolved": {k: (detail or {}).get(k) for k in ("id", "name", "type", "protocol", "port", "_kind") if (detail or {}).get(k) is not None}})
        if ok is True:
            return True, evidence, reason
        if ok is None:
            saw_unknown = True
    return (None, evidence, "indeterminate") if saw_unknown else (False, evidence, "no matching port references")


def _zone_container_matches(container: dict[str, Any] | None, zone: str | None) -> tuple[bool | None, list[dict[str, Any]], str]:
    """Evaluate zone criteria. If packet zone is unknown, result is indeterminate when rule constrains zones."""
    if not container:
        return True, [], "any (field absent)"
    refs = list(_iter_refs(container))
    if not refs:
        return True, [], "any (no objects/literals)"
    names = [str(r.get("name") or r.get("id") or "") for r in refs]
    evidence = [{"ref": {k: r.get(k) for k in ("id", "name", "type") if r.get(k) is not None}} for r in refs]
    if zone is None or not str(zone).strip():
        return None, evidence, f"rule constrains zones {names}; packet zone not provided"
    z = str(zone).strip().lower()
    for n in names:
        if n.lower() == z:
            for e in evidence:
                e["matches"] = str(e.get("ref", {}).get("name", "")).lower() == z
                e["reason"] = "zone match" if e["matches"] else "zone differs"
            return True, evidence, f"zone matched {zone}"
    for e in evidence:
        e["matches"] = False
        e["reason"] = "zone differs"
    return False, evidence, f"packet zone {zone!r} not in rule zones {names}"


async def analyze_opening(
    client: "FMCClient",
    *,
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
    src = parse_endpoint(source)
    dst = parse_endpoint(destination)
    index = await load_object_index(client)

    policies: list[dict[str, Any]]
    if policy_id:
        policy = await client.get(await client.config_path(f"/policy/accesspolicies/{policy_id}"))
        policies = [policy] if policy else []
    else:
        policies = await client.get_all(await client.config_path("/policy/accesspolicies"))

    all_matches: list[dict[str, Any]] = []
    first_match: dict[str, Any] | None = None
    scanned = 0
    for pol in policies[:max_policies]:
        pid = pol.get("id")
        if not pid:
            continue
        try:
            rules = await client.get_all(
                await client.config_path(f"/policy/accesspolicies/{pid}/accessrules"),
                expanded=True,
                max_items=max_rules_per_policy,
            )
        except Exception as e:
            all_matches.append({"policy": {"id": pid, "name": pol.get("name")}, "error": str(e)})
            continue
        for rule in rules:
            scanned += 1
            if not include_disabled and rule.get("enabled") is False:
                continue
            src_ok, src_ev, src_reason = _network_container_matches(rule.get("sourceNetworks"), src, index)
            dst_ok, dst_ev, dst_reason = _network_container_matches(rule.get("destinationNetworks"), dst, index)
            prt_ok, prt_ev, prt_reason = _port_container_matches(rule.get("destinationPorts"), protocol, port, index)
            # source ports usually any; not evaluated unless present and strictness desired.
            verdicts = [src_ok, dst_ok, prt_ok]
            if all(v is True for v in verdicts):
                status = "match"
            elif any(v is False for v in verdicts):
                status = "no-match"
            else:
                status = "possible"
            if status == "no-match":
                continue
            entry = {
                "policy": {"id": pid, "name": pol.get("name")},
                "rule": {
                    "id": rule.get("id"),
                    "name": rule.get("name"),
                    "action": rule.get("action"),
                    "enabled": rule.get("enabled"),
                    **({"index": rule.get("metadata", {}).get("ruleIndex")} if detail_level != "summary" and isinstance(rule.get("metadata"), dict) else {}),
                },
                "status": status,
                "reasons": {"source": src_reason, "destination": dst_reason, "port": prt_reason},
            }
            if include_evidence and detail_level != "summary":
                entry["evidence"] = {"source": src_ev[:5], "destination": dst_ev[:5], "port": prt_ev[:5]}
            all_matches.append(entry)
            if first_match is None and status == "match" and rule.get("enabled") is not False:
                first_match = entry

    lim = max(0, min(max_results, 500))
    result = {
        "request": {
            "source": src.to_dict(),
            "destination": dst.to_dict(),
            "protocol": protocol,
            "port": port,
        },
        "policies_scanned": min(len(policies), max_policies),
        "rules_scanned": scanned,
        "first_matching_rule": first_match,
        "match_count": len(all_matches),
        "returned": min(len(all_matches), lim),
        "filters": {"max_results": lim, "include_evidence": include_evidence, "detail_level": detail_level},
        "caveats": [
            "Best-effort analysis. Verify in FMC GUI/API Explorer and consider zones, applications, users, SGTs, dynamic attributes, URL categories, time ranges, prefilter, and deployment state.",
            "Nested object groups are resolved only from loaded/expanded object members; unresolved references are reported as possible/indeterminate.",
            "First-match is approximated by returned rule order; FMC rule evaluation depends on policy structure.",
        ],
    }
    if detail_level != "summary":
        result["matches"] = all_matches[:lim]
    return result


async def trace_access_policy(
    client: "FMCClient",
    *,
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
    """Simulate packet evaluation through access rules in order (rule-criteria trace).

    This is NOT a full FTD/LINA datapath packet-tracer (no NAT, routing, interface
    resolution, or device-side engine). It evaluates access-rule criteria only.
    """
    src = parse_endpoint(source)
    dst = parse_endpoint(destination)
    index = await load_object_index(client)
    policy = await client.get(await client.config_path(f"/policy/accesspolicies/{policy_id}"))
    rules = await client.get_all(
        await client.config_path(f"/policy/accesspolicies/{policy_id}/accessrules"),
        expanded=True,
        max_items=max_rules,
    )

    trace: list[dict[str, Any]] = []
    hit: dict[str, Any] | None = None
    focus = (str(rule_id).lower() if rule_id else None, str(rule_name).lower() if rule_name else None)
    for pos, rule in enumerate(rules, 1):
        rid = str(rule.get("id") or "")
        rname = str(rule.get("name") or "")
        if focus[0] and rid.lower() != focus[0]:
            # if focusing by name too, allow either; if only id specified, skip others unless asked to include context
            if not (focus[1] and rname.lower() == focus[1]):
                pass
        is_focus = (focus[0] and rid.lower() == focus[0]) or (focus[1] and rname.lower() == focus[1])
        if (focus[0] or focus[1]) and not is_focus and len(trace) >= 200:
            # keep scanning only until focus found? still need order context; limit non-focus detail
            pass
        if not include_disabled and rule.get("enabled") is False:
            if is_focus or not (focus[0] or focus[1]):
                trace.append({"position": pos, "rule": {"id": rid, "name": rname, "action": rule.get("action"), "enabled": False}, "result": "SKIPPED_DISABLED"})
            continue

        src_ok, src_ev, src_reason = _network_container_matches(rule.get("sourceNetworks"), src, index)
        dst_ok, dst_ev, dst_reason = _network_container_matches(rule.get("destinationNetworks"), dst, index)
        prt_ok, prt_ev, prt_reason = _port_container_matches(rule.get("destinationPorts"), protocol, port, index)
        sz_ok, sz_ev, sz_reason = _zone_container_matches(rule.get("sourceZones"), source_zone)
        dz_ok, dz_ev, dz_reason = _zone_container_matches(rule.get("destinationZones"), destination_zone)
        verdicts = [src_ok, dst_ok, prt_ok, sz_ok, dz_ok]
        if all(v is True for v in verdicts):
            result = "MATCH"
        elif any(v is False for v in verdicts):
            result = "NO_MATCH"
        else:
            result = "INDETERMINATE"

        step = {
            "position": pos,
            "rule": {"id": rid, "name": rname, "action": rule.get("action"), "enabled": rule.get("enabled")},
            "result": result,
            "checks": {
                "source": {"result": src_ok, "reason": src_reason},
                "destination": {"result": dst_ok, "reason": dst_reason},
                "destination_port": {"result": prt_ok, "reason": prt_reason},
                "source_zone": {"result": sz_ok, "reason": sz_reason},
                "destination_zone": {"result": dz_ok, "reason": dz_reason},
            },
        }
        # Include evidence only when requested or focused, to save tokens.
        if include_evidence and detail_level != "summary" and (is_focus or result in ("MATCH", "INDETERMINATE")):
            step["evidence"] = {"source": src_ev[:4], "destination": dst_ev[:4], "destination_port": prt_ev[:4], "source_zone": sz_ev[:4], "destination_zone": dz_ev[:4]}
        if detail_level == "summary":
            step = {"position": pos, "rule": {"id": rid, "name": rname, "action": rule.get("action")}, "result": result}

        should_record = (not focus[0] and not focus[1]) or is_focus or result == "MATCH" or (pos <= 15)
        if should_record and len(trace) < max(1, max_trace_steps):
            trace.append(step)

        if result == "MATCH" and hit is None:
            hit = {"position": pos, "rule": {"id": rid, "name": rname, "action": rule.get("action"), "enabled": rule.get("enabled")}, "action": rule.get("action")}
            if stop_on_first_match and not (focus[0] or focus[1]):
                break
            if is_focus:
                break

    verdict = {"matched": hit is not None, "hit": hit, "final_action": (hit or {}).get("action"), "note": "No matching access rule found by criteria trace; actual result depends on policy default action and non-ACP factors." if not hit else "First matching rule by simulated criteria/order."}
    return {
        "mode": "access-rule-criteria-simulation",
        "policy": {"id": policy.get("id"), "name": policy.get("name"), "defaultAction": (policy.get("defaultAction") or {}).get("action") if isinstance(policy.get("defaultAction"), dict) else policy.get("defaultAction")},
        "packet": {"source": src.to_dict(), "destination": dst.to_dict(), "protocol": protocol, "port": port, "source_zone": source_zone, "destination_zone": destination_zone},
        "rules_scanned": len(rules),
        "trace_count": len(trace),
        "filters": {"detail_level": detail_level, "include_evidence": include_evidence, "max_trace_steps": max_trace_steps},
        "trace": trace,
        "verdict": verdict,
        "caveats": [
            "Simulates access-rule criteria only (not FTD/LINA datapath). Does not model NAT, routing, interface selection, prefilter in full, intrusion/file/malware outcomes, identity/SGT/dynamic attributes, URL/app filtering internals, or platform-specific behavior.",
            "Zone checks are only evaluated when source_zone/destination_zone are provided; otherwise constrained zones are indeterminate.",
            "Verify on the managed FTD (CLI packet-tracer / FMC troubleshoot tools) for authoritative path analysis.",
        ],
    }


def _default_action_summary(default_action: Any) -> dict[str, Any]:
    if not isinstance(default_action, dict):
        return {"raw": default_action, "action": default_action, "is_implicit_deny_or_block": None}
    action = str(default_action.get("action") or "").upper()
    # FMC default actions vary by version/config (BLOCK, TRUST, NETWORK_DISCOVERY, PERMIT, etc.).
    is_deny = action in {"BLOCK", "BLOCK_ALL", "DENY"}
    intrusion = default_action.get("intrusionPolicy") or default_action.get("ipsPolicy")
    return {
        "action": default_action.get("action"),
        "type": default_action.get("type"),
        "id": default_action.get("id"),
        "is_implicit_deny_or_block": is_deny,
        "logBegin": default_action.get("logBegin"),
        "logEnd": default_action.get("logEnd"),
        "sendEventsToFMC": default_action.get("sendEventsToFMC"),
        "enableSyslog": default_action.get("enableSyslog"),
        "intrusionPolicy": {k: intrusion.get(k) for k in ("name", "id", "type", "inspectionMode")} if isinstance(intrusion, dict) else intrusion,
        "variableSet": ({k: default_action.get("variableSet", {}).get(k) for k in ("name", "id", "type")} if isinstance(default_action.get("variableSet"), dict) else default_action.get("variableSet")),
    }


def _rule_intrusion_summary(rule: dict[str, Any]) -> dict[str, Any]:
    ips = rule.get("ipsPolicy") or rule.get("intrusionPolicy")
    file_policy = rule.get("filePolicy")
    mode = ips.get("inspectionMode") if isinstance(ips, dict) else None
    mode_upper = str(mode).upper() if mode else None
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "action": rule.get("action"),
        "enabled": rule.get("enabled"),
        "has_intrusion_policy": bool(ips),
        "intrusionPolicy": {k: ips.get(k) for k in ("name", "id", "type", "inspectionMode")} if isinstance(ips, dict) else None,
        "inspectionMode": mode,
        "is_prevention_mode": mode_upper in {"PREVENTION", "PREVENT", "INLINE"} if mode_upper else None,
        "is_detection_mode": mode_upper in {"DETECTION", "DETECT", "PASSIVE", "IDS"} if mode_upper else None,
        "has_file_policy": bool(file_policy),
        "filePolicy": ({k: file_policy.get(k) for k in ("name", "id", "type")} if isinstance(file_policy, dict) else None),
        "variableSet": ({k: rule.get("variableSet", {}).get(k) for k in ("name", "id", "type")} if isinstance(rule.get("variableSet"), dict) else None),
    }


OBJECT_INVENTORY = {
    "hosts": "/object/hosts",
    "networks": "/object/networks",
    "ranges": "/object/ranges",
    "fqdns": "/object/fqdns",
    "network_groups": "/object/networkgroups",
    "ports": "/object/protocolportobjects",
    "port_groups": "/object/portobjectgroups",
    "icmpv4": "/object/icmpv4objects",
    "icmpv6": "/object/icmpv6objects",
    "urls": "/object/urls",
    "url_groups": "/object/urlgroups",
    "security_zones": "/object/securityzones",
    "sgts": "/object/securitygrouptags",
    "dynamic_objects": "/object/dynamicobjects",
}

RULE_REF_CONTAINERS = [
    "sourceNetworks", "destinationNetworks",
    "sourcePorts", "destinationPorts",
    "sourceZones", "destinationZones",
    "sourceDynamicObjects", "destinationDynamicObjects",
    "sourceSecurityGroupTags", "destinationSecurityGroupTags",
    "urls", "vlanTags", "applications",
]


def _collect_refs(value: Any, refs: dict[str, dict[str, Any]] | None = None, path: str = "") -> dict[str, dict[str, Any]]:
    if refs is None:
        refs = {}
    if isinstance(value, dict):
        # object/literal reference
        if value.get("id") or value.get("name"):
            rid = str(value.get("id") or "")
            rname = str(value.get("name") or "")
            key = rid or f"name::{rname}::{value.get('type','')}"
            if key and (rid or rname):
                refs.setdefault(key, {"id": value.get("id"), "name": value.get("name"), "type": value.get("type"), "paths": set()})
                refs[key]["paths"].add(path)
        for k in ("objects", "literals", "entries"):
            if k in value:
                _collect_refs(value[k], refs, f"{path}.{k}" if path else k)
        # don't recurse into every field blindly; containers handled above
    elif isinstance(value, list):
        for item in value:
            _collect_refs(item, refs, path)
    return refs


def collect_rule_references(rule: dict[str, Any]) -> dict[str, dict[str, Any]]:
    refs: dict[str, dict[str, Any]] = {}
    for c in RULE_REF_CONTAINERS:
        if c in rule:
            _collect_refs(rule.get(c), refs, c)
    # normalize path sets for JSON
    for v in refs.values():
        v["paths"] = sorted(v["paths"])
    return refs


async def _resolve_policy_devices(client: "FMCClient", policy_id: str) -> list[dict[str, Any]]:
    try:
        assignments = await client.get_all(await client.config_path("/assignment/policyassignments"), expanded=True)
    except Exception:
        return []
    devices = []
    for a in assignments:
        pol = a.get("policy") or {}
        if str(pol.get("id")) != str(policy_id) or str(pol.get("type")) != "AccessPolicy":
            continue
        for t in a.get("targets") or []:
            if t.get("type") in {"Device", "DeviceGroup"} and t.get("id"):
                devices.append({"id": t.get("id"), "name": t.get("name"), "type": t.get("type")})
    # dedupe
    seen=set(); out=[]
    for d in devices:
        if d["id"] in seen: continue
        seen.add(d["id"]); out.append(d)
    return out


async def find_unused_access_rules(
    client: "FMCClient",
    *,
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
    policy = await client.get(await client.config_path(f"/policy/accesspolicies/{policy_id}"))
    rules = await client.get_all(
        await client.config_path(f"/policy/accesspolicies/{policy_id}/accessrules"),
        expanded=True,
        max_items=max_rules,
    )
    hit_by_rule: dict[str, dict[str, Any]] = {}
    hit_meta: dict[str, Any] = {"requested": include_hit_counts, "available": False}
    if include_hit_counts:
        resolved_device = device_id
        devices = []
        if not resolved_device:
            devices = await _resolve_policy_devices(client, policy_id)
            real = [d for d in devices if d.get("type") == "Device"]
            if len(real) == 1:
                resolved_device = real[0]["id"]
            elif len(devices) == 1:
                resolved_device = devices[0]["id"]
            hit_meta["resolved_devices"] = devices
        hit_meta["device_id"] = resolved_device
        if resolved_device:
            try:
                base = f"{client.base_url}{await client.config_path(f'/policy/accesspolicies/{policy_id}/operational/hitcounts')}"
                filt = f"deviceId:{resolved_device};fetchZeroHitCount:true"
                off = 0
                items = []
                while True:
                    r = await client._client.get(base, headers=client._auth_headers(), params={"filter": filt, "expanded": "true", "limit": 500, "offset": off})
                    if r.status_code >= 400:
                        hit_meta["error"] = {"status_code": r.status_code, "body": r.text[:500]}
                        break
                    data = r.json() or {}
                    page = data.get("items") or []
                    items.extend(page)
                    paging = data.get("paging") or {}
                    count = paging.get("count")
                    if isinstance(count, int) and off + 500 >= count: break
                    if not page or len(page) < 500: break
                    off += 500
                hit_meta["available"] = not hit_meta.get("error")
                hit_meta["count"] = len(items)
                for it in items:
                    rule = it.get("rule") or {}
                    rid = str(rule.get("id") or "")
                    if rid:
                        hit_by_rule[rid] = {
                            "hitCount": it.get("hitCount"),
                            "lastHitTimeStamp": it.get("lastHitTimeStamp"),
                            "lastDeployedTimeStamp": it.get("lastDeployedTimeStamp"),
                            "ruleIndex": (it.get("metadata") or {}).get("ruleIndex"),
                        }
            except Exception as e:
                hit_meta["error"] = str(e)
        elif include_hit_counts:
            hit_meta["note"] = "No unique device resolved for this policy; provide device_id to fetch hit counts."

    disabled = zero_hit = with_hits = unknown_hits = 0
    candidates = []
    for r in rules:
        rid = str(r.get("id") or "")
        rname = r.get("name")
        if not _name_matches(rname, name_contains, name_regex):
            continue
        enabled = r.get("enabled") is not False
        hit = hit_by_rule.get(rid)
        hc = hit.get("hitCount") if hit else None
        is_zero = hc == 0
        is_unused_candidate = (not enabled) or (is_zero is True)
        if not enabled: disabled += 1
        if hc is None: unknown_hits += 1
        elif is_zero: zero_hit += 1
        elif isinstance(hc, int) and hc > 0: with_hits += 1
        if not is_unused_candidate and (zero_hit_only or disabled_only):
            continue
        if disabled_only and enabled:
            continue
        if zero_hit_only and not is_zero:
            continue
        if include_disabled or is_unused_candidate or enabled:
            if is_unused_candidate or not summary_only:
                candidates.append({
                    "id": rid, "name": rname, "action": r.get("action"), "enabled": r.get("enabled"),
                    "hitCount": hc, **({"hitInfo": hit} if hit and not summary_only else {}),
                    "unused_candidate": is_unused_candidate,
                    "reasons": [reason for reason, cond in [("disabled", not enabled), ("zero_hit_count", is_zero is True)] if cond],
                })
    filtered_candidates = [c for c in candidates if c["unused_candidate"]] if (zero_hit_only or disabled_only or not summary_only) else candidates
    # if not filtering to candidates only, keep candidates list meaningful
    out_candidates = [c for c in candidates if c["unused_candidate"]]
    page = out_candidates[offset: offset + max(0, results_limit)]
    resp = {
        "policy": {"id": policy.get("id"), "name": policy.get("name")},
        "hit_counts": {"requested": hit_meta.get("requested"), "available": hit_meta.get("available"), "device_id": hit_meta.get("device_id"), "count": hit_meta.get("count"), **({"note": hit_meta["note"]} if hit_meta.get("note") else {}), **({"error": hit_meta["error"]} if hit_meta.get("error") else {})},
        "filters": {"name_contains": name_contains, "name_regex": name_regex, "zero_hit_only": zero_hit_only, "disabled_only": disabled_only, "results_limit": results_limit, "offset": offset, "summary_only": summary_only},
        "summary": {
            "rules_total": len(rules),
            "disabled_rules": disabled,
            "zero_hit_rules": zero_hit if hit_meta.get("available") else None,
            "rules_with_hits": with_hits if hit_meta.get("available") else None,
            "hit_count_unknown_or_unavailable": unknown_hits,
            "unused_candidates": len(out_candidates),
            "returned": len(page),
        },
        "caveats": [
            "Disabled rules and zero-hit rules are reported as unused candidates. Zero hits can be legitimate (new rules, rare traffic, hit count reset, or wrong device/time window); verify before removing.",
            "Hit counts require a device and FMC operational support; filter uses deviceId;fetchZeroHitCount:true when available.",
            "This does not detect shadowed rules (rules never reached because an earlier rule matches).",
        ],
    }
    if not summary_only:
        resp["unused_candidates"] = page
    return resp


async def find_unused_objects(
    client: "FMCClient",
    *,
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
    types = object_types or ["hosts", "networks", "ranges", "fqdns", "network_groups", "ports", "port_groups", "urls", "url_groups", "security_zones"]
    # 1) collect references from access rules
    if policy_id:
        policies = [{"id": policy_id}]
    else:
        policies = await client.get_all(await client.config_path("/policy/accesspolicies"))
        policies = policies[:max_policies]
    refs_by_id: dict[str, dict[str, Any]] = {}
    refs_by_name: dict[str, dict[str, Any]] = {}
    rules_scanned = 0
    for pol in policies:
        pid = pol.get("id")
        if not pid: continue
        try:
            rules = await client.get_all(await client.config_path(f"/policy/accesspolicies/{pid}/accessrules"), expanded=True, max_items=max_rules_per_policy)
        except Exception:
            continue
        for rule in rules:
            rules_scanned += 1
            rrefs = collect_rule_references(rule)
            where = {"policy_id": pid, "policy_name": pol.get("name"), "rule_id": rule.get("id"), "rule_name": rule.get("name")}
            for ref in rrefs.values():
                if ref.get("id"):
                    refs_by_id.setdefault(str(ref["id"]), {**{k:v for k,v in ref.items() if k!='paths'}, "used_in": []})
                    refs_by_id[str(ref["id"])]["used_in"].append(where)
                if ref.get("name"):
                    nk = str(ref["name"]).lower()
                    refs_by_name.setdefault(nk, {**{k:v for k,v in ref.items() if k!='paths'}, "used_in": []})
                    refs_by_name[nk]["used_in"].append(where)

    # 2) inventory objects and diff
    out_types = {}
    total_unused = 0
    total_objects = 0
    for t in types:
        suffix = OBJECT_INVENTORY.get(t)
        if not suffix:
            out_types[t] = {"error": "unknown object type"}
            continue
        try:
            objs = await client.get_all(await client.config_path(suffix), expanded=False, max_items=max_objects_per_type)
        except Exception as e:
            out_types[t] = {"error": str(e)}
            continue
        total_objects += len(objs)
        unused = []
        used = []
        for o in objs:
            oid = str(o.get("id") or "")
            name = str(o.get("name") or "")
            u = refs_by_id.get(oid) or refs_by_name.get(name.lower())
            item = {"id": o.get("id"), "name": o.get("name"), "type": o.get("type", t)}
            if u:
                item["reference_count"] = len(u.get("used_in") or [])
                if include_used and _name_matches(name, name_contains, name_regex):
                    used.append(item)
            else:
                if _name_matches(name, name_contains, name_regex):
                    unused.append(item)
        total_unused += len(unused)
        entry: dict[str, Any] = {"count": len(objs), "unused_count": len(unused), "returned": min(len(unused[offset: offset + max(0, results_limit)]), len(unused))}
        if not summary_only:
            entry["unused"] = unused[offset: offset + max(0, results_limit)]
        if include_used and not summary_only:
            entry["used_count"] = len(objs) - len(unused)
            entry["used"] = used[offset: offset + max(0, results_limit)]
        elif include_used:
            entry["used_count"] = len(objs) - len(unused)
        out_types[t] = entry

    return {
        "filters": {"name_contains": name_contains, "name_regex": name_regex, "results_limit": results_limit, "offset": offset, "summary_only": summary_only, "include_used": include_used},
        "scope": {"policy_id": policy_id, "policies_scanned": min(len(policies), max_policies) if not policy_id else 1, "rules_scanned": rules_scanned, "object_types": types},
        "summary": {"objects_scanned": total_objects, "unused_objects": total_unused},
        "types": out_types,
        "caveats": [
            "Best-effort: checks direct references in access rules (selected/scanned ACPs). Objects may still be used by NAT/prefilter/FlexConfig/platform/VPN/other policies, group nesting nuances, or non-scanned ACPs.",
            "Reference matching uses object id and name; name collisions or unresolved refs can affect accuracy. Verify in FMC before deleting.",
        ],
    }


async def audit_access_policy_inspection(
    client: "FMCClient",
    *,
    policy_id: str | None = None,
    include_rules: bool = True,
    rule_detail_limit: int = 25,
    include_disabled_rules: bool = False,
    max_policies: int = 100,
    max_rules_per_policy: int = 5000,
    summary_only: bool = False,
    only_issues: bool = False,
) -> dict[str, Any]:
    """Audit ACP default actions (implicit deny/block) and rule intrusion/IPS settings."""
    if policy_id:
        pol = await client.get(await client.config_path(f"/policy/accesspolicies/{policy_id}"))
        policies = [pol]
    else:
        policies = await client.get_all(await client.config_path("/policy/accesspolicies"), expanded=True)
        policies = policies[:max_policies]

    reports = []
    all_default_deny: bool | None = True
    for pol in policies:
        pid = pol.get("id")
        if not pid:
            continue
        try:
            full = await client.get(await client.config_path(f"/policy/accesspolicies/{pid}"))
        except Exception:
            full = pol
        da = _default_action_summary(full.get("defaultAction") or pol.get("defaultAction"))
        if da.get("is_implicit_deny_or_block") is False:
            all_default_deny = False
        elif da.get("is_implicit_deny_or_block") is None and all_default_deny is True:
            all_default_deny = None

        report: dict[str, Any] = {
            "policy": {"id": pid, "name": full.get("name") or pol.get("name"), "type": full.get("type") or pol.get("type")},
            "defaultAction": da,
        }
        if include_rules:
            try:
                rules = await client.get_all(
                    await client.config_path(f"/policy/accesspolicies/{pid}/accessrules"),
                    expanded=True,
                    max_items=max_rules_per_policy,
                )
            except Exception as e:
                report["rules_error"] = str(e)
                rules = []
            evaluated = [r for r in rules if include_disabled_rules or r.get("enabled") is not False]
            summaries = [_rule_intrusion_summary(r) for r in evaluated]
            # IPS/IDS checks are most meaningful for rules that inspect traffic; still report all.
            allow_like = [r for r in summaries if str(r.get("action") or "").upper() in {"ALLOW", "PERMIT", "TRUST", "MONITOR", "INTERACTIVE_BLOCK", "INTERACTIVE_BLOCK_RESET"} or str(r.get("action") or "").upper().startswith("ALLOW")]
            with_ips = [r for r in summaries if r.get("has_intrusion_policy")]
            prevention = [r for r in with_ips if r.get("is_prevention_mode") is True]
            detection = [r for r in with_ips if r.get("is_detection_mode") is True]
            missing_ips = [r for r in summaries if not r.get("has_intrusion_policy")]
            missing_ips_allow = [r for r in allow_like if not r.get("has_intrusion_policy")]
            report["intrusion_inspection"] = {
                "rules_total_fetched": len(rules),
                "rules_evaluated": len(evaluated),
                "rules_with_intrusion_policy": len(with_ips),
                "rules_without_intrusion_policy": len(missing_ips),
                "rules_with_prevention_mode": len(prevention),
                "rules_with_detection_mode": len(detection),
                "allow_like_rules_evaluated": len(allow_like),
                "allow_like_rules_without_intrusion_policy": len(missing_ips_allow),
                "all_evaluated_rules_have_intrusion_policy": len(evaluated) > 0 and len(with_ips) == len(evaluated),
                "some_evaluated_rules_have_intrusion_policy": 0 < len(with_ips) < len(evaluated),
                "no_evaluated_rules_have_intrusion_policy": len(evaluated) > 0 and len(with_ips) == 0,
            }
            if not summary_only:
                report["rules_missing_intrusion_policy"] = [{"id": r["id"], "name": r["name"], "action": r["action"], "enabled": r["enabled"]} for r in missing_ips[:rule_detail_limit]]
                report["rules_with_intrusion_policy"] = [{"id": r["id"], "name": r["name"], "action": r["action"], "enabled": r["enabled"], "intrusionPolicy": r["intrusionPolicy"], "inspectionMode": r["inspectionMode"]} for r in with_ips[:rule_detail_limit]]
        has_issue = (da.get("is_implicit_deny_or_block") is False) or (report.get("intrusion_inspection", {}).get("allow_like_rules_without_intrusion_policy", 0) > 0)
        report["has_issue"] = has_issue
        if not only_issues or has_issue:
            reports.append(report)

    return {
        "filters": {"summary_only": summary_only, "only_issues": only_issues, "rule_detail_limit": rule_detail_limit},
        "summary": {
            "policies_audited": len(reports) if not only_issues else None,
            "policies_with_issues_reported": len(reports) if only_issues else sum(1 for r in reports if r.get("has_issue")),
            "all_policies_default_action_is_deny_or_block": all_default_deny,
        },
        "policies": reports,
        "caveats": [
            "Interprets implicit deny as defaultAction.action BLOCK/BLOCK_ALL/DENY. FMC default actions and inspection behavior vary by version/policy type; verify in FMC UI/API Explorer.",
            "IPS/IDS reporting is based on presence of ipsPolicy/intrusionPolicy and inspectionMode (PREVENTION-like vs DETECTION-like). Rules may inspect traffic differently depending on action, ACP mode, and FTD capabilities.",
            "Default action intrusion/logging settings are reported when present; intrusion at default action is version/policy dependent.",
        ],
    }

# Cisco FMC MCP Server (`cisco-fmc-mcp`)

A Python [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for **Cisco Secure Firewall Management Center (FMC)**. It exposes FMC REST API operations as MCP tools so AI agents and MCP clients can inspect and (optionally) manage FMC configuration.

## Features

- **Python + FastMCP** implementation.
- **Streamable HTTP** MCP transport (FastMCP `transport="http"`, endpoint `/mcp`) and `stdio` transport.
- **Ticket / firewall-opening investigation (read-only, best effort)**:
  - `investigate_firewall_opening(source, destination, protocol?, port?, policy_id?)` — finds matching/possible access rules for a requested opening.
  - `trace_packet_access_rules(policy_id, source, destination, protocol?, port?, source_zone?, destination_zone?, rule_id?)` — **packet-tracker style simulation** through access rules in order (per-rule MATCH/NO_MATCH/INDETERMINATE, first-hit verdict, policy default action when available). This is an **access-rule criteria simulation**, not a full FTD/LINA datapath packet-tracer.
  - Supports endpoints as **IP address**, **CIDR/subnet**, **IP range** (`a-b`), or **FQDN/hostname**.
  - Loads relevant FMC objects (hosts, networks, ranges, FQDNs, network groups, port objects/groups where available).
- **Inspection & hygiene audits (read-only, best effort)**:
  - `audit_access_policy_inspection(policy_id?)` — checks ACP default action (implicit deny/block) and IPS/IDS/intrusion policy presence + inspection mode on rules.
  - `find_unused_access_rules(policy_id, device_id?)` — disabled and/or zero-hit rule candidates (uses FMC hitcounts when available; requires device context).
  - `find_unused_objects(object_types?, policy_id?)` — objects not directly referenced by scanned access rules.
- **Core FMC starter coverage**:
  - Status/domain, devices, policy assignments, deployment status (read)
  - Host/network/range/FQDN objects: list/get (CRUD for hosts/networks/ports; extendable)
  - Port/service objects (`ProtocolPortObject`): list/get/create/update/delete
  - Access policies: list/get (read)
  - Access rules: list/get/create/update/delete
- **Safety gate**: mutating tools (`create*`, `update*`, `delete*`) require `FMC_ALLOW_WRITES=true`.

> **Important:** FMC REST payloads and behavior can vary by FMC version. Always verify write payloads in FMC API Explorer: `https://<fmc-host>/api/api-explorer`. Test against a lab or non-production FMC before using write operations.

## Project layout

```text
fmc-mcp/
├── fmc_mcp/
│   ├── __init__.py
│   ├── __main__.py
│   ├── analysis.py     # ticket/packet-trace/inspection/unused-object-rule analysis
│   ├── config.py       # env/config loading
│   ├── fmc_client.py   # async FMC REST client (auth, pagination, CRUD)
│   └── server.py       # FastMCP server and tools
├── tests/
│   ├── test_analysis.py
│   └── test_config.py
├── .dockerignore
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- Network access to your FMC
- FMC API user credentials (dedicated least-privilege account recommended)

## Installation

```bash
cd /home/kaare/fmc-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If `python3 -m venv` fails on Debian/Ubuntu, install the venv package (e.g. `python3-venv`) or use an existing Python environment manager.

## Configuration

Copy `.env.example` to `.env` and set values:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|---|---:|---|
| `FMC_HOST` | yes | FMC base URL, e.g. `https://fmc.example.local` |
| `FMC_USERNAME` | yes | FMC API username |
| `FMC_PASSWORD` | yes | FMC API password |
| `FMC_DOMAIN_UUID` | no | FMC domain UUID; auto-discovered if omitted |
| `FMC_VERIFY_SSL` | no | `true` (default) or `false` (lab only) |
| `FMC_CA_BUNDLE` | no | Path to CA bundle for private/self-signed certs |
| `FMC_ALLOW_WRITES` | no | `true` enables create/update/delete tools; default `false` |
| `MCP_TRANSPORT` | no | `http` (default, Streamable HTTP) or `stdio` |
| `MCP_HOST` | no | HTTP bind host, default `127.0.0.1` |
| `MCP_PORT` | no | HTTP port, default `8000` |
| `LOG_LEVEL` | no | `DEBUG`, `INFO`, etc. |

## Running with Docker (recommended)

The container runs the **Streamable HTTP MCP** server at `http://<host>:<port>/mcp` (FastMCP `transport=http`). The image is non-root and defaults to **read-only mode** (`FMC_ALLOW_WRITES=false`).

### Parameters (environment variables)

| Parameter | Env var | Required | Default | Description |
|---|---|---:|---|---|
| FMC URL | `FMC_HOST` | yes | — | FMC base URL, e.g. `https://fmc.example.local` (include `https://`) |
| FMC username | `FMC_USERNAME` | yes | — | FMC API username |
| FMC password | `FMC_PASSWORD` | yes | — | FMC API password (pass via env/secret manager; avoid shell history where possible) |
| FMC domain UUID | `FMC_DOMAIN_UUID` | no | auto-discover | FMC domain UUID if auto-discovery is not desired |
| Verify TLS | `FMC_VERIFY_SSL` | no | `true` | Set `false` only for lab/self-signed testing (not recommended) |
| CA bundle | `FMC_CA_BUNDLE` | no | — | Container path to a CA bundle file; mount it as a volume |
| Allow writes | `FMC_ALLOW_WRITES` | no | `false` | `true` enables create/update/delete tools. Keep `false` unless intentionally needed |
| MCP bind address | `MCP_HOST` | no | `0.0.0.0` (container) | Address the server binds to **inside** the container. Use port publishing to control host exposure |
| MCP port | `MCP_PORT` | no | `8000` | Port the server listens on **inside** the container |
| MCP transport | `MCP_TRANSPORT` | no | `http` | `http` (Streamable HTTP, `/mcp`) or `stdio` |
| Log level | `LOG_LEVEL` | no | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Build

```bash
cd /home/kaare/fmc-mcp
docker build -t cisco-fmc-mcp:local .
```

### Run with `docker run`

```bash
docker run --rm \
  --name cisco-fmc-mcp \
  -p 127.0.0.1:8000:8000 \
  -e FMC_HOST="https://fmc.example.local" \
  -e FMC_USERNAME="apiuser" \
  -e FMC_PASSWORD="your-password" \
  -e FMC_ALLOW_WRITES="false" \
  -e MCP_HOST="0.0.0.0" \
  -e MCP_PORT="8000" \
  cisco-fmc-mcp:local
```

MCP endpoint: `http://127.0.0.1:8000/mcp`

Change host exposure/port mapping as needed (example: expose on port 18000 only locally):
```bash
-p 127.0.0.1:18000:8000 -e MCP_PORT=8000
```

Self-signed/private CA:
```bash
docker run --rm -p 127.0.0.1:8000:8000 \
  -e FMC_HOST="https://fmc.example.local" \
  -e FMC_USERNAME="apiuser" \
  -e FMC_PASSWORD="your-password" \
  -e FMC_CA_BUNDLE="/certs/fmc-ca.pem" \
  -e FMC_VERIFY_SSL="true" \
  -v "$(pwd)/certs/fmc-ca.pem:/certs/fmc-ca.pem:ro" \
  cisco-fmc-mcp:local
```

### Run with Docker Compose

```bash
cd /home/kaare/fmc-mcp
cp .env.example .env
# edit .env: set FMC_HOST, FMC_USERNAME, FMC_PASSWORD (and optional settings)
docker compose up -d --build
# or: docker-compose up -d --build
docker compose logs -f
```

`docker-compose.yml` reads `FMC_*` values from your environment/`.env`, binds the MCP endpoint to `127.0.0.1:8000` by default, and sets `MCP_HOST=0.0.0.0` inside the container.

### Connect an MCP client (Streamable HTTP)

Point your MCP client to the Streamable HTTP endpoint:
```text
http://127.0.0.1:8000/mcp
```
(Replace host/port if you changed the mapping.)

### Docker security notes

- **No built-in MCP authentication.** The server exposes tools over HTTP; do not publish it publicly. Prefer `127.0.0.1` port bindings, VPN/private networks, or a TLS-terminating authenticating reverse proxy.
- **Credentials:** pass `FMC_USERNAME`/`FMC_PASSWORD` via environment variables or your platform’s secret mechanism. Do not bake secrets into the image. Do not commit `.env`.
- **Write safety:** keep `FMC_ALLOW_WRITES=false` unless you explicitly intend configuration changes. FMC write payloads vary by version — verify in FMC API Explorer.
- **TLS:** keep `FMC_VERIFY_SSL=true`; use `FMC_CA_BUNDLE` for private/self-signed FMC certificates.

## Running locally (Python)

### Streamable HTTP

```bash
cd /home/kaare/fmc-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # set FMC_HOST/FMC_USERNAME/FMC_PASSWORD
export $(grep -v '^#' .env | xargs)  # or your preferred env loader
python -m fmc_mcp.server
```

Default endpoint: `http://127.0.0.1:8000/mcp` (local default bind is `MCP_HOST=127.0.0.1`).

### stdio (local MCP client subprocess)

```bash
MCP_TRANSPORT=stdio python -m fmc_mcp.server
```

## Tool overview

### Ticket investigation / packet trace
- `investigate_firewall_opening(source, destination, protocol?, port?, policy_id?, ..., max_results?, include_evidence?, detail_level?)` — read-only analysis for firewall-opening tickets. **Token-saving defaults:** `max_results=25`, `include_evidence=false`, `detail_level="compact"` (`summary` for counts/first match only).
- `trace_packet_access_rules(policy_id, source, destination, protocol?, port?, source_zone?, destination_zone?, ..., include_evidence?, detail_level?, max_trace_steps?)` — packet-tracker style **rule-criteria simulation** (not full FTD datapath). **Token-saving defaults:** `include_evidence=false`, `detail_level="compact"`, `max_trace_steps=50`. Provide zones for zone-aware evaluation.

> **Token-saving tips:** prefer `policy_id` scoping, `summary_only=true`, name filters, small `results_limit`/`limit`, `expanded=false` on lists, and avoid `include_evidence` unless needed. `list_access_rules` defaults to compact output (`expanded=false`, `limit=100`, supports `name_contains`/`action`/`enabled`/`offset`).

### Inspection & hygiene audits (read-only, best effort)
- `audit_access_policy_inspection(policy_id?, include_rules?, summary_only?, only_issues?, rule_detail_limit?)` — checks each ACP’s `defaultAction` (implicit deny/block interpretation) and rule-level `ipsPolicy`/intrusion policy presence + `inspectionMode` (e.g. `DETECTION`/`PREVENTION`). **Token-saving:** `summary_only=true` (counts only), `only_issues=true`, `include_rules=false` for fast all-ACP default-action audit, `rule_detail_limit` (default 25).
- `find_unused_access_rules(policy_id, device_id?, ..., name_contains?, zero_hit_only?, disabled_only?, results_limit?, offset?, summary_only?)` — disabled/zero-hit unused candidates (hitcounts when available). **Token-saving:** `results_limit` (default 50), `offset`, `summary_only`, name filters.
- `find_unused_objects(object_types?, policy_id?, ..., name_contains?, name_regex?, results_limit?, offset?, summary_only?, include_used?)` — objects not directly referenced by scanned access rules. **Token-saving:** `results_limit` per type (default 50), `offset`, `summary_only`, `name_contains`/`name_regex`, scope with `policy_id` and minimal `object_types`. Verify before deletion.

### Read tools
- `get_fmc_status()` — FMC connection/domain and server write mode.
- `list_devices()` — managed device records.
- `list_policy_assignments()` — policy-to-device/group/template assignments (useful to find the access policy applied to a device).
- `get_deployment_status()` — pending/deployable devices.
- `list_hosts`/`get_host`, `list_networks`/`get_network`, `list_ranges`/`get_range`, `list_fqdns`/`get_fqdn`
- `list_port_objects`/`get_port_object`
- `list_access_policies`/`get_access_policy`
- `list_access_rules(policy_id, ...)`, `get_access_rule(policy_id, rule_id)`

### Write tools (require `FMC_ALLOW_WRITES=true`)
- Hosts: `create_host`, `update_host`, `delete_host`
- Networks: `create_network`, `update_network`, `delete_network`
- Port objects: `create_port_object`, `update_port_object`, `delete_port_object`
- Access rules: `create_access_rule(policy_id, payload)`, `update_access_rule(policy_id, rule_id, payload)`, `delete_access_rule`

Access rule payloads are FMC-schema-dependent. A safe update pattern is:
1. `get_access_rule(...)`
2. Modify the returned object as needed
3. Pass the full updated payload to `update_access_rule(...)`

## Testing

```bash
source .venv/bin/activate
pytest -q
```

Current tests cover configuration and endpoint/port parsing basics (no live FMC required for parsing tests). Integration testing should be done against a lab FMC or a Cisco sandbox. `investigate_firewall_opening` is best-effort: verify results in FMC, especially zones, applications, users/SGTs, dynamic attributes, URL categories, prefilter, rule order/sections, and deployment state.

## Safety notes

- Keep `FMC_ALLOW_WRITES=false` unless you intentionally need changes.
- Use a dedicated FMC API account with least privilege.
- Verify TLS (`FMC_VERIFY_SSL=true`) or trust a CA bundle (`FMC_CA_BUNDLE`).
- Review every mutating action; FMC changes can affect traffic policy. This server does **not** trigger deployment.
- Do not expose the HTTP MCP endpoint publicly without authentication/TLS.

## Extending

The code is organized for extension:
- Add endpoints/constants in `fmc_mcp/server.py` (`OBJECT_ENDPOINTS`) for more FMC object types.
- Add methods in `fmc_mcp/fmc_client.py` for specialized FMC workflows.
- Add tools for NAT policies, device management, intrusion policies, etc., after confirming API payloads in FMC API Explorer.

## Disclaimer

This is a community-style starter implementation, not a Cisco product. Validate behavior against your FMC version and security policies before production use.

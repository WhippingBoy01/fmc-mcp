# AGENTS.md

This repo is a Python MCP server for Cisco Secure Firewall Management Center (FMC): package `fmc_mcp` (FastMCP), Streamable HTTP MCP at `/mcp` by default or `stdio`.

## Layout / entrypoints
- `fmc_mcp/server.py` — FastMCP server and tool definitions (main entrypoint: `python -m fmc_mcp.server` or `cisco-fmc-mcp`).
- `fmc_mcp/fmc_client.py` — async FMC REST client (auth/pagination/CRUD).
- `fmc_mcp/analysis.py` — read-only investigation/trace/inspection/unused-object-rule analysis.
- `fmc_mcp/config.py` — env loading (`load_settings`) and write gate (`require_writes`).
- `tests/` — pytest suite (`test_config.py`, `test_analysis.py`).

## Commands
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # runtime + pytest deps
# or: pip install -e ".[dev]"
python -m fmc_mcp.server                  # uses env/.env; default MCP_TRANSPORT=http (127.0.0.1:8000/mcp)
MCP_TRANSPORT=stdio python -m fmc_mcp.server
pytest -q                                 # all tests (pyproject: testpaths=tests, asyncio_mode=auto)
pytest -q tests/test_config.py            # single file
pytest -q tests/test_config.py -k load_settings_defaults  # single test
python3 -m py_compile fmc_mcp/*.py tests/*.py             # quick syntax check
```
No lint/typecheck/CI/pre-commit config is present in this repo; do not invent extra gates.

## Config & safety (FMC)
- Required: `FMC_HOST` (scheme required), `FMC_USERNAME`, `FMC_PASSWORD`. Optional: `FMC_DOMAIN_UUID`, `FMC_VERIFY_SSL` (default true), `FMC_CA_BUNDLE`, `FMC_ALLOW_WRITES` (default false), `MCP_TRANSPORT` (`http`/`stdio`, `streamable-http` normalized), `MCP_HOST`/`MCP_PORT` (local default `127.0.0.1:8000`), `LOG_LEVEL`.
- `config.load_settings` reads process env and a local `.env` if present without overriding explicit env vars; pass a non-existent env file path in tests to avoid loading repo `.env`.
- **Writes are safety-gated:** mutating tools must check `require_writes(settings)` (`FMC_ALLOW_WRITES=true` required). Do not weaken this gate or trigger deployment.
- FMC REST payloads/fields vary by FMC version; verify write payloads in `https://<fmc-host>/api/api-explorer` before changing/adding write behavior. Prefer TLS verification; use `FMC_CA_BUNDLE` for private certs.
- Never commit `.env`, credentials, tokens, or cert bundles (`.gitignore` excludes `.env*` except `.env.example`).

## Testing / behavior notes
- Existing tests are offline/unit (config parsing, analysis helpers) — no live FMC required. Integration validation needs a lab/sandbox FMC.
- Analysis/trace/inspection/unused tools are **best-effort** (API/field availability varies by FMC version); they are not a full FTD datapath packet-tracer. Preserve token-saving/default-limit and compact-output behavior when modifying tools.
- Docker runs non-root, defaults `MCP_HOST=0.0.0.0` in-container with host port publishing (see `Dockerfile`, `docker-compose.yml`, README). No built-in MCP auth; do not expose publicly.

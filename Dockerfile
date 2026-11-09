# Cisco FMC MCP server (Streamable HTTP / stdio)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Container-friendly defaults. Override via `docker run -e ...` / compose.
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    FMC_ALLOW_WRITES=false \
    FMC_VERIFY_SSL=true \
    LOG_LEVEL=INFO

WORKDIR /app

# Install runtime dependencies first for better layer caching.
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY fmc_mcp ./fmc_mcp
COPY README.md ./

# Run as non-root.
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Streamable HTTP MCP endpoint: http://<host>:<mapped-port>/mcp
CMD ["python", "-m", "fmc_mcp.server"]

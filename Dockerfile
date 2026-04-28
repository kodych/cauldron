# syntax=docker/dockerfile:1.7

# ---- Stage 1: build the React frontend bundle -----------------------------
FROM node:20-slim AS frontend

WORKDIR /frontend

# Install deps from lockfile so the bundle is byte-reproducible across
# rebuilds. The package*.json copy is split from the source copy so the
# (slow) npm install layer caches across iteration.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npm run build


# ---- Stage 2: Python runtime ----------------------------------------------
FROM python:3.11-slim AS runtime

# curl is used by the HEALTHCHECK below; keep the image lean otherwise.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install Python deps first so source-only changes don't bust the layer.
COPY pyproject.toml README.md LICENSE ./
COPY cauldron/__init__.py cauldron/__init__.py
RUN pip install --no-cache-dir ".[api,ai]"

# Now copy the rest of the package and the freshly built frontend bundle.
COPY cauldron/ ./cauldron/
COPY data/samples/ ./data/samples/
COPY --from=frontend /frontend/dist ./frontend/dist

# Default CORS to the host's own origin only — anyone deploying behind
# a reverse proxy can override via CAULDRON_CORS_ORIGINS.
ENV CAULDRON_FRONTEND_DIST=/app/frontend/dist

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://localhost:8000/api/v1/health || exit 1

# Bind to 0.0.0.0 inside the container — the operator controls which
# host port (and which interface) the container exposes via -p / compose.
CMD ["uvicorn", "cauldron.api.server:app", "--host", "0.0.0.0", "--port", "8000"]

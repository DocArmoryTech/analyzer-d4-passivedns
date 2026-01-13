# Dockerfile for analyzer-d4-passivedns API

FROM python:3.10-slim AS base

# Install system dependencies (build tools, git for Poetry install if needed)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and workdir
RUN useradd -m -u 10001 pdns
WORKDIR /app

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PDNS_HOME=/app

# Copy project metadata, README, and package source for dependency layer and packaging
COPY pyproject.toml README.md ./
COPY pdns ./pdns

# Install Poetry and dependencies, then install the project as a package
RUN pip install --no-cache-dir poetry \
    && poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi \
    && pip install .

# Copy additional application resources
COPY config ./config
COPY tools ./tools

# Switch to non-root user
USER pdns

# Default command: run the FastAPI server via the installed CLI script
EXPOSE 8000
CMD ["pdns", "serve", "--host", "0.0.0.0", "--port", "8000"]

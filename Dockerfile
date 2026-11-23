# One image for both roles: the API (default command) and the worker (`python -m triage worker`).
#   docker build -t sbom-triage:dev .
#   docker run --rm -p 8000:8000 sbom-triage:dev                 # API, file store, login off
#   docker run --rm sbom-triage:dev python -m triage worker      # worker (needs TRIAGE_STORE=postgres and DATABASE_URL)
# Base images come from the public ECR mirror of the Docker official images (no Docker Hub rate limit).
ARG REGISTRY=public.ecr.aws/docker/library

# ---- dashboard: static files only, no Node in the final image ----
FROM ${REGISTRY}/node:22-slim AS web
WORKDIR /web
RUN npm install -g pnpm@10
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# ---- the Docker CLI, for the worker's sandbox (it talks to a daemon given by DOCKER_HOST) ----
FROM ${REGISTRY}/docker:27-cli AS dockercli

# ---- application ----
FROM ${REGISTRY}/python:3.12-slim AS app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH=/app/.venv/bin:$PATH
WORKDIR /app
RUN pip install --no-cache-dir uv==0.13.9
# dependencies first, so a code change does not reinstall them
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --extra postgres --extra auth --extra openai
# The package is installed in place (editable): the code finds out/ and fixtures/ relative to /app/backend.
COPY backend/ backend/
COPY fixtures/cache/ fixtures/cache/
RUN uv sync --frozen --no-dev --extra postgres --extra auth --extra openai
COPY --from=web /web/dist web/dist
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
# Runs as an unprivileged user; out/ is the artifact volume and the only place the process writes.
RUN useradd --uid 10001 --create-home triage && mkdir -p /app/out /repos && chown -R 10001:10001 /app/out /repos
USER 10001
EXPOSE 8000
CMD ["uvicorn", "triage.api:app", "--host", "0.0.0.0", "--port", "8000"]

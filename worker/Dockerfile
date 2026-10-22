# syntax=docker/dockerfile:1
#
# ExDomainVault home scanning worker — container image (alternative to the systemd install in
# docs/home-worker-setup.md). Outbound HTTPS only; the container exposes no ports.
#
# Build (from the repository root):
#   docker build -t exdomainvault-worker:local worker/
#
# Run (read-only root filesystem, no capabilities, key and env supplied at run time):
#   docker run -d --name exdomainvault-worker --restart unless-stopped \
#     --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
#     --cap-drop ALL --security-opt no-new-privileges:true \
#     --memory 512m --pids-limit 64 --cpus 0.5 \
#     --env-file /etc/exdomainvault/worker.env \
#     -e EXDV_PRIVATE_KEY_FILE=/run/secrets/worker.key \
#     -v /etc/exdomainvault/worker.key:/run/secrets/worker.key:ro \
#     -v exdomainvault-worker-state:/var/lib/exdomainvault-worker \
#     exdomainvault-worker:local
#
# The mounted key must be owned by uid 10001 and mode 0600 (or 0400): the worker refuses a key that is
# group/world readable. No secrets are baked into the image.

# Base image pinned by exact tag and index digest (python:3.12.14-slim-trixie, published 2026-09-25).
# Update both together.
ARG PYTHON_IMAGE=python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

# ---------------------------------------------------------------------------------------------------
# Build stage: create the virtual environment and install pinned dependencies and the worker package.
# ---------------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/exdomainvault-worker/.venv
ENV PATH=/opt/exdomainvault-worker/.venv/bin:$PATH

WORKDIR /src
COPY requirements.txt ./
# Use hash-checking mode when requirements.txt carries --hash entries; otherwise exact pins only.
RUN if grep -q -- '--hash=' requirements.txt; then \
        pip install --no-cache-dir --require-hashes -r requirements.txt; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir --no-deps . \
    && python -m compileall -q /opt/exdomainvault-worker/.venv

# ---------------------------------------------------------------------------------------------------
# Runtime stage: no compilers, no pip cache, no source tree, non-root user.
# ---------------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="exdomainvault-worker" \
      org.opencontainers.image.description="ExDomainVault home scanning worker (outbound HTTPS only)"

RUN groupadd --system --gid 10001 exdomainvault-worker \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /var/lib/exdomainvault-worker --shell /usr/sbin/nologin exdomainvault-worker \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/exdomainvault-worker

COPY --from=build /opt/exdomainvault-worker/.venv /opt/exdomainvault-worker/.venv

ENV PATH=/opt/exdomainvault-worker/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EXDV_ENVIRONMENT=production \
    EXDV_HEALTH_FILE=/var/lib/exdomainvault-worker/health.json

# The only writable location the worker needs; mount a volume here when running --read-only.
VOLUME ["/var/lib/exdomainvault-worker"]
WORKDIR /var/lib/exdomainvault-worker
USER 10001:10001

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
    CMD ["exdomainvault-worker", "--health"]

ENTRYPOINT ["exdomainvault-worker"]

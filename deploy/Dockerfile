# =============================================================================
#  SOVEREIGN ROOT PROTOCOL (SRP) — UNIVERSAL DOCKER IMAGE
# =============================================================================
#  Build:
#    docker build -f deploy/Dockerfile -t srp-node:latest .
#
#  Run (choose role via SRP_ROLE env):
#    docker run -e SRP_ROLE=proxy    -p 9000:9000    srp-node:latest
#    docker run -e SRP_ROLE=sync     -p 9200:9200    srp-node:latest
#    docker run -e SRP_ROLE=telemetry                 srp-node:latest
#    docker run -e SRP_ROLE=init                      srp-node:latest
#
#  Orchestrate all services:
#    docker compose -f deploy/docker-compose.yml up -d
# =============================================================================

FROM python:3.11-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN pip install --no-cache-dir torch==2.2.0 --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/srp

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY srp_proxy.py .
COPY srp_loader.py .
COPY srp-node.py .
COPY srp_filter.c .
COPY telemetry/ telemetry/
COPY cluster/ cluster/
COPY orchestration/ orchestration/
COPY operations/ operations/
COPY scripts/ scripts/

RUN python3 -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" \
    && rm -rf /root/.cache/huggingface/hub/*.msgpack

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SENTENCE_TRANSFORMERS_HOME=/opt/srp/model_cache

COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 9000 9001 9200 9201 1993

ENTRYPOINT ["docker-entrypoint.sh"]

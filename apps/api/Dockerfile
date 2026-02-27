FROM python:3.12-slim
WORKDIR /app

# Create non-root user with explicit UID/GID matching compose user: "999:999"
RUN groupadd -r -g 999 appuser && useradd -r -u 999 -g appuser -d /app -s /sbin/nologin appuser

COPY requirements.txt requirements.lock ./
# Use lockfile with hash verification for supply-chain security.
# Fall back to requirements.txt if lockfile is missing (development).
RUN if [ -f requirements.lock ]; then \
      pip install --no-cache-dir --require-hashes -r requirements.lock; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

COPY app ./app

# Create writable directories with strict permissions:
#   /data         — state files (API keys, users, audit) — owner-only
#   /run/secrets  — Vault Agent tmpfs mount point (RAM-only)
#   /tmp          — tmpfs for temporary files
RUN mkdir -p /data /tmp /run/secrets && \
    chmod 0700 /data /run/secrets && \
    chown -R appuser:appuser /app /data /tmp /run/secrets

# Environment hardening
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random

EXPOSE 8000

# Run as non-root
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

# Default: standalone mode. When Vault Agent sidecar is used,
# it will exec uvicorn after rendering secrets to /run/secrets/.
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]

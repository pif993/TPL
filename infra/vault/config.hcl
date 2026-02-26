# ─────────────────────────────────────────────────────────────────────────────
# HashiCorp Vault Server Configuration — TPL Project
# ─────────────────────────────────────────────────────────────────────────────
# Secrets encrypted at rest (file backend with AES-256-GCM barrier).
# Production: replace file backend with Consul/Raft + auto-unseal via KMS/HSM.
# ─────────────────────────────────────────────────────────────────────────────

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  # TLS disabled inside Docker network — Traefik terminates TLS externally.
  # For production with direct exposure, enable TLS here.
  tls_disable = true
}

# Audit: file backend writes to stdout (Docker captures it).
# Second audit backend writes to persistent file for compliance.
# Enabled programmatically during bootstrap.

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"

# UI disabled in headless mode — enable only if needed.
ui = false

# Max lease TTL: 768h (32 days). Default: 768h.
default_lease_ttl = "1h"
max_lease_ttl     = "768h"

# Disable mlock in container (use --cap-add IPC_LOCK or mlockall in prod)
disable_mlock = true

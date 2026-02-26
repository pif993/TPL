# ─────────────────────────────────────────────────────────────────────────────
# Vault Policy: tpl-api
# Grants the API service access ONLY to its own secret path.
# No other service can read API secrets.
# ─────────────────────────────────────────────────────────────────────────────

# Read-only access to API secrets
path "secret/data/tpl/api/*" {
  capabilities = ["read"]
}

# Allow listing keys (to discover available secrets)
path "secret/metadata/tpl/api/*" {
  capabilities = ["read", "list"]
}

# Deny everything else (implicit, but explicit for clarity)
path "secret/*" {
  capabilities = ["deny"]
}

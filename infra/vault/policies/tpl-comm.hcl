# ─────────────────────────────────────────────────────────────────────────────
# Vault Policy: tpl-comm
# Communication engine — can only read its own shared secret.
# ─────────────────────────────────────────────────────────────────────────────

path "secret/data/tpl/comm/*" {
  capabilities = ["read"]
}

path "secret/metadata/tpl/comm/*" {
  capabilities = ["read", "list"]
}

path "secret/*" {
  capabilities = ["deny"]
}

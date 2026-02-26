# ─────────────────────────────────────────────────────────────────────────────
# Vault Policy: tpl-admin
# Full admin access for bootstrap, rotation, and management operations.
# Used ONLY by the bootstrap script — never by runtime services.
# ─────────────────────────────────────────────────────────────────────────────

path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/policies/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/audit/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "sys/mounts/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

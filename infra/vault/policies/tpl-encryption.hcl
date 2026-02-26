# ─────────────────────────────────────────────────────────────────────────────
# Vault Policy: tpl-encryption
# Encryption engine — can only read master key and key-ring.
# ─────────────────────────────────────────────────────────────────────────────

path "secret/data/tpl/encryption/*" {
  capabilities = ["read"]
}

path "secret/metadata/tpl/encryption/*" {
  capabilities = ["read", "list"]
}

# Allow the encryption engine to write rotated keys
path "secret/data/tpl/encryption/keyring" {
  capabilities = ["create", "update", "read"]
}

path "secret/*" {
  capabilities = ["deny"]
}

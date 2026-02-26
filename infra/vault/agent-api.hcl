# ─────────────────────────────────────────────────────────────────────────────
# Vault Agent Configuration — API Sidecar
# Authenticates via AppRole, writes secrets to tmpfs (RAM-only).
# Secrets auto-renew and re-template on rotation.
# ─────────────────────────────────────────────────────────────────────────────

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://vault:8200"
  retry {
    num_retries = 5
  }
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/vault/approle/role-id"
      secret_id_file_path = "/vault/approle/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
      mode = 0640
    }
  }
}

# Template blocks: render each secret to tmpfs mount /run/secrets/
# The API container reads from these files via *_FILE env vars.

template {
  destination  = "/run/secrets/api_secret"
  perms        = "0400"
  error_on_missing_key = true
  contents     = <<-EOT
  {{- with secret "secret/data/tpl/api/jwt" }}{{ .Data.data.api_secret }}{{ end }}
  EOT
}

template {
  destination  = "/run/secrets/tpl_admin_password"
  perms        = "0400"
  error_on_missing_key = true
  contents     = <<-EOT
  {{- with secret "secret/data/tpl/api/users" }}{{ .Data.data.admin_password }}{{ end }}
  EOT
}

template {
  destination  = "/run/secrets/tpl_user_password"
  perms        = "0400"
  error_on_missing_key = true
  contents     = <<-EOT
  {{- with secret "secret/data/tpl/api/users" }}{{ .Data.data.user_password }}{{ end }}
  EOT
}

template {
  destination  = "/run/secrets/comm_shared_secret"
  perms        = "0400"
  error_on_missing_key = true
  contents     = <<-EOT
  {{- with secret "secret/data/tpl/comm/hmac" }}{{ .Data.data.shared_secret }}{{ end }}
  EOT
}

template {
  destination  = "/run/secrets/tpl_master_key"
  perms        = "0400"
  error_on_missing_key = true
  contents     = <<-EOT
  {{- with secret "secret/data/tpl/encryption/master" }}{{ .Data.data.master_key }}{{ end }}
  EOT
}

# Note: In sidecar mode, vault-agent only renders secrets to tmpfs.
# The API container starts independently via its own Dockerfile CMD.
# Secret rotation triggers API restart via Docker healthcheck.

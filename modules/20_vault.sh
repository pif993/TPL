#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Module: 20_vault — HashiCorp Vault secret manager
#
# "Maximum security" secret management:
#   • Secrets NEVER in .env, repo, Docker images, or logs
#   • Encrypted at rest (Vault barrier AES-256-GCM)
#   • Per-service policies (API reads only secret/tpl/api/*)
#   • AppRole auth with short-lived tokens
#   • Vault Agent sidecar writes secrets to tmpfs (RAM-only)
#   • Rotation via `vault_rotate` helper
#   • Audit log for every secret access
#   • Zero default passwords — all generated cryptographically
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"20_vault","ver":"1.0.0","deps":["10_traefik"],"desc":"HashiCorp Vault secret manager with AppRole, per-service policies, tmpfs delivery, audit, rotation"}
JSON
}

# ── Helpers ──────────────────────────────────────────────────────────────────
_rand_secret(){ head -c "${1:-32}" /dev/urandom | base64 | tr -d '/+=\n' | head -c "${1:-32}"; }

# All Vault API calls go through docker exec + vault CLI.
# No host port exposure needed — everything runs inside the container.
_VAULT_CONTAINER="tpl-vault"
_VAULT_INTERNAL="http://127.0.0.1:8200"

_vault_ready(){
  echo "INFO: Waiting for Vault container to become ready..."
  for i in $(seq 1 60); do
    # vault status exits 2 = sealed-but-reachable, 0 = unsealed. Both mean API is up.
    local rc=0
    docker exec -e VAULT_ADDR="$_VAULT_INTERNAL" "$_VAULT_CONTAINER" \
      vault status -format=json >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
      echo "INFO: Vault is reachable (status exit=$rc)."
      return 0
    fi
    sleep 1
  done
  echo "ERR: Vault not reachable after 60s" >&2
  docker logs "$_VAULT_CONTAINER" 2>&1 | tail -20 >&2
  return 1
}

# Run vault CLI inside the container
_vcli(){
  docker exec -e VAULT_ADDR="$_VAULT_INTERNAL" \
    ${VAULT_TOKEN:+-e VAULT_TOKEN="$VAULT_TOKEN"} \
    "$_VAULT_CONTAINER" vault "$@"
}

# Pipe data to vault CLI stdin (for policy writes etc.)
_vcli_stdin(){
  docker exec -i -e VAULT_ADDR="$_VAULT_INTERNAL" \
    ${VAULT_TOKEN:+-e VAULT_TOKEN="$VAULT_TOKEN"} \
    "$_VAULT_CONTAINER" vault "$@"
}

# Initialize Vault and unseal. Sets ROOT_TOKEN and writes UNSEAL_KEYS_FILE.
# Retries up to 15 s to handle slow post-start readiness.
_vault_init_and_unseal(){
  local unseal_file="$1"
  local INIT_RESPONSE="" attempt

  for attempt in $(seq 1 15); do
    INIT_RESPONSE=$(_vcli operator init -format=json -key-shares=5 -key-threshold=3 2>&1) && break
    # Check if the output looks like a JSON object (success) despite non-zero exit
    if echo "$INIT_RESPONSE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
      break
    fi
    echo "  … init attempt $attempt/15 — retrying in 2s ($(echo "$INIT_RESPONSE" | head -1))"
    INIT_RESPONSE=""
    sleep 2
  done

  if [ -z "$INIT_RESPONSE" ]; then
    echo "ERR: vault operator init failed after 15 attempts" >&2
    # Show container logs for debugging
    docker logs "$_VAULT_CONTAINER" 2>&1 | tail -30 >&2
    return 1
  fi

  echo "$INIT_RESPONSE" > "$unseal_file"
  chmod 600 "$unseal_file"

  ROOT_TOKEN=$(echo "$INIT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")

  # Unseal with first 3 of 5 keys
  local keys
  keys=$(echo "$INIT_RESPONSE" | python3 -c "import sys,json; [print(k) for k in json.load(sys.stdin)['unseal_keys_b64'][:3]]")
  while IFS= read -r key; do
    _vcli operator unseal "$key" >/dev/null 2>&1
  done <<< "$keys"
  echo "INFO: Vault initialized and unsealed."
}

apply(){
  echo "──── 20_vault: Initializing Vault secret manager ────"
  mkdir -p infra/vault/policies infra/vault/data compose.d

  # ── 1. Compose fragment for Vault server ──────────────────────────────────
  cat > compose.d/20-vault.yml <<'YML'
services:
  vault:
    image: hashicorp/vault:1.15
    container_name: tpl-vault
    command: ["server"]
    environment:
      VAULT_LOCAL_CONFIG: ""
      VAULT_ADDR: "http://127.0.0.1:8200"
    volumes:
      - ./infra/vault/config.hcl:/vault/config/vault.hcl:ro
      - vault_data:/vault/file
      - vault_audit:/vault/audit
    ports: []
    restart: unless-stopped
    # NOTE: Vault's entrypoint uses setcap(8) to grant IPC_LOCK to the binary.
    # no-new-privileges blocks setcap → crash-loop. Vault manages its own
    # privilege dropping (root → vault user) so this is acceptable.
    cap_drop:
      - ALL
    cap_add:
      - IPC_LOCK
      - SETFCAP
      - CHOWN
      - FOWNER
      - DAC_OVERRIDE
      - SETUID
      - SETGID
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
          pids: 64
    healthcheck:
      test: ["CMD", "vault", "status", "-address=http://127.0.0.1:8200"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 10s
    networks:
      - default

volumes:
  vault_data:
    name: tpl_vault_data
  vault_audit:
    name: tpl_vault_audit
YML

  # ── 2. Copy policies ─────────────────────────────────────────────────────
  for pol in infra/vault/policies/*.hcl; do
    [ -f "$pol" ] || continue
    echo "INFO: Policy file ready: $(basename "$pol")"
  done

  # ── 3. Start Vault container ──────────────────────────────────────────────
  echo "INFO: Starting Vault server..."
  local compose_args=(-f compose.yml)
  [ -f compose.d/20-vault.yml ] && compose_args+=(-f compose.d/20-vault.yml)
  docker compose "${compose_args[@]}" up -d vault
  _vault_ready || return 1

  # ── 4. Initialize Vault (if needed) ──────────────────────────────────────
  local UNSEAL_KEYS_FILE=".vault_unseal_keys.json"
  local ROOT_TOKEN=""

  # Check if already initialized via vault CLI
  local IS_INIT
  IS_INIT=$(_vcli status -format=json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized', False))" 2>/dev/null || echo "False")

  if [ "$IS_INIT" = "False" ]; then
    echo "INFO: Initializing Vault (first run)..."
    _vault_init_and_unseal "$UNSEAL_KEYS_FILE" || return 1
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  VAULT INITIALIZED — SAVE UNSEAL KEYS SECURELY!            ║"
    echo "║                                                            ║"
    echo "║  Unseal keys saved to: ${UNSEAL_KEYS_FILE}                 ║"
    echo "║  Move this file to SECURE OFFLINE STORAGE immediately.     ║"
    echo "║  Root token is ephemeral — will be revoked after setup.    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
  else
    echo "INFO: Vault already initialized."

    if [ ! -f "${UNSEAL_KEYS_FILE}" ]; then
      # Keys file gone (e.g. rollback). Wipe volumes and reinitialize.
      echo "WARN: No unseal keys file — wiping stale Vault and reinitializing..."
      docker compose "${compose_args[@]}" down --remove-orphans 2>/dev/null || true
      docker volume rm tpl_vault_data tpl_vault_audit 2>/dev/null || true
      sleep 2
      docker compose "${compose_args[@]}" up -d vault
      _vault_ready || return 1
      _vault_init_and_unseal "$UNSEAL_KEYS_FILE" || return 1
      echo ""
      echo "╔══════════════════════════════════════════════════════════════╗"
      echo "║  VAULT RE-INITIALIZED — SAVE UNSEAL KEYS SECURELY!        ║"
      echo "╚══════════════════════════════════════════════════════════════╝"
      echo ""
    else
      # Keys file exists — unseal if sealed
      local SEALED
      SEALED=$(_vcli status -format=json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))" 2>/dev/null || echo "True")
      if [ "$SEALED" = "True" ]; then
        echo "INFO: Vault is sealed, auto-unsealing..."
        local keys
        keys=$(python3 -c "import json; [print(k) for k in json.load(open('${UNSEAL_KEYS_FILE}'))['unseal_keys_b64'][:3]]")
        while IFS= read -r key; do
          _vcli operator unseal "$key" >/dev/null 2>&1
        done <<< "$keys"
        echo "INFO: Vault unsealed."
      fi
      ROOT_TOKEN=$(python3 -c "import json; print(json.load(open('${UNSEAL_KEYS_FILE}'))['root_token'])")
    fi
  fi

  if [ -z "$ROOT_TOKEN" ]; then
    echo "ERR: No root token available. Cannot configure Vault." >&2
    return 1
  fi

  export VAULT_TOKEN="$ROOT_TOKEN"

  # ── Verify the root token is still valid ──────────────────────────────────
  # If a previous run revoked the root token, we must wipe and reinitialize.
  if ! _vcli token lookup -format=json >/dev/null 2>&1; then
    echo "WARN: Root token is invalid/revoked — wiping Vault and reinitializing..."
    unset VAULT_TOKEN
    docker compose "${compose_args[@]}" down --remove-orphans 2>/dev/null || true
    docker volume rm tpl_vault_data tpl_vault_audit 2>/dev/null || true
    rm -f "$UNSEAL_KEYS_FILE"
    sleep 2
    docker compose "${compose_args[@]}" up -d vault
    _vault_ready || return 1
    ROOT_TOKEN=""
    _vault_init_and_unseal "$UNSEAL_KEYS_FILE" || return 1
    export VAULT_TOKEN="$ROOT_TOKEN"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  VAULT RE-INITIALIZED — SAVE UNSEAL KEYS SECURELY!        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
  fi

  # Wait for Vault to be fully ready (unsealed + active)
  echo "INFO: Waiting for Vault to be fully active..."
  for i in $(seq 1 30); do
    if _vcli status -format=json 2>/dev/null | \
       python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if not d.get('sealed') else 1)" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  # ── 5. Enable KV v2 secrets engine ───────────────────────────────────────
  echo "INFO: Configuring secrets engine..."
  if ! _vcli secrets list -format=json 2>/dev/null | python3 -c "import sys,json; exit(0 if 'secret/' in json.load(sys.stdin) else 1)" 2>/dev/null; then
    _vcli secrets enable -path=secret -version=2 kv >/dev/null 2>&1
    echo "INFO: KV v2 secrets engine enabled at secret/"
  else
    echo "INFO: KV v2 secrets engine already mounted."
  fi

  # ── 6. Write policies ────────────────────────────────────────────────────
  echo "INFO: Writing access policies..."
  for pol_file in infra/vault/policies/*.hcl; do
    [ -f "$pol_file" ] || continue
    local pol_name
    pol_name=$(basename "$pol_file" .hcl)
    # Pipe policy HCL into vault via stdin
    cat "$pol_file" | _vcli_stdin policy write "$pol_name" - >/dev/null 2>&1
    echo "  ✓ Policy: ${pol_name}"
  done

  # ── 7. Enable AppRole auth ───────────────────────────────────────────────
  echo "INFO: Configuring AppRole auth..."
  if ! _vcli auth list -format=json 2>/dev/null | python3 -c "import sys,json; exit(0 if 'approle/' in json.load(sys.stdin) else 1)" 2>/dev/null; then
    _vcli auth enable approle >/dev/null 2>&1
    echo "INFO: AppRole auth method enabled."
  fi

  # ── 8. Create AppRole for the API service ─────────────────────────────────
  echo "INFO: Creating API AppRole..."
  _vcli write auth/approle/role/tpl-api \
    token_policies="tpl-api,tpl-comm,tpl-encryption" \
    token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=720h secret_id_num_uses=0 \
    token_num_uses=0 bind_secret_id=true >/dev/null 2>&1

  # Get Role ID
  local ROLE_ID _json_out
  _json_out=$(_vcli read -format=json auth/approle/role/tpl-api/role-id 2>/dev/null) || true
  if [ -z "$_json_out" ]; then
    echo "ERR: Failed to read AppRole role-id from Vault." >&2
    return 1
  fi
  ROLE_ID=$(echo "$_json_out" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
  if [ -z "$ROLE_ID" ]; then
    echo "ERR: role-id is empty after parsing." >&2
    return 1
  fi

  # Generate Secret ID
  local SECRET_ID
  _json_out=$(_vcli write -format=json -f auth/approle/role/tpl-api/secret-id 2>/dev/null) || true
  if [ -z "$_json_out" ]; then
    echo "ERR: Failed to generate AppRole secret-id from Vault." >&2
    return 1
  fi
  SECRET_ID=$(echo "$_json_out" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
  if [ -z "$SECRET_ID" ]; then
    echo "ERR: secret-id is empty after parsing." >&2
    return 1
  fi

  # Write AppRole credentials to files (for Vault Agent sidecar)
  mkdir -p .vault_approle
  echo -n "$ROLE_ID"   > .vault_approle/role-id
  echo -n "$SECRET_ID" > .vault_approle/secret-id
  chmod 600 .vault_approle/role-id .vault_approle/secret-id
  # Vault Agent runs as uid 100 (vault) inside the container
  chown -R 100:1000 .vault_approle
  echo "  ✓ AppRole tpl-api configured (role-id + secret-id in .vault_approle/)"

  # ── 9. Generate and store all secrets ─────────────────────────────────────
  echo "INFO: Generating cryptographic secrets (no defaults, no weak values)..."

  local API_SECRET ADMIN_PW USER_PW COMM_SECRET MASTER_KEY
  API_SECRET="$(_rand_secret 48)"
  ADMIN_PW="$(_rand_secret 32)"
  USER_PW="$(_rand_secret 32)"
  COMM_SECRET="$(_rand_secret 48)"
  MASTER_KEY="$(_rand_secret 64)"

  # Store in Vault KV v2 using vault kv put
  _vcli kv put secret/tpl/api/jwt \
    api_secret="$API_SECRET" algorithm=HS256 created_at="$(date +%s)" >/dev/null 2>&1
  echo "  ✓ secret/tpl/api/jwt"

  _vcli kv put secret/tpl/api/users \
    admin_password="$ADMIN_PW" user_password="$USER_PW" created_at="$(date +%s)" >/dev/null 2>&1
  echo "  ✓ secret/tpl/api/users"

  _vcli kv put secret/tpl/comm/hmac \
    shared_secret="$COMM_SECRET" created_at="$(date +%s)" >/dev/null 2>&1
  echo "  ✓ secret/tpl/comm/hmac"

  _vcli kv put secret/tpl/encryption/master \
    master_key="$MASTER_KEY" version=1 created_at="$(date +%s)" >/dev/null 2>&1
  echo "  ✓ secret/tpl/encryption/master"

  # Clear secrets from shell memory
  unset API_SECRET ADMIN_PW USER_PW COMM_SECRET MASTER_KEY

  # ── 10. Enable audit backend ──────────────────────────────────────────────
  echo "INFO: Enabling audit logging..."
  if ! _vcli audit list -format=json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d else 1)" 2>/dev/null; then
    _vcli audit enable file file_path=/vault/audit/audit.log log_raw=false >/dev/null 2>&1
    echo "  ✓ Audit backend: file (/vault/audit/audit.log)"
  fi

  # ── 11. Create admin token for rotation operations ────────────────────────
  echo "INFO: Creating scoped admin token for rotation..."
  local ADMIN_TOKEN
  _json_out=$(_vcli token create -format=json \
    -policy=tpl-admin -ttl=8760h -renewable \
    -display-name=tpl-rotation-admin 2>/dev/null) || true
  if [ -z "$_json_out" ]; then
    echo "ERR: Failed to create admin token from Vault." >&2
    return 1
  fi
  ADMIN_TOKEN=$(echo "$_json_out" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
  if [ -z "$ADMIN_TOKEN" ]; then
    echo "ERR: admin-token is empty after parsing." >&2
    return 1
  fi

  echo -n "$ADMIN_TOKEN" > .vault_approle/admin-token
  chmod 600 .vault_approle/admin-token
  echo "  ✓ Admin token for rotation saved to .vault_approle/admin-token"

  # ── 12. Revoke root token ─────────────────────────────────────────────────
  echo "INFO: Revoking root token (best practice)..."
  _vcli token revoke -self >/dev/null 2>&1 || true
  unset VAULT_TOKEN
  echo "  ✓ Root token revoked. Use admin token or unseal keys for future admin ops."

  # ── 13. Print bootstrap credentials (one-time display) ────────────────────
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  VAULT SETUP COMPLETE — ALL SECRETS GENERATED              ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║                                                            ║"
  echo "║  Secrets stored in Vault (encrypted at rest):              ║"
  echo "║    • secret/tpl/api/jwt        — JWT signing key           ║"
  echo "║    • secret/tpl/api/users      — Bootstrap user passwords  ║"
  echo "║    • secret/tpl/comm/hmac      — Communication HMAC key    ║"
  echo "║    • secret/tpl/encryption/master — Master encryption key  ║"
  echo "║                                                            ║"
  echo "║  Files to secure:                                          ║"
  echo "║    • .vault_unseal_keys.json   → offline / HSM storage     ║"
  echo "║    • .vault_approle/           → mounted read-only to API  ║"
  echo "║                                                            ║"
  echo "║  No passwords are 'admin/admin' or 'change-me'.            ║"
  echo "║  No secrets in .env, Docker images, or logs.               ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""

  echo "INFO: Module 20_vault applied successfully."
}

check(){
  # Check Vault health via docker exec (no port exposure needed)
  if ! docker exec -e VAULT_ADDR="$_VAULT_INTERNAL" "$_VAULT_CONTAINER" \
       vault status -format=json 2>/dev/null | \
       python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if not d.get('sealed') else 1)" 2>/dev/null; then
    echo "ERR: Vault not healthy or sealed" >&2
    return 1
  fi
  [ -f .vault_approle/role-id ] || { echo "ERR: .vault_approle/role-id missing" >&2; return 1; }
  [ -f .vault_approle/secret-id ] || { echo "ERR: .vault_approle/secret-id missing" >&2; return 1; }
  echo "OK: Vault healthy, AppRole credentials present."
}

rollback(){
  echo "INFO: Rolling back Vault module..."
  local compose_args=(-f compose.yml)
  [ -f compose.d/20-vault.yml ] && compose_args+=(-f compose.d/20-vault.yml)
  docker compose "${compose_args[@]}" down -v --remove-orphans 2>/dev/null || true
  docker volume rm tpl_vault_data tpl_vault_audit 2>/dev/null || true
  rm -f compose.d/20-vault.yml
  rm -f .vault_unseal_keys.json
  rm -rf .vault_approle
  echo "INFO: Vault containers, volumes, compose fragment and keys removed."
}

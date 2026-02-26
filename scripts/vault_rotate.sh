#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TPL Secret Rotation Script
#
# Rotates secrets in Vault without downtime:
#   1. Generates new cryptographic secret
#   2. Writes new version to Vault KV v2 (versioned — old stays for rollback)
#   3. Vault Agent detects change and re-templates to /run/secrets/
#   4. Vault Agent restarts the API process with new secrets
#
# Usage:
#   ./scripts/vault_rotate.sh <secret_name> [--force]
#
# Secret names: jwt | users | comm | master | all
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

# Load admin token
if [ -f .vault_approle/admin-token ]; then
  VAULT_TOKEN="$(cat .vault_approle/admin-token)"
elif [ -n "${VAULT_TOKEN:-}" ]; then
  : # use env
else
  echo "ERR: No admin token found. Set VAULT_TOKEN or ensure .vault_approle/admin-token exists." >&2
  exit 1
fi

export VAULT_ADDR VAULT_TOKEN

_rand(){ head -c "${1:-32}" /dev/urandom | base64 | tr -d '/+=\n' | head -c "${1:-32}"; }

_vault_write(){
  local path="$1" data="$2"
  curl -fs -X POST "${VAULT_ADDR}/v1/${path}" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$data" >/dev/null
}

_vault_read(){
  local path="$1"
  curl -fs "${VAULT_ADDR}/v1/${path}" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null
}

rotate_jwt(){
  echo "── Rotating JWT signing key (API_SECRET) ──"
  local new_secret; new_secret="$(_rand 48)"
  _vault_write "secret/data/tpl/api/jwt" \
    "{\"data\":{\"api_secret\":\"${new_secret}\",\"algorithm\":\"HS256\",\"rotated_at\":$(date +%s)}}"
  unset new_secret
  echo "  ✓ secret/tpl/api/jwt rotated (new version created)"
  echo "  NOTE: Existing JWTs signed with old key will be invalid."
  echo "        Vault Agent will restart API with new key automatically."
}

rotate_users(){
  echo "── Rotating bootstrap user passwords ──"
  local new_admin; new_admin="$(_rand 32)"
  local new_user; new_user="$(_rand 32)"
  _vault_write "secret/data/tpl/api/users" \
    "{\"data\":{\"admin_password\":\"${new_admin}\",\"user_password\":\"${new_user}\",\"rotated_at\":$(date +%s)}}"
  unset new_admin new_user
  echo "  ✓ secret/tpl/api/users rotated"
  echo "  NOTE: Only affects bootstrap/fallback passwords."
  echo "        Users in .tpl_users.json keep their own Argon2id hashes."
}

rotate_comm(){
  echo "── Rotating communication HMAC key (COMM_SHARED_SECRET) ──"
  local new_secret; new_secret="$(_rand 48)"
  _vault_write "secret/data/tpl/comm/hmac" \
    "{\"data\":{\"shared_secret\":\"${new_secret}\",\"rotated_at\":$(date +%s)}}"
  unset new_secret
  echo "  ✓ secret/tpl/comm/hmac rotated"
  echo "  NOTE: In-flight signed messages with old key will fail verification."
}

rotate_master(){
  echo "── Rotating master encryption key (TPL_MASTER_KEY) ──"
  # Read current version
  local current_version
  current_version=$(_vault_read "secret/data/tpl/encryption/master" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['data']['data'].get('version', 1))" 2>/dev/null || echo "1")
  local new_version=$((current_version + 1))
  local new_key; new_key="$(_rand 64)"
  _vault_write "secret/data/tpl/encryption/master" \
    "{\"data\":{\"master_key\":\"${new_key}\",\"version\":${new_version},\"rotated_at\":$(date +%s)}}"
  unset new_key
  echo "  ✓ secret/tpl/encryption/master rotated (v${current_version} → v${new_version})"
  echo "  NOTE: Data encrypted with old key must be re-encrypted."
  echo "        Use /api/encryption/rotate endpoint to re-encrypt stored data."
}

rotate_approle(){
  echo "── Rotating AppRole Secret ID ──"
  # Destroy current secret ID accessor (optional) and generate new
  local new_sid
  new_sid=$(curl -fs -X POST "${VAULT_ADDR}/v1/auth/approle/role/tpl-api/secret-id" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
  echo -n "$new_sid" > .vault_approle/secret-id
  chmod 600 .vault_approle/secret-id
  unset new_sid
  echo "  ✓ AppRole secret-id rotated"
  echo "  NOTE: Restart Vault Agent sidecar to pick up new secret-id."
}

revoke_secret(){
  local path="$1"
  echo "── Revoking secret: ${path} ──"
  # Delete all versions and metadata
  curl -fs -X DELETE "${VAULT_ADDR}/v1/secret/metadata/${path}" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" >/dev/null 2>&1
  echo "  ✓ ${path} — all versions permanently destroyed"
}

show_versions(){
  local path="$1"
  echo "── Version history: ${path} ──"
  local meta
  meta=$(_vault_read "secret/metadata/${path}" 2>/dev/null)
  if [ -n "$meta" ]; then
    echo "$meta" | python3 -c "
import sys, json
d = json.load(sys.stdin)['data']
versions = d.get('versions', {})
for v, info in sorted(versions.items(), key=lambda x: int(x[0])):
    state = 'destroyed' if info.get('destroyed') else ('deleted' if info.get('deletion_time') else 'active')
    print(f'  v{v}: created={info[\"created_time\"][:19]}  state={state}')
print(f'  current_version={d.get(\"current_version\", \"?\")}')
"
  else
    echo "  (no metadata found)"
  fi
}

SECRET="${1:-help}"
FORCE="${2:-}"

case "$SECRET" in
  jwt)     rotate_jwt ;;
  users)   rotate_users ;;
  comm)    rotate_comm ;;
  master)  rotate_master ;;
  approle) rotate_approle ;;
  all)
    echo "═══ Rotating ALL secrets ═══"
    rotate_jwt
    rotate_users
    rotate_comm
    rotate_master
    rotate_approle
    echo ""
    echo "═══ All secrets rotated ═══"
    echo "Vault Agent will restart the API automatically."
    ;;
  revoke)
    [ -n "${2:-}" ] || { echo "Usage: $0 revoke <vault_path>"; exit 1; }
    revoke_secret "$2"
    ;;
  versions)
    [ -n "${2:-}" ] || { echo "Usage: $0 versions <vault_path>  (e.g. tpl/api/jwt)"; exit 1; }
    show_versions "$2"
    ;;
  status)
    echo "═══ Vault Secret Status ═══"
    for p in tpl/api/jwt tpl/api/users tpl/comm/hmac tpl/encryption/master; do
      show_versions "$p"
    done
    ;;
  help|*)
    echo "TPL Secret Rotation"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  jwt       Rotate JWT signing key"
    echo "  users     Rotate bootstrap user passwords"
    echo "  comm      Rotate communication HMAC key"
    echo "  master    Rotate master encryption key"
    echo "  approle   Rotate Vault AppRole secret-id"
    echo "  all       Rotate ALL secrets at once"
    echo "  revoke <path>   Permanently destroy a secret (e.g. tpl/api/jwt)"
    echo "  versions <path> Show version history of a secret"
    echo "  status    Show version status of all secrets"
    echo ""
    echo "Vault Agent will automatically detect changes and restart the API."
    ;;
esac

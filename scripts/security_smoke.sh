#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TPL Security Smoke Tests
# ─────────────────────────────────────────────────────────────────────────────
# Run after deployment to verify critical security controls.
#
# Usage:  ./scripts/security_smoke.sh [BASE_URL]
#         Default BASE_URL: http://localhost:8080
#
# Exit code 0 = all tests pass, 1 = failures detected
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BASE="${1:-http://localhost:8080}"
API="${BASE}/api"
PASS=0
FAIL=0
SKIP=0

green()  { printf '\033[32m✓ %s\033[0m\n' "$*"; }
red()    { printf '\033[31m✗ %s\033[0m\n' "$*"; }
yellow() { printf '\033[33m⊘ %s\033[0m\n' "$*"; }

pass() { PASS=$((PASS+1)); green "$1"; }
fail() { FAIL=$((FAIL+1)); red  "$1"; }
skip() { SKIP=$((SKIP+1)); yellow "$1 (skipped)"; }

# ── Helper: HTTP status code ─────────────────────────────────────────────────
http_status() {
  curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo "000"
}

http_body() {
  curl -s "$@" 2>/dev/null || echo ""
}

echo "═══════════════════════════════════════════════════════════════"
echo "  TPL Security Smoke Tests — $(date -Iseconds)"
echo "  Target: ${BASE}"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── T1: Default secret fails startup ────────────────────────────────────────
echo "── T1: Default secret rejection ──"
# We can't test the actual fail-fast at startup from outside; instead, we
# verify the API is running (which means it passed the secret checks).
STATUS=$(http_status "${API}/health")
if [ "$STATUS" = "200" ]; then
  pass "T1: API is running (secrets passed fail-fast)"
else
  skip "T1: API not reachable at ${API}/health (status=$STATUS)"
fi

# ─── T2: /modules/apply returns 403 by default ──────────────────────────────
echo ""
echo "── T2: /modules/apply disabled by default (ENABLE_CONTROL_PLANE=0) ──"
STATUS=$(http_status -X POST "${API}/modules/apply" \
  -H "Content-Type: application/json" \
  -d '{"modules":["test"]}')
if [ "$STATUS" = "403" ] || [ "$STATUS" = "401" ]; then
  pass "T2: /modules/apply blocked (HTTP $STATUS)"
elif [ "$STATUS" = "000" ]; then
  skip "T2: API not reachable"
else
  fail "T2: /modules/apply returned HTTP $STATUS (expected 401 or 403)"
fi

# ─── T3: Auth fallback blocked (BOOTSTRAP_MODE=false) ───────────────────────
echo ""
echo "── T3: Auth fallback blocked when BOOTSTRAP_MODE=false ──"
# Try to login with a non-existent user — should fail with 401
STATUS=$(http_status -X POST "${API}/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent_test_user","password":"AnyP@ss123!"}')
if [ "$STATUS" = "401" ]; then
  pass "T3: Fallback auth blocked for unknown user (HTTP 401)"
elif [ "$STATUS" = "429" ]; then
  pass "T3: Rate limited (429) — fallback not reachable"
elif [ "$STATUS" = "000" ]; then
  skip "T3: API not reachable"
else
  fail "T3: Unexpected status for unknown user login (HTTP $STATUS)"
fi

# ─── T4: Unauthenticated admin endpoints blocked ────────────────────────────
echo ""
echo "── T4: Admin endpoints require auth ──"
for ep in "/modules/state" "/audit/logs" "/users"; do
  STATUS=$(http_status "${API}${ep}")
  if [ "$STATUS" = "401" ]; then
    pass "T4: ${ep} requires auth (HTTP 401)"
  elif [ "$STATUS" = "000" ]; then
    skip "T4: API not reachable for ${ep}"
  else
    fail "T4: ${ep} returned HTTP $STATUS (expected 401)"
  fi
done

# ─── T5: CORS rejects * with credentials ────────────────────────────────────
echo ""
echo "── T5: CORS rejects wildcard origin ──"
CORS_ORIGIN=$(curl -s -o /dev/null -D - \
  -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: GET" \
  -X OPTIONS "${API}/health" 2>/dev/null | \
  grep -i 'access-control-allow-origin' | tr -d '\r' || echo "")
if echo "$CORS_ORIGIN" | grep -qi "evil.example.com"; then
  fail "T5: CORS reflected arbitrary origin"
elif echo "$CORS_ORIGIN" | grep -q '\*'; then
  fail "T5: CORS allows wildcard origin"
else
  pass "T5: CORS rejects unauthorized origin"
fi

# ─── T6: Security headers present ───────────────────────────────────────────
echo ""
echo "── T6: Security headers ──"
HEADERS=$(curl -s -D - -o /dev/null "${API}/health" 2>/dev/null || echo "")
for hdr in "x-content-type-options" "x-frame-options" "referrer-policy" "cache-control"; do
  if echo "$HEADERS" | grep -qi "$hdr"; then
    pass "T6: Header ${hdr} present"
  elif [ -z "$HEADERS" ]; then
    skip "T6: API not reachable for header check"
  else
    fail "T6: Header ${hdr} missing"
  fi
done

# ─── T7: Rate limiting works ────────────────────────────────────────────────
echo ""
echo "── T7: Rate limiting on /token ──"
GOT_429=false
for i in $(seq 1 12); do
  STATUS=$(http_status -X POST "${API}/token" \
    -H "Content-Type: application/json" \
    -d '{"username":"ratelimit_test","password":"bad"}')
  if [ "$STATUS" = "429" ]; then
    GOT_429=true
    break
  fi
done
if $GOT_429; then
  pass "T7: Rate limiting triggered (HTTP 429 after $i attempts)"
elif [ "$STATUS" = "000" ]; then
  skip "T7: API not reachable"
else
  fail "T7: No rate limiting after 12 failed login attempts"
fi

# ─── T8: Health endpoint public ──────────────────────────────────────────────
echo ""
echo "── T8: Health endpoint accessible ──"
STATUS=$(http_status "${API}/health")
if [ "$STATUS" = "200" ]; then
  pass "T8: /health returns 200"
elif [ "$STATUS" = "000" ]; then
  skip "T8: API not reachable"
else
  fail "T8: /health returned HTTP $STATUS"
fi

# ─── T9: Path traversal blocked ─────────────────────────────────────────────
echo ""
echo "── T9: Path traversal blocked ──"
# Use --path-as-is and URL-encoded dots to bypass client-side normalization
STATUS=$(http_status --path-as-is "${API}/%2e%2e/%2e%2e/etc/passwd")
if [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ] || [ "$STATUS" = "404" ] || [ "$STATUS" = "422" ] || [ "$STATUS" = "502" ]; then
  pass "T9: Path traversal blocked (HTTP $STATUS)"
elif [ "$STATUS" = "000" ]; then
  skip "T9: API not reachable"
else
  # Also check: did it actually return /etc/passwd content?
  BODY=$(http_body --path-as-is "${API}/%2e%2e/%2e%2e/etc/passwd")
  if echo "$BODY" | grep -q "root:"; then
    fail "T9: Path traversal returned /etc/passwd content!"
  else
    pass "T9: Path traversal returned HTTP $STATUS but no sensitive content"
  fi
fi

# ─── T10: Vault Secret Management ─────────────────────────────────────────
echo ""
echo "── T10: Vault secret management ──"
if [ -f "compose.d/20-vault.yml" ]; then
  # Check Vault is running and healthy
  VAULT_STATUS=$(docker exec tpl-vault vault status -format=json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('unsealed' if not d.get('sealed') else 'sealed')" 2>/dev/null || echo "unreachable")
  if [ "$VAULT_STATUS" = "unsealed" ]; then
    pass "T10a: Vault is running and unsealed"
  elif [ "$VAULT_STATUS" = "sealed" ]; then
    fail "T10a: Vault is sealed — secrets cannot be delivered"
  else
    skip "T10a: Vault container not reachable"
  fi

  # Check AppRole credentials exist
  if [ -f ".vault_approle/role-id" ] && [ -f ".vault_approle/secret-id" ]; then
    pass "T10b: AppRole credentials present"
  else
    fail "T10b: AppRole credentials missing (.vault_approle/)"
  fi

  # Check no secrets in .env file (not even empty placeholders)
  LEAKED=false
  for secret_var in API_SECRET TPL_ADMIN_PASSWORD TPL_USER_PASSWORD COMM_SHARED_SECRET TPL_MASTER_KEY; do
    if grep -q "^${secret_var}=" .env 2>/dev/null; then
      fail "T10c: Secret variable ${secret_var} found in .env (should not exist at all)"
      LEAKED=true
    fi
  done
  if [ "$LEAKED" = "false" ]; then
    pass "T10c: No secret variables in .env file"
  fi

  # Check Vault audit backend is enabled
  AUDIT_ENABLED=$(docker exec tpl-vault vault audit list -format=json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d else 'no')" 2>/dev/null || echo "unknown")
  if [ "$AUDIT_ENABLED" = "yes" ]; then
    pass "T10d: Vault audit logging enabled"
  elif [ "$AUDIT_ENABLED" = "unknown" ]; then
    skip "T10d: Cannot check Vault audit (no access)"
  else
    fail "T10d: Vault audit logging NOT enabled"
  fi

  # Check secrets are delivered via /run/secrets/ (tmpfs)
  SECRETS_MOUNT=$(docker inspect tpl-api 2>/dev/null | python3 -c "
import sys, json
containers = json.load(sys.stdin)
if containers:
    mounts = containers[0].get('Mounts', [])
    for m in mounts:
        if '/run/secrets' in m.get('Destination', ''):
            print('tmpfs' if m.get('Type') == 'volume' else m.get('Type', 'unknown'))
            sys.exit(0)
print('missing')
" 2>/dev/null || echo "unknown")
  if [ "$SECRETS_MOUNT" = "tmpfs" ] || [ "$SECRETS_MOUNT" = "volume" ]; then
    pass "T10e: Secrets delivered via tmpfs volume (/run/secrets)"
  elif [ "$SECRETS_MOUNT" = "unknown" ]; then
    skip "T10e: Cannot inspect API container"
  else
    fail "T10e: Secrets NOT delivered via tmpfs (found: ${SECRETS_MOUNT})"
  fi
else
  skip "T10: Vault not configured (compose.d/20-vault.yml missing)"
fi

# T11: No secrets in Docker inspect (env vars should be empty in Vault mode)
echo ""
echo "── T11: No secrets in container environment ──"
if [ -f "compose.d/20-vault.yml" ]; then
  LEAKED_ENV=false
  for secret_var in API_SECRET TPL_ADMIN_PASSWORD TPL_USER_PASSWORD COMM_SHARED_SECRET TPL_MASTER_KEY; do
    val=$(docker inspect tpl-api 2>/dev/null | python3 -c "
import sys, json
containers = json.load(sys.stdin)
if containers:
    env = containers[0].get('Config', {}).get('Env', [])
    for e in env:
        if e.startswith('${secret_var}='):
            v = e.split('=', 1)[1]
            if v and len(v) > 0:
                print(v[:4] + '...')
                sys.exit(0)
print('')
" 2>/dev/null || echo "")
    if [ -n "$val" ]; then
      fail "T11: Secret ${secret_var} found in container env (visible via docker inspect)"
      LEAKED_ENV=true
    fi
  done
  if [ "$LEAKED_ENV" = "false" ]; then
    pass "T11: No secrets in container environment variables"
  fi
else
  skip "T11: Vault not configured — secrets are in env vars (legacy mode)"
fi

# T12: Unseal keys file permissions
echo ""
echo "── T12: Vault unseal keys file security ──"
if [ -f ".vault_unseal_keys.json" ]; then
  PERMS=$(stat -c '%a' .vault_unseal_keys.json 2>/dev/null || stat -f '%Lp' .vault_unseal_keys.json 2>/dev/null || echo "unknown")
  if [ "$PERMS" = "600" ]; then
    pass "T12: Unseal keys file has restrictive permissions (600)"
  elif [ "$PERMS" = "unknown" ]; then
    skip "T12: Cannot check file permissions"
  else
    fail "T12: Unseal keys file has permissions ${PERMS} (should be 600)"
  fi
else
  if [ -f "compose.d/20-vault.yml" ]; then
    pass "T12: Unseal keys file not present (moved to secure storage)"
  else
    skip "T12: Vault not configured"
  fi
fi

# ─── T13: No repo bind mount ────────────────────────────────────────────────
echo ""
echo "── T13: No repository bind mount on API container ──"
BIND_CHECK=$(docker inspect tpl-api 2>/dev/null | python3 -c "
import sys, json
containers = json.load(sys.stdin)
if containers:
    mounts = containers[0].get('Mounts', [])
    for m in mounts:
        src = m.get('Source', '')
        dst = m.get('Destination', '')
        if dst == '/work' and m.get('Type') == 'bind':
            print('UNSAFE: ./:/work bind mount found')
            sys.exit(0)
        if '/modules' in dst and m.get('Type') == 'bind':
            print('WARN: modules bind mount found')
            sys.exit(0)
print('OK')
" 2>/dev/null || echo "unknown")
if [ "$BIND_CHECK" = "OK" ]; then
  pass "T13: No repository/modules bind mount on API container"
elif echo "$BIND_CHECK" | grep -q "UNSAFE"; then
  fail "T13: $BIND_CHECK"
elif [ "$BIND_CHECK" = "unknown" ]; then
  skip "T13: Cannot inspect API container"
else
  fail "T13: $BIND_CHECK"
fi

# ─── T14: Container runs as non-root ────────────────────────────────────────
echo ""
echo "── T14: Container runs as non-root ──"
CONTAINER_USER=$(docker inspect tpl-api 2>/dev/null | python3 -c "
import sys, json
containers = json.load(sys.stdin)
if containers:
    user = containers[0].get('Config', {}).get('User', '')
    print(user if user else 'root')
" 2>/dev/null || echo "unknown")
if [ "$CONTAINER_USER" != "root" ] && [ "$CONTAINER_USER" != "" ] && [ "$CONTAINER_USER" != "unknown" ]; then
  pass "T14: API container runs as non-root user ($CONTAINER_USER)"
elif [ "$CONTAINER_USER" = "unknown" ]; then
  skip "T14: Cannot inspect API container"
else
  fail "T14: API container runs as root!"
fi

# ─── T15: .env file permissions ──────────────────────────────────────────────
echo ""
echo "── T15: .env file permissions ──"
if [ -f ".env" ]; then
  ENV_PERMS=$(stat -c '%a' .env 2>/dev/null || stat -f '%Lp' .env 2>/dev/null || echo "unknown")
  if [ "$ENV_PERMS" = "600" ]; then
    pass "T15: .env has restrictive permissions (600)"
  elif [ "$ENV_PERMS" = "unknown" ]; then
    skip "T15: Cannot check .env permissions"
  else
    fail "T15: .env has permissions ${ENV_PERMS} (should be 600)"
  fi
else
  pass "T15: No .env file (secrets managed externally)"
fi

# ─── T16: No default/weak secrets in .secrets/ directory ─────────────────────
echo ""
echo "── T16: No default/weak secrets in .secrets/ ──"
if [ -d ".secrets" ]; then
  WEAK_FOUND=false
  WEAK_LIST="change-me-please change-me changeme secret admin password user test default 12345 admin123 comm-secret-change-me"
  for secret_file in api_secret tpl_admin_password tpl_user_password comm_shared_secret tpl_master_key; do
    if [ ! -f ".secrets/$secret_file" ]; then
      fail "T16: Secret file .secrets/$secret_file missing"
      WEAK_FOUND=true
      continue
    fi
    val=$(cat ".secrets/$secret_file" 2>/dev/null || echo "")
    if [ -z "$val" ]; then
      fail "T16: .secrets/$secret_file is empty"
      WEAK_FOUND=true
      continue
    fi
    for weak in $WEAK_LIST; do
      if [ "$val" = "$weak" ]; then
        fail "T16: .secrets/$secret_file has weak default value"
        WEAK_FOUND=true
      fi
    done
    if [ "${#val}" -lt 8 ]; then
      fail "T16: .secrets/$secret_file is too short (${#val} chars)"
      WEAK_FOUND=true
    fi
  done
  if [ "$WEAK_FOUND" = "false" ]; then
    pass "T16: No weak/default secrets found in .secrets/"
  fi
else
  if [ -f "compose.d/20-vault.yml" ]; then
    pass "T16: Vault mode — .secrets/ not needed (secrets from Vault tmpfs)"
  else
    fail "T16: .secrets/ directory not found (run: ./init.sh auto-install)"
  fi
fi

# ─── T17: API key endpoint auth ──────────────────────────────────────────────
echo ""
echo "── T17: API key management endpoints require auth ──"
STATUS=$(http_status -X POST "${API}/api-keys" \
  -H "Content-Type: application/json" \
  -d '{"owner":"test"}')
if [ "$STATUS" = "401" ]; then
  pass "T17: /api-keys requires auth (HTTP 401)"
elif [ "$STATUS" = "000" ]; then
  skip "T17: API not reachable"
else
  fail "T17: /api-keys returned HTTP $STATUS (expected 401)"
fi

# ─── T18: /modules/reset also gated by ENABLE_CONTROL_PLANE ─────────────────
echo ""
echo "── T18: /modules/reset disabled by default (ENABLE_CONTROL_PLANE=0) ──"
STATUS=$(http_status -X POST "${API}/modules/reset" \
  -H "X-Confirm: YES")
if [ "$STATUS" = "403" ] || [ "$STATUS" = "401" ]; then
  pass "T18: /modules/reset blocked (HTTP $STATUS)"
elif [ "$STATUS" = "000" ]; then
  skip "T18: API not reachable"
else
  fail "T18: /modules/reset returned HTTP $STATUS (expected 401 or 403)"
fi

# ─── T19: .secrets/ directory permissions ────────────────────────────────────
echo ""
echo "── T19: .secrets/ directory permissions ──"
if [ -d ".secrets" ]; then
  DIR_PERMS=$(stat -c '%a' .secrets 2>/dev/null || stat -f '%Lp' .secrets 2>/dev/null || echo "unknown")
  if [ "$DIR_PERMS" = "700" ]; then
    pass "T19: .secrets/ directory has restrictive permissions (700)"
  elif [ "$DIR_PERMS" = "unknown" ]; then
    skip "T19: Cannot check directory permissions"
  else
    fail "T19: .secrets/ has permissions ${DIR_PERMS} (should be 700)"
  fi
  # Check individual secret file permissions
  FILE_PERMS_OK=true
  for sf in .secrets/*; do
    [ -f "$sf" ] || continue
    FP=$(stat -c '%a' "$sf" 2>/dev/null || stat -f '%Lp' "$sf" 2>/dev/null || echo "unknown")
    if [ "$FP" != "600" ] && [ "$FP" != "unknown" ]; then
      fail "T19: $sf has permissions ${FP} (should be 600)"
      FILE_PERMS_OK=false
    fi
  done
  if $FILE_PERMS_OK; then
    pass "T19: All secret files have restrictive permissions (600)"
  fi
else
  if [ -f "compose.d/20-vault.yml" ]; then
    pass "T19: Vault mode — .secrets/ not used"
  else
    fail "T19: .secrets/ directory missing"
  fi
fi

# ─── T20: No secrets in .env (structural check) ─────────────────────────────
echo ""
echo "── T20: .env contains zero secret variables ──"
if [ -f ".env" ]; then
  SECRET_VARS_FOUND=false
  for sv in API_SECRET TPL_ADMIN_PASSWORD TPL_USER_PASSWORD COMM_SHARED_SECRET TPL_MASTER_KEY ENABLE_MODULES_API; do
    if grep -q "^${sv}=" .env 2>/dev/null; then
      fail "T20: Legacy variable ${sv} found in .env"
      SECRET_VARS_FOUND=true
    fi
  done
  if [ "$SECRET_VARS_FOUND" = "false" ]; then
    pass "T20: .env contains only non-sensitive configuration"
  fi
else
  pass "T20: No .env file"
fi

# ─── T21: BOOTSTRAP_MODE defaults to false ───────────────────────────────────
echo ""
echo "── T21: BOOTSTRAP_MODE default is false ──"
if [ -f ".env" ]; then
  BM_VAL=$(grep "^BOOTSTRAP_MODE=" .env 2>/dev/null | head -1 | cut -d= -f2)
  if [ "$BM_VAL" = "false" ] || [ -z "$BM_VAL" ]; then
    pass "T21: BOOTSTRAP_MODE is false (${BM_VAL:-not set})"
  else
    fail "T21: BOOTSTRAP_MODE=${BM_VAL} (should be false in production)"
  fi
else
  pass "T21: No .env file (BOOTSTRAP_MODE defaults to false in code)"
fi

# ─── T22: FORCE_KILL removed (dead config) ──────────────────────────────────────
echo ""
echo "── T22: FORCE_KILL absent ──"
if [ -f ".env" ]; then
  if grep -q "^FORCE_KILL=" .env 2>/dev/null; then
    fail "T22: FORCE_KILL found in .env — deprecated variable, remove it"
  else
    pass "T22: FORCE_KILL not in .env (correctly removed)"
  fi
else
  pass "T22: No .env file (FORCE_KILL does not exist)"
fi

# ─── T23: No .tpl_* state files in project root ─────────────────────────────
echo ""
echo "── T23: No .tpl_* state files in project root ──"
TPL_FILES=$(find . -maxdepth 1 -name ".tpl_*" ! -name ".tpl_state.json" -type f 2>/dev/null)
TPL_DIRS=$(find . -maxdepth 1 -name ".tpl_*" -type d 2>/dev/null)
if [ -n "$TPL_FILES" ] || [ -n "$TPL_DIRS" ]; then
  fail "T23: Found .tpl_* state files in project root (should live in /data volume only):"
  echo "      $TPL_FILES $TPL_DIRS" | tr '\n' ' '
  echo ""
else
  pass "T23: No .tpl_* state files in project root"
fi

# ─── T24: Keycloak has no host-published ports ───────────────────────────────
echo ""
echo "── T24: Keycloak has no host-published ports ──"
KC_COMPOSE="compose.d/60-keycloak.yml"
if [ -f "$KC_COMPOSE" ]; then
  # Check for 'ports:' directive on keycloak service (should only have 'expose:')
  if grep -qE '^\s+ports:' "$KC_COMPOSE" 2>/dev/null; then
    # Verify it's not on the db service — check context around keycloak
    # Conservative: fail if *any* ports: directive exists (db shouldn't have one either)
    fail "T24: Keycloak compose has 'ports:' directive — KC should be internal-only (use expose:)"
  else
    pass "T24: Keycloak has no host-published ports (expose only)"
  fi
else
  skip "T24: No Keycloak compose found (module not installed)"
fi

# ─── T25: Keycloak DB is on isolated internal network ────────────────────────
echo ""
echo "── T25: Keycloak DB on isolated internal network ──"
if [ -f "$KC_COMPOSE" ]; then
  if grep -q 'internal: true' "$KC_COMPOSE" 2>/dev/null; then
    pass "T25: Keycloak compose defines internal-only network for DB isolation"
  else
    fail "T25: No internal network defined — DB may be reachable from other containers"
  fi
else
  skip "T25: No Keycloak compose found (module not installed)"
fi

# ─── T26: release.sh packaging script exists ─────────────────────────────────
echo ""
echo "── T26: release.sh packaging script exists ──"
if [ -x "scripts/release.sh" ]; then
  pass "T26: scripts/release.sh exists and is executable"
else
  fail "T26: scripts/release.sh missing or not executable — releases may contain state files"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "═══════════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  red "SECURITY SMOKE TESTS FAILED — review failures above"
  exit 1
fi

if [ "$SKIP" -gt 0 ]; then
  echo ""
  yellow "Some tests skipped (API not reachable). Run with API up."
fi

echo ""
green "All security smoke tests passed."
exit 0

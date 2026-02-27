#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# TPL Integration Smoke Test — compose up → health → full endpoint → teardown
# ═══════════════════════════════════════════════════════════════════════════════
# Usage:
#   ./scripts/test_integration.sh         # full test (start → test → stop)
#   ./scripts/test_integration.sh --skip-up   # assume services running
#   ./scripts/test_integration.sh --skip-down # leave services running after
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

SKIP_UP=false
SKIP_DOWN=false
for arg in "$@"; do
  case "$arg" in
    --skip-up)   SKIP_UP=true ;;
    --skip-down) SKIP_DOWN=true ;;
  esac
done

BASE="https://localhost:8443"
API="$BASE/api"
PASS=0; FAIL=0; WARN=0; TOTAL=0

red()    { printf '\033[31m✗ %s\033[0m\n' "$*"; }
green()  { printf '\033[32m✓ %s\033[0m\n' "$*"; }
yellow() { printf '\033[33m⊘ %s\033[0m\n' "$*"; }

check() {
  local label="$1" expected="$2" actual="$3"
  TOTAL=$((TOTAL+1))
  if [[ "$actual" =~ $expected ]]; then
    green "$label (HTTP $actual)"
    PASS=$((PASS+1))
  else
    red "$label (expected ~$expected got $actual)"
    FAIL=$((FAIL+1))
  fi
}

_http() { curl -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  TPL Integration Smoke Test — $(date -Iseconds)"
echo "═══════════════════════════════════════════════════════════════"

# ── PHASE 1: Start services ──────────────────────────────────────────
if [[ "$SKIP_UP" = false ]]; then
  echo ""
  echo "── Phase 1: Starting services ──"
  bash "$ROOT/run.sh" up 2>&1 | tail -5
  echo "Waiting for services to become healthy..."
  for i in $(seq 1 30); do
    STATUS=$(_http "$API/health")
    [[ "$STATUS" = "200" ]] && break
    sleep 2
  done
fi

# ── PHASE 2: Health & readiness ──────────────────────────────────────
echo ""
echo "── Phase 2: Health & readiness ──"
check "API /health"     "200" "$(_http "$API/health")"
check "API /status"     "200" "$(_http "$API/status")"
check "Web / (login)"   "200" "$(_http "$BASE/")"
check "Web /styles.css" "200" "$(_http "$BASE/styles.css")"
check "Web /landing.js" "200" "$(_http "$BASE/landing.js")"

# ── PHASE 3: Auth flow ──────────────────────────────────────────────
echo ""
echo "── Phase 3: Authentication ──"
PASS_FILE="$ROOT/.secrets/tpl_admin_password"
if [[ -f "$PASS_FILE" ]]; then
  ADMIN_PASS="$(cat "$PASS_FILE")"
else
  ADMIN_PASS="${TPL_ADMIN_PASSWORD:-}"
fi

if [[ -z "$ADMIN_PASS" ]]; then
  yellow "Cannot read admin password — skipping auth tests"
  WARN=$((WARN+1))
else
  # Login
  LOGIN_RESP=$(curl -sk -X POST "$API/token" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" 2>/dev/null)
  TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

  if [[ -n "$TOKEN" ]]; then
    green "Login succeeded (got JWT)"
    PASS=$((PASS+1)); TOTAL=$((TOTAL+1))

    AUTH="-H Authorization:Bearer $TOKEN"

    # ── PHASE 4: Authenticated endpoints ───────────────────────────
    echo ""
    echo "── Phase 4: Authenticated endpoints ──"

    for ep in "/me" "/modules/state" "/audit/logs" "/users" "/secrets/status" \
              "/comm/status" "/encryption/status" "/security/status" "/version/info" \
              "/lang/strings?lang=it" "/resilience/health" "/router/routes" \
              "/diagnosis/run" "/api-keys"; do
      check "GET $ep" "200" "$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$API$ep" 2>/dev/null)"
      sleep 0.1
    done

    # ── PHASE 5: Security controls ──────────────────────────────────
    echo ""
    echo "── Phase 5: Security controls ──"
    # Unauthenticated access must be blocked
    check "Unauth /users"        "401" "$(_http "$API/users")"
    check "Unauth /audit/logs"   "401" "$(_http "$API/audit/logs")"
    check "Unauth /secrets/status" "401" "$(_http "$API/secrets/status")"
    # Control plane disabled
    check "POST /modules/apply"  "40[13]" "$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d '{"modules":["test"]}' "$API/modules/apply" 2>/dev/null)"
    # Bad credentials
    check "Bad creds"            "401" "$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
      -H 'Content-Type: application/json' -d '{"username":"admin","password":"WRONG"}' \
      "$API/token" 2>/dev/null)"
  else
    red "Login failed — skipping authenticated tests"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
  fi
fi

# ── PHASE 6: Frontend pages ────────────────────────────────────────
echo ""
echo "── Phase 6: Frontend pages ──"
for page in "/" "/login.html" "/dashboard.html" "/advanced.html" "/admin-modules.html"; do
  check "Web: $page" "200" "$(_http "$BASE$page")"
done

# ── PHASE 7: Teardown ─────────────────────────────────────────────
if [[ "$SKIP_DOWN" = false && "$SKIP_UP" = false ]]; then
  echo ""
  echo "── Phase 7: Teardown ──"
  bash "$ROOT/run.sh" down 2>&1 | tail -3
  green "Services stopped"
fi

# ── RESULTS ─────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $WARN warnings, $FAIL failed"
echo "  TOTAL:   $TOTAL checks"
echo "═══════════════════════════════════════════════════════════════"
echo ""

[[ $FAIL -gt 0 ]] && exit 1
exit 0

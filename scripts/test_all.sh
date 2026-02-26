#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=$(cat .secrets/tpl_admin_password)
TOKEN=$(curl -sk https://localhost:8443/api/token -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

B="https://localhost:8443/api"
OK=0; FAIL=0; WARN=0

t() {
  local label="$1" url="$2" method="${3:-GET}" body="${4:-}"
  local resp code
  if [[ "$method" == "POST" && -n "$body" ]]; then
    resp=$(curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -X POST -d "$body" -w '\n%{http_code}' "$url" 2>/dev/null)
  elif [[ "$method" == "POST" ]]; then
    resp=$(curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -X POST -w '\n%{http_code}' "$url" 2>/dev/null)
  else
    resp=$(curl -sk -H "Authorization: Bearer $TOKEN" -w '\n%{http_code}' "$url" 2>/dev/null)
  fi
  code=$(echo "$resp" | tail -1)
  local snippet
  snippet=$(echo "$resp" | sed '$d' | head -c 150)
  if [[ "$code" =~ ^2 ]]; then
    echo "  ✓ $label ($code)"
    OK=$((OK+1))
  elif [[ "$code" =~ ^4 ]]; then
    echo "  ⚠ $label ($code) ${snippet}"
    WARN=$((WARN+1))
  else
    echo "  ✗ $label ($code) ${snippet}"
    FAIL=$((FAIL+1))
  fi
  sleep 0.15  # avoid rate-limit exhaustion
}

echo "═══════════════════════════════════════════════════════"
echo "  TPL PLATFORM — COMPREHENSIVE FUNCTIONALITY TEST"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── 1. INFRASTRUCTURE ──────────────────────────────────"
t "Health"           "$B/health"
t "Status"           "$B/status"
t "OpenAPI schema"   "$B/openapi.json"

echo ""
echo "── 2. AUTH & SESSION ──────────────────────────────────"
t "Login (token)"    "$B/token" POST "{\"username\":\"admin\",\"password\":\"$PASS\"}"
t "Me (profile)"     "$B/me"

echo ""
echo "── 3. USER MANAGEMENT ─────────────────────────────────"
t "List users"       "$B/users"
t "Get admin user"   "$B/users/admin"
t "Available roles"  "$B/users/roles/available"
t "My profile"       "$B/users/me/profile"
t "Users stats"      "$B/users/stats/summary"

echo ""
echo "── 4. MODULES & DISTRIBUTION ──────────────────────────"
t "Module state"     "$B/modules/state"
t "Module bundle"    "$B/modules/bundle"
t "Releases"         "$B/modules/releases"
t "Update history"   "$B/modules/update-history"
t "Security check"   "$B/modules/security-checklist"
t "Integrity"        "$B/modules/integrity"
t "Distro config"    "$B/modules/distribution-config"

echo ""
echo "── 5. VERSION MANAGER ─────────────────────────────────"
t "Version info"     "$B/version/info"
t "Version modules"  "$B/version/modules"
t "Version engines"  "$B/version/engines"
t "Changelog"        "$B/version/changelog"
t "Dependencies"     "$B/version/dependencies"
t "Rollback points"  "$B/version/rollback-points"

echo ""
echo "── 6. LANGUAGE ENGINE ─────────────────────────────────"
t "Lang strings"     "$B/lang/strings?lang=it"
t "Lang catalog"     "$B/lang/catalog"
t "Supported langs"  "$B/lang/supported"
t "Lang keys"        "$B/lang/keys"
t "Lang health"      "$B/lang/health"

echo ""
echo "── 7. COMMUNICATION ENGINE ────────────────────────────"
t "Comm status"      "$B/comm/status"
t "Comm logs"        "$B/comm/logs"
t "Comm subscribers" "$B/comm/subscribers"

echo ""
echo "── 8. ENCRYPTION ENGINE ───────────────────────────────"
t "Encryption status"    "$B/encryption/status"
t "Encryption benchmark" "$B/encryption/benchmark"
t "Encrypt test"    "$B/encryption/encrypt" POST '{"plaintext":"test-data-123","context":"test"}'
t "Hash test"       "$B/encryption/hash" POST '{"data":"hello-world"}'
t "Sign test"       "$B/encryption/sign" POST '{"message":"sign-me"}'
t "Token gen"       "$B/encryption/token" POST '{"payload":{"user":"test"}}'

echo ""
echo "── 9. SECURITY ENGINE ─────────────────────────────────"
t "Security status"  "$B/security/status"
t "Security alerts"  "$B/security/alerts"
t "WAF status"       "$B/security/waf"
t "IP lists"         "$B/security/ip/lists"
t "Firewall rules"   "$B/security/firewall"
t "Integrity check"  "$B/security/integrity"
t "Bruteforce stats" "$B/security/bruteforce"
t "Threat timeline"  "$B/security/threats/timeline"
t "Security score"   "$B/security/score"

echo ""
echo "── 10. LOG ENGINE ─────────────────────────────────────"
t "Audit logs"       "$B/audit/logs"
t "Log event write"  "$B/log/events" POST '{"event":"test event","level":"info","source":"test_script","message":"test log"}'
t "Log events read"  "$B/log/events"

echo ""
echo "── 11. AI LOG ANALYSIS ────────────────────────────────"
t "AI log analysis"  "$B/ai/log-analysis"

echo ""
echo "── 12. RESILIENCE ENGINE ──────────────────────────────"
t "Resil health"     "$B/resilience/health"
t "Resil readiness"  "$B/resilience/readiness"
t "Resil resources"  "$B/resilience/resources"
t "Resil status"     "$B/resilience/status"
t "Resil backups"    "$B/resilience/backups"

echo ""
echo "── 13. ROUTER MANAGER ─────────────────────────────────"
t "Routes"           "$B/router/routes"
t "Router status"    "$B/router/status"
t "Router alerts"    "$B/router/alerts"
t "Heal log"         "$B/router/heal-log"
t "Circuit breakers" "$B/router/circuit-breakers"
t "Topology"         "$B/router/topology"
t "Route map"        "$B/r/map"

echo ""
echo "── 14. SELF DIAGNOSIS ─────────────────────────────────"
t "Diagnosis run"    "$B/diagnosis/run"
t "Correlate"        "$B/diagnosis/correlate"
t "Engines list"     "$B/diagnosis/engines"
t "Config drift"     "$B/diagnosis/config-drift"
t "Recommendations"  "$B/diagnosis/recommendations"
t "Report"           "$B/diagnosis/report"
t "Diag metrics"     "$B/diagnosis/metrics"

echo ""
echo "── 15. TEMPLATE MANAGER ───────────────────────────────"
t "Template list"    "$B/template/list"
t "Template status"  "$B/template/status"

echo ""
echo "── 16. SECRETS & API KEYS ─────────────────────────────"
t "Secrets status"   "$B/secrets/status"
t "API keys list"    "$B/api-keys"

echo ""
echo "── 17. FRONTEND PAGES ─────────────────────────────────"
FB="https://localhost:8443"
for page in "/" "/login.html" "/dashboard.html" "/advanced.html" "/admin-modules.html"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$FB$page")
  if [[ "$code" =~ ^2 ]]; then
    echo "  ✓ Web: $page ($code)"
    OK=$((OK+1))
  else
    echo "  ✗ Web: $page ($code)"
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  RESULTS: $OK passed, $WARN warnings, $FAIL failed"
echo "  TOTAL:   $((OK+WARN+FAIL)) endpoints tested"
echo "═══════════════════════════════════════════════════════"

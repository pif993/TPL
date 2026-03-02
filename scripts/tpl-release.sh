#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# TPL Release Manager — Automated Change Detection & OTA Release
# ═══════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/tpl-release.sh                  # Full release pipeline
#   ./scripts/tpl-release.sh scan             # Scan for changes only
#   ./scripts/tpl-release.sh release          # Create release (stage + manifest)
#   ./scripts/tpl-release.sh install          # Run install pipeline (start+apply+finalize)
#   ./scripts/tpl-release.sh snapshot         # Take new baseline snapshot
#   ./scripts/tpl-release.sh status           # Show registry status
#   ./scripts/tpl-release.sh history          # Show release history
#   ./scripts/tpl-release.sh full             # Full: release + install pipeline
#
# Options:
#   --codename NAME    Set release codename (e.g. "Fusion")
#   --bump TYPE        Version bump: patch (default), minor, major
#   --dry              Dry run: scan only, don't create release
#   --yes              Skip confirmation prompts
#
# Environment:
#   TPL_API_URL        API base URL (default: https://localhost:8443)
#   TPL_USER           API username (default: admin)
#   TPL_PASS           API password
#
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Configuration ─────────────────────────────────────────────────────
API_URL="${TPL_API_URL:-https://localhost:8443}"
API_USER="${TPL_USER:-admin}"
API_PASS="${TPL_PASS:-}"
CODENAME=""
BUMP="patch"
DRY_RUN=false
AUTO_YES=false
ACTION="${1:-full}"

# ── Parse arguments ───────────────────────────────────────────────────
shift 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --codename) CODENAME="$2"; shift 2 ;;
        --bump)     BUMP="$2"; shift 2 ;;
        --dry)      DRY_RUN=true; shift ;;
        --yes|-y)   AUTO_YES=true; shift ;;
        *)          shift ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────
log()   { echo -e "${BLUE}[TPL]${NC} $*"; }
ok()    { echo -e "${GREEN}  ✓${NC} $*"; }
warn()  { echo -e "${YELLOW}  ⚠${NC} $*"; }
err()   { echo -e "${RED}  ✗${NC} $*"; }
header() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

# ── Get auth token ────────────────────────────────────────────────────
get_token() {
    if [[ -z "$API_PASS" ]]; then
        # Try to read from .env or prompt
        if [[ -f .env ]] && grep -q "TPL_ADMIN_PASS" .env 2>/dev/null; then
            API_PASS=$(grep "TPL_ADMIN_PASS" .env | cut -d= -f2 | tr -d '"')
        else
            echo -ne "${YELLOW}Password per ${API_USER}: ${NC}"
            read -rs API_PASS
            echo
        fi
    fi

    TOKEN=$(curl -sk -X POST "${API_URL}/api/token" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"${API_USER}\",\"password\":\"${API_PASS}\"}" \
        2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

    if [[ -z "$TOKEN" ]]; then
        err "Autenticazione fallita"
        exit 1
    fi
    ok "Autenticato come ${API_USER}"
}

# ── API call helper ───────────────────────────────────────────────────
api_get() {
    curl -sk -H "Authorization: Bearer $TOKEN" "${API_URL}/api${1}" 2>/dev/null
}

api_post() {
    local data="${2:-{}}"
    curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d "$data" "${API_URL}/api${1}" 2>/dev/null
}

# ── Commands ──────────────────────────────────────────────────────────

cmd_status() {
    header "Registry Status"
    get_token
    local status
    status=$(api_get "/ota/registry/status")
    echo "$status" | python3 -c "
import json, sys
s = json.load(sys.stdin)
print(f'  Versione baseline:  {s.get(\"baseline_version\", \"nessuna\")}')
print(f'  File tracciati:     {s.get(\"total_tracked\", 0)}')
print(f'  File nel baseline:  {s.get(\"total_baseline\", 0)}')
print(f'  Modificati:         {s.get(\"changed\", 0)}')
print(f'  Nuovi:              {s.get(\"new\", 0)}')
print(f'  Eliminati:          {s.get(\"deleted\", 0)}')
print(f'  Ha modifiche:       {\"Sì\" if s.get(\"has_changes\") else \"No\"}')
cats = s.get('categories', {})
if cats:
    print(f'  Per categoria:      {cats}')
lr = s.get('last_release')
if lr:
    print(f'  Ultimo rilascio:    {lr.get(\"version\")} ({lr.get(\"codename\",\"\")})')
"
}

cmd_scan() {
    header "Scansione Modifiche"
    get_token
    local diff
    diff=$(api_post "/ota/registry/scan")
    echo "$diff" | python3 -c "
import json, sys
d = json.load(sys.stdin)
s = d.get('summary', {})
print(f'  Baseline: {d.get(\"baseline_version\", \"nessuno\")}')
print(f'  Modificati: {s.get(\"changed\", 0)}  |  Nuovi: {s.get(\"new\", 0)}  |  Eliminati: {s.get(\"deleted\", 0)}')
print()
for f in d.get('changed', []):
    delta = f.get('size_delta', 0)
    sign = '+' if delta >= 0 else ''
    print(f'  \033[33m~\033[0m {f[\"path\"]}  [{f[\"category\"]}]  {sign}{delta}B')
for f in d.get('new', []):
    print(f'  \033[32m+\033[0m {f[\"path\"]}  [{f[\"category\"]}]  {f[\"size\"]}B')
for f in d.get('deleted', []):
    print(f'  \033[31m-\033[0m {f[\"path\"]}  [{f[\"category\"]}]')
if not d.get('has_changes'):
    print('  Nessuna modifica rilevata.')
"
}

cmd_snapshot() {
    header "Baseline Snapshot"
    get_token
    local result
    result=$(api_post "/ota/registry/snapshot")
    echo "$result" | python3 -c "
import json, sys
r = json.load(sys.stdin)
print(f'  File tracciati: {r.get(\"files_tracked\", 0)}')
print(f'  Versione:       {r.get(\"baseline_version\", \"\")}')
print(f'  {r.get(\"message\", \"\")}')
"
    ok "Baseline aggiornato"
}

cmd_release() {
    header "Creazione Release"
    get_token

    # First scan to show what will be released
    log "Scansione modifiche..."
    local diff
    diff=$(api_post "/ota/registry/scan")
    local has_changes
    has_changes=$(echo "$diff" | python3 -c "import json,sys; print(json.load(sys.stdin).get('has_changes', False))")

    if [[ "$has_changes" != "True" ]]; then
        warn "Nessuna modifica da rilasciare."
        return 0
    fi

    echo "$diff" | python3 -c "
import json, sys
d = json.load(sys.stdin)
s = d.get('summary', {})
print(f'  Modifiche trovate: {s[\"changed\"]} modificati, {s[\"new\"]} nuovi, {s[\"deleted\"]} eliminati')
for f in d.get('changed', [])[:10]:
    print(f'    ~ {f[\"path\"]}')
for f in d.get('new', [])[:10]:
    print(f'    + {f[\"path\"]}')
"

    if [[ "$DRY_RUN" == true ]]; then
        warn "Dry run — nessuna release creata"
        return 0
    fi

    if [[ "$AUTO_YES" != true ]]; then
        echo -ne "\n${YELLOW}Creare release (bump: ${BUMP})? [y/N] ${NC}"
        read -r confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            warn "Annullato"
            return 0
        fi
    fi

    # Build release request body
    local req_body="{\"bump\":\"${BUMP}\""
    if [[ -n "$CODENAME" ]]; then
        req_body="${req_body},\"codename\":\"${CODENAME}\""
    fi
    req_body="${req_body}}"

    log "Creazione release (bump: ${BUMP})..."
    local result
    result=$(api_post "/ota/registry/release" "$req_body")
    local status
    status=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))")

    if [[ "$status" == "staged" ]]; then
        echo "$result" | python3 -c "
import json, sys
r = json.load(sys.stdin)
print(f'  Versione:   {r[\"version\"]} (da {r[\"from_version\"]})')
print(f'  Codename:   {r.get(\"codename\", \"\")}')
print(f'  File:       {r[\"files_count\"]}')
print(f'  Categorie:  {r.get(\"categories\", {})}')
for f in r.get('files_staged', []):
    print(f'    ✓ {f}')
"
        ok "Release creata e staged"
        # Return version for pipeline
        echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version',''))"
    else
        echo "$result" | python3 -m json.tool
        err "Release non creata: $status"
        return 1
    fi
}

cmd_install() {
    local version="$1"
    header "Install Pipeline: ${version}"
    get_token

    # Step 1: start
    log "Step 1/3: install/start/${version}..."
    local start_result
    start_result=$(api_post "/ota/install/start/${version}")
    local start_status
    start_status=$(echo "$start_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [[ "$start_status" != "ready" ]]; then
        echo "$start_result" | python3 -m json.tool 2>/dev/null
        err "install/start fallito: $start_status"
        return 1
    fi
    ok "Install ready"

    # Step 2: apply
    log "Step 2/3: install/apply..."
    local apply_result
    apply_result=$(api_post "/ota/install/apply")
    local apply_status
    apply_status=$(echo "$apply_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [[ "$apply_status" != "applied" ]]; then
        echo "$apply_result" | python3 -m json.tool 2>/dev/null
        err "install/apply fallito: $apply_status"
        return 1
    fi
    local applied_count
    applied_count=$(echo "$apply_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('applied_files',0))" 2>/dev/null)
    ok "Applied: ${applied_count} file"

    # Step 3: finalize
    log "Step 3/3: install/finalize..."
    local finalize_result
    finalize_result=$(api_post "/ota/install/finalize")
    local fin_status
    fin_status=$(echo "$finalize_result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [[ "$fin_status" != "finalized" ]]; then
        echo "$finalize_result" | python3 -m json.tool 2>/dev/null
        err "install/finalize fallito: $fin_status"
        return 1
    fi
    ok "Finalized"

    echo ""
    ok "${BOLD}OTA ${version} installato con successo!${NC}"
}

cmd_history() {
    header "Release History"
    get_token
    api_get "/ota/registry/history" | python3 -c "
import json, sys
h = json.load(sys.stdin)
print(f'  Totale rilasci: {h.get(\"total\", 0)}\n')
for r in reversed(h.get('history', [])):
    cn = f' «{r[\"codename\"]}»' if r.get('codename') else ''
    print(f'  {r[\"version\"]}{cn}  ({r.get(\"released_at\",\"\")[:19]})')
    print(f'    da {r.get(\"from_version\",\"?\")} → {r.get(\"files_count\",0)} file  {r.get(\"categories\",{})}')
"
}

cmd_full() {
    header "TPL Full Release Pipeline"

    # Phase 1: Scan
    cmd_scan

    if [[ "$DRY_RUN" == true ]]; then
        warn "Dry run completo"
        return 0
    fi

    # Phase 2: Release (captures version from last line of output)
    local release_output
    release_output=$(cmd_release)
    local new_version
    new_version=$(echo "$release_output" | tail -1)

    if [[ -z "$new_version" || "$new_version" == *"Nessuna"* || "$new_version" == *"Annullato"* ]]; then
        return 0
    fi

    # Phase 3: Install pipeline
    cmd_install "$new_version"

    echo ""
    header "Release ${new_version} completata!"
}

# ── Main ──────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   TPL Release Manager v1.0           ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

case "$ACTION" in
    scan)       cmd_scan ;;
    release)    cmd_release ;;
    install)
        # Need version argument
        VERSION="${2:-}"
        if [[ -z "$VERSION" ]]; then
            err "Specificare la versione: ./scripts/tpl-release.sh install 3.5.5"
            exit 1
        fi
        cmd_install "$VERSION"
        ;;
    snapshot)   cmd_snapshot ;;
    status)     cmd_status ;;
    history)    cmd_history ;;
    full|"")    cmd_full ;;
    *)
        echo "Uso: $0 {scan|release|install|snapshot|status|history|full} [opzioni]"
        exit 1
        ;;
esac

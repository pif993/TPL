#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# TPL Migration Runner — Executes version-specific data/config migrations
#
# Usage (called by ota_update.sh or ota_update_engine.py):
#   bash migrations/run_migrations.sh <current_ver> <target_ver> <phase> [project_root]
#
# Phases:
#   pre   — runs BEFORE files are replaced (data prep, renames)
#   post  — runs AFTER files are replaced (cache clear, permissions, schema)
#
# Each version can have:
#   migrations/<ver>/migrate.sh   — main migration script
#   migrations/<ver>/meta.json    — metadata (optional, for auditing)
#   migrations/<ver>/rollback.sh  — rollback script (optional)
#
# Exit codes:
#   0 = all migrations OK
#   1 = migration failed (caller should abort/rollback)
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

MIGRATIONS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TPL_ROOT="${4:-$(cd "$MIGRATIONS_DIR/.." && pwd)}"
CURRENT_VER="${1:?Usage: run_migrations.sh <current_ver> <target_ver> <phase>}"
TARGET_VER="${2:?}"
PHASE="${3:?}"  # pre or post

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log() { echo -e "${GREEN}[MIGRATE]${NC} $*"; }
warn() { echo -e "${YELLOW}[MIGRATE]${NC} $*"; }
err() { echo -e "${RED}[MIGRATE]${NC} $*" >&2; }

# ── Semver parser ─────────────────────────────────────────────────────
# Converts "v3.4.1" → "3 4 1" for comparison
semver_parts() {
  local v="${1#v}"
  local major minor patch
  IFS='.' read -r major minor patch <<< "${v%%[-+]*}"
  echo "${major:-0} ${minor:-0} ${patch:-0}"
}

# Returns: -1 if a<b, 0 if a==b, 1 if a>b
semver_compare() {
  local a_parts b_parts
  read -r a_major a_minor a_patch <<< "$(semver_parts "$1")"
  read -r b_major b_minor b_patch <<< "$(semver_parts "$2")"

  if (( a_major != b_major )); then
    (( a_major < b_major )) && echo -1 || echo 1; return
  fi
  if (( a_minor != b_minor )); then
    (( a_minor < b_minor )) && echo -1 || echo 1; return
  fi
  if (( a_patch != b_patch )); then
    (( a_patch < b_patch )) && echo -1 || echo 1; return
  fi
  echo 0
}

# ── Find pending migrations ──────────────────────────────────────────
# Lists all version directories in migrations/ that are > current AND <= target
# Output: one version per line, sorted ascending
find_pending_migrations() {
  local current="$1" target="$2"
  local pending=()

  # Scan for versioned subdirectories (e.g., migrations/3.5.1/)
  for dir in "$MIGRATIONS_DIR"/*/; do
    [[ -d "$dir" ]] || continue
    local ver
    ver=$(basename "$dir")
    # Skip non-version directories (e.g., __pycache__)
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || continue

    local cmp_current cmp_target
    cmp_current=$(semver_compare "$ver" "$current")
    cmp_target=$(semver_compare "$ver" "$target")

    # Include if ver > current AND ver <= target
    if (( cmp_current > 0 )) && (( cmp_target <= 0 )); then
      pending+=("$ver")
    fi
  done

  # Sort by semver (ascending)
  if [[ ${#pending[@]} -gt 0 ]]; then
    printf '%s\n' "${pending[@]}" | sort -t. -k1,1n -k2,2n -k3,3n
  fi
}

# ── Execute a single migration ───────────────────────────────────────
run_single_migration() {
  local ver="$1" phase="$2"
  local migrate_script="${MIGRATIONS_DIR}/${ver}/migrate.sh"

  if [[ ! -f "$migrate_script" ]]; then
    log "v${ver}: nessuno script (skip)"
    return 0
  fi

  if [[ ! -x "$migrate_script" ]]; then
    chmod +x "$migrate_script"
  fi

  log "v${ver} [${phase}]: esecuzione..."

  local start_ts
  start_ts=$(date +%s)

  if bash "$migrate_script" "$phase" "$TPL_ROOT" 2>&1 | while IFS= read -r line; do
    echo -e "  ${CYAN}│${NC} $line"
  done; then
    local elapsed=$(( $(date +%s) - start_ts ))
    log "v${ver} [${phase}]: completato (${elapsed}s) ✓"
    return 0
  else
    local rc=$?
    err "v${ver} [${phase}]: FALLITO (exit code ${rc})"
    return 1
  fi
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
  log "Migrazione ${PHASE}: ${CURRENT_VER} → ${TARGET_VER}"

  local pending
  pending=$(find_pending_migrations "$CURRENT_VER" "$TARGET_VER")

  if [[ -z "$pending" ]]; then
    log "Nessuna migrazione pendente per fase '${PHASE}'"
    echo '{"migrations_run":0,"phase":"'"$PHASE"'","status":"ok"}'
    return 0
  fi

  local count=0
  local failed=0
  local versions_run=()

  while IFS= read -r ver; do
    count=$((count + 1))

    # Check if this version declares this phase
    local meta="${MIGRATIONS_DIR}/${ver}/meta.json"
    if [[ -f "$meta" ]]; then
      local phases
      phases=$(python3 -c "
import json, sys
m = json.load(open('$meta'))
print(' '.join(m.get('phases', ['post'])))
" 2>/dev/null || echo "post")
      if [[ ! " $phases " =~ " $PHASE " ]]; then
        log "v${ver}: fase '${PHASE}' non dichiarata (skip)"
        continue
      fi
    fi

    if ! run_single_migration "$ver" "$PHASE"; then
      failed=$((failed + 1))
      err "Migrazione v${ver} fallita — STOP pipeline"
      echo '{"migrations_run":'"$count"',"failed":'"$failed"',"stopped_at":"'"$ver"'","phase":"'"$PHASE"'","status":"failed"}'
      return 1
    fi

    versions_run+=("$ver")
  done <<< "$pending"

  local versions_json
  versions_json=$(printf '%s\n' "${versions_run[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))")

  log "Migrazioni ${PHASE} completate: ${#versions_run[@]} eseguite ✓"
  echo '{"migrations_run":'"${#versions_run[@]}"',"versions":'"$versions_json"',"phase":"'"$PHASE"'","status":"ok"}'
}

main

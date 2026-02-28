#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# TPL OTA Update Script — Host-side update applicator
# Usage:
#   sudo bash scripts/ota_update.sh --check         # Check for prepared updates
#   sudo bash scripts/ota_update.sh --apply <tag>    # Apply a prepared update
#   sudo bash scripts/ota_update.sh --rollback       # Rollback to last backup
#   sudo bash scripts/ota_update.sh --list           # List available staged versions
#   sudo bash scripts/ota_update.sh --cleanup <tag>  # Remove staged version
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────
TPL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OTA_DIR="${TPL_ROOT}/data/ota"
STAGING_DIR="${OTA_DIR}/staging"
BACKUP_DIR="${OTA_DIR}/backups"
LOG_FILE="${OTA_DIR}/update.log"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Helpers ───────────────────────────────────────────────────────────

log() { echo -e "${GREEN}[OTA]${NC} $*"; echo "[$(date -Iseconds)] $*" >> "$LOG_FILE" 2>/dev/null || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; echo "[$(date -Iseconds)] WARN: $*" >> "$LOG_FILE" 2>/dev/null || true; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; echo "[$(date -Iseconds)] ERROR: $*" >> "$LOG_FILE" 2>/dev/null || true; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
header() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}\n"; }

die() { err "$@"; exit 1; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    die "Questo script deve essere eseguito come root (sudo)"
  fi
}

ensure_dirs() {
  mkdir -p "$STAGING_DIR" "$BACKUP_DIR" 2>/dev/null || true
}

# ── List staged versions ─────────────────────────────────────────────

cmd_list() {
  header "Versioni preparate"
  ensure_dirs

  local count=0
  for d in "$STAGING_DIR"/*/; do
    [[ -d "$d" ]] || continue
    local tag
    tag=$(basename "$d")
    local files
    files=$(find "$d" -type f | wc -l)
    local size
    size=$(du -sh "$d" 2>/dev/null | cut -f1)
    echo -e "  ${CYAN}${tag}${NC}  →  ${files} file, ${size}"
    count=$((count + 1))
  done

  if [[ $count -eq 0 ]]; then
    info "Nessuna versione preparata."
    info "Usa il Centro Aggiornamenti OTA nella dashboard per preparare un aggiornamento."
  else
    echo ""
    info "${count} versione/i pronte per l'installazione."
  fi
}

# ── Check for prepared updates ───────────────────────────────────────

cmd_check() {
  header "Controllo aggiornamenti preparati"
  ensure_dirs

  local found=0
  for d in "$STAGING_DIR"/*/; do
    [[ -d "$d" ]] || continue

    local tag
    tag=$(basename "$d")
    echo -e "\n${GREEN}✓${NC} Trovata versione preparata: ${BOLD}${tag}${NC}"

    # Verify key files
    local checks=0
    local ok=0
    for f in compose.yml run.sh apps/api/app/main.py; do
      checks=$((checks + 1))
      if [[ -f "${d}${f}" ]]; then
        ok=$((ok + 1))
        echo -e "  ${GREEN}✓${NC} ${f}"
      else
        echo -e "  ${RED}✗${NC} ${f} (mancante)"
      fi
    done

    # Check modules
    if [[ -d "${d}modules" ]]; then
      local mods
      mods=$(find "${d}modules" -name "*.sh" | wc -l)
      echo -e "  ${GREEN}✓${NC} ${mods} moduli shell trovati"
    fi

    # Check engines
    if [[ -d "${d}apps/api/app/engines" ]]; then
      local engs
      engs=$(find "${d}apps/api/app/engines" -name "*_engine.py" | wc -l)
      echo -e "  ${GREEN}✓${NC} ${engs} engine Python trovati"
    fi

    echo -e "  Verifica: ${ok}/${checks} file essenziali presenti"
    found=$((found + 1))
  done

  if [[ $found -eq 0 ]]; then
    info "Nessun aggiornamento preparato."
    echo ""
    info "Per preparare un aggiornamento:"
    echo "  1. Apri la Dashboard → Moduli → Versione"
    echo "  2. Clicca 'Verifica' nel Centro Aggiornamenti OTA"
    echo "  3. Seleziona una release e clicca 'Prepara'"
    echo "  4. Poi torna qui ed esegui: sudo bash scripts/ota_update.sh --apply <tag>"
  fi
}

# ── Create backup ────────────────────────────────────────────────────

create_backup() {
  local backup_name="pre-update-$(date +%Y%m%d_%H%M%S)"
  local backup_path="${BACKUP_DIR}/${backup_name}"

  log "Creazione backup: ${backup_name}"
  mkdir -p "$backup_path"

  # Backup key directories (exclude data, secrets, logs, caches)
  rsync -a --quiet \
    --exclude='data/' \
    --exclude='.secrets/' \
    --exclude='logs/' \
    --exclude='__pycache__/' \
    --exclude='.git/' \
    --exclude='*.pyc' \
    --exclude='.env' \
    "$TPL_ROOT/" "$backup_path/"

  # Save metadata
  cat > "${backup_path}/.backup_meta.json" <<EOF
{
  "created": "$(date -Iseconds)",
  "tpl_root": "${TPL_ROOT}",
  "hostname": "$(hostname)",
  "type": "pre-update"
}
EOF

  local size
  size=$(du -sh "$backup_path" 2>/dev/null | cut -f1)
  log "Backup creato: ${backup_path} (${size})"
  echo "$backup_path"
}

# ── Apply update ─────────────────────────────────────────────────────

cmd_apply() {
  local tag="${1:-}"
  [[ -z "$tag" ]] && die "Uso: $0 --apply <tag>\nEsempio: $0 --apply v2.2.0"

  # Sanitize tag
  tag=$(echo "$tag" | sed 's/[^a-zA-Z0-9._-]//g')

  local staging="${STAGING_DIR}/${tag}"
  [[ -d "$staging" ]] || die "Versione ${tag} non trovata in staging.\nPrepara prima l'aggiornamento dal Centro Aggiornamenti OTA."

  check_root

  # Concurrency lock: prevent simultaneous apply runs
  local lockfile="${OTA_DIR}/.ota_apply.lock"
  exec 200>"$lockfile"
  if ! flock -n 200; then
    die "Un altro aggiornamento OTA è già in esecuzione. Attendere il completamento."
  fi
  # Lock is auto-released when fd 200 closes (script exit)

  header "Aggiornamento OTA — ${tag}"

  # ── Step 1: Pre-flight checks ────────────────────────────────────
  log "Step 1/6: Pre-flight checks"

  local errors=0
  for f in compose.yml run.sh; do
    if [[ ! -f "${staging}/${f}" ]]; then
      err "File essenziale mancante: ${f}"
      errors=$((errors + 1))
    fi
  done

  local disk_free
  disk_free=$(df -BM "$TPL_ROOT" | tail -1 | awk '{print $4}' | tr -d 'M')
  if [[ "$disk_free" -lt 200 ]]; then
    err "Spazio disco insufficiente: ${disk_free}MB (minimo 200MB)"
    errors=$((errors + 1))
  else
    log "  Spazio disco: ${disk_free}MB ✓"
  fi

  if [[ $errors -gt 0 ]]; then
    die "Pre-flight check falliti (${errors} errori). Aggiornamento annullato."
  fi
  log "  Pre-flight checks superati ✓"

  # ── Step 2: Create backup ────────────────────────────────────────
  log "Step 2/6: Creazione backup"
  local backup_dir
  backup_dir=$(create_backup)
  log "  Backup salvato in: ${backup_dir}"

  # ── Step 3: Stop services ────────────────────────────────────────
  log "Step 3/6: Arresto servizi"
  cd "$TPL_ROOT"
  if docker compose ps --quiet 2>/dev/null | head -1 | grep -q .; then
    docker compose down --timeout 30 2>&1 | while read -r line; do
      echo "  $line"
    done
    log "  Servizi arrestati ✓"
  else
    log "  Nessun servizio in esecuzione"
  fi

  # ── Step 4: Apply files ──────────────────────────────────────────
  log "Step 4/6: Applicazione aggiornamento"

  # Directories to update (safe list — excludes data, secrets, logs)
  local -a UPDATE_DIRS=(
    "apps"
    "compose.d"
    "infra"
    "modules"
    "scripts"
  )

  # Root-level files to update
  local -a UPDATE_FILES=(
    "compose.yml"
    "VERSION.json"
    "run.sh"
    "bootstrap.sh"
    "init.sh"
    "go.sh"
    "README.md"
    "install_tpl.sh"
    "install.sh"
  )

  local updated=0
  local skipped=0

  # Update directories
  for dir in "${UPDATE_DIRS[@]}"; do
    if [[ -d "${staging}/${dir}" ]]; then
      log "  Aggiornamento: ${dir}/"
      rsync -a --delete \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        "${staging}/${dir}/" "${TPL_ROOT}/${dir}/"
      updated=$((updated + 1))
    fi
  done

  # Update root files
  for file in "${UPDATE_FILES[@]}"; do
    if [[ -f "${staging}/${file}" ]]; then
      cp -a "${staging}/${file}" "${TPL_ROOT}/${file}"
      updated=$((updated + 1))
    fi
  done

  # Ensure scripts are executable
  find "${TPL_ROOT}/scripts" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
  chmod +x "${TPL_ROOT}/run.sh" "${TPL_ROOT}/go.sh" "${TPL_ROOT}/bootstrap.sh" \
    "${TPL_ROOT}/init.sh" "${TPL_ROOT}/install.sh" "${TPL_ROOT}/install_tpl.sh" 2>/dev/null || true

  log "  ${updated} componenti aggiornati ✓"

  # ── Step 4b: Propagate version from VERSION.json ─────────────────
  if [[ -x "${TPL_ROOT}/scripts/version.sh" ]] && [[ -f "${TPL_ROOT}/VERSION.json" ]]; then
    log "  Propagazione versione ai file della piattaforma..."
    bash "${TPL_ROOT}/scripts/version.sh" apply 2>&1 | while read -r line; do
      log "    $line"
    done
    log "  Versione propagata ✓"
  fi

  # ── Step 5: Rebuild containers ───────────────────────────────────
  log "Step 5/6: Rebuild container"
  cd "$TPL_ROOT"
  docker compose build --no-cache 2>&1 | tail -5
  log "  Container ricostruiti ✓"

  # ── Step 6: Start services ──────────────────────────────────────
  log "Step 6/6: Avvio servizi"
  if [[ -x "${TPL_ROOT}/run.sh" ]]; then
    "${TPL_ROOT}/run.sh" 2>&1 | tail -10
  else
    docker compose up -d 2>&1 | tail -5
  fi
  log "  Servizi avviati ✓"

  # ── Post-update verification ─────────────────────────────────────
  echo ""
  header "Verifica post-aggiornamento"
  sleep 5

  local health_ok=true
  # Check if API responds
  if curl -sf --max-time 10 http://localhost:8080/api/health >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} API health check OK"
  elif curl -sf --max-time 10 https://localhost:8443/api/health -k >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} API health check OK (HTTPS)"
  else
    echo -e "  ${YELLOW}!${NC} API non ancora pronta (potrebbe essere in avvio)"
    health_ok=false
  fi

  # Check containers
  local running
  running=$(docker compose ps --status running --quiet 2>/dev/null | wc -l)
  echo -e "  ${GREEN}✓${NC} ${running} container in esecuzione"

  # ── Summary ──────────────────────────────────────────────────────
  echo ""
  header "Aggiornamento completato"
  echo -e "  Versione applicata:  ${BOLD}${tag}${NC}"
  echo -e "  Backup disponibile:  ${backup_dir}"
  echo -e "  Container attivi:    ${running}"
  if [[ $health_ok == false ]]; then
    echo ""
    warn "L'API potrebbe richiedere qualche secondo per l'avvio completo."
    info "Verifica con: curl -sf https://localhost:8443/api/health -k"
  fi
  echo ""
  info "Per rollback: sudo bash scripts/ota_update.sh --rollback"

  # Update log
  cat >> "${OTA_DIR}/history.jsonl" <<EOF
{"ts":"$(date -Iseconds)","action":"update","tag":"${tag}","backup":"${backup_dir}","status":"completed"}
EOF
}

# ── Rollback ─────────────────────────────────────────────────────────

cmd_rollback() {
  check_root
  header "Rollback ultimo aggiornamento"

  ensure_dirs

  # Find latest backup
  local latest_backup=""
  for d in "${BACKUP_DIR}"/pre-update-*/; do
    [[ -d "$d" ]] && latest_backup="$d"
  done

  if [[ -z "$latest_backup" ]]; then
    die "Nessun backup trovato in ${BACKUP_DIR}.\nNon è possibile effettuare il rollback."
  fi

  local backup_name
  backup_name=$(basename "$latest_backup")
  log "Ripristino da backup: ${backup_name}"

  # Confirm
  echo -e "${YELLOW}ATTENZIONE: Questa operazione ripristinerà i file dal backup ${backup_name}.${NC}"
  echo -e "I dati in ./data/ e ./.secrets/ NON verranno modificati."
  echo ""
  read -p "Continuare? (s/N) " -n 1 -r
  echo ""
  [[ $REPLY =~ ^[Ss]$ ]] || { info "Rollback annullato."; exit 0; }

  # Stop services
  log "Arresto servizi"
  cd "$TPL_ROOT"
  docker compose down --timeout 30 2>&1 | tail -3

  # Restore files
  log "Ripristino file da ${latest_backup}"
  rsync -a \
    --exclude='data/' \
    --exclude='.secrets/' \
    --exclude='logs/' \
    --exclude='.env' \
    --exclude='.git/' \
    "$latest_backup/" "$TPL_ROOT/"

  # Fix permissions
  find "${TPL_ROOT}/scripts" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
  chmod +x "${TPL_ROOT}/run.sh" "${TPL_ROOT}/go.sh" 2>/dev/null || true

  # Rebuild and start
  log "Rebuild container"
  docker compose build --no-cache 2>&1 | tail -5

  log "Avvio servizi"
  if [[ -x "${TPL_ROOT}/run.sh" ]]; then
    "${TPL_ROOT}/run.sh" 2>&1 | tail -10
  else
    docker compose up -d 2>&1 | tail -5
  fi

  echo ""
  header "Rollback completato"
  echo -e "  Ripristinato da: ${BOLD}${backup_name}${NC}"
  info "Verifica che tutto funzioni correttamente."

  cat >> "${OTA_DIR}/history.jsonl" <<EOF
{"ts":"$(date -Iseconds)","action":"rollback","from_backup":"${backup_name}","status":"completed"}
EOF
}

# ── Cleanup staged version ───────────────────────────────────────────

cmd_cleanup() {
  local tag="${1:-}"
  [[ -z "$tag" ]] && die "Uso: $0 --cleanup <tag>"

  tag=$(echo "$tag" | sed 's/[^a-zA-Z0-9._-]//g')

  local staging="${STAGING_DIR}/${tag}"
  local download="${OTA_DIR}/downloads/${tag}.tar.gz"

  local removed=0
  if [[ -d "$staging" ]]; then
    rm -rf "$staging"
    log "Rimosso: ${staging}"
    removed=$((removed + 1))
  fi
  if [[ -f "$download" ]]; then
    rm -f "$download"
    log "Rimosso: ${download}"
    removed=$((removed + 1))
  fi

  if [[ $removed -eq 0 ]]; then
    info "Nessun file trovato per la versione ${tag}"
  else
    log "Pulizia completata: ${removed} elementi rimossi per ${tag}"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
  ensure_dirs

  case "${1:-}" in
    --check|-c)   cmd_check ;;
    --apply|-a)   shift; cmd_apply "${1:-}" ;;
    --rollback|-r) cmd_rollback ;;
    --list|-l)    cmd_list ;;
    --cleanup)    shift; cmd_cleanup "${1:-}" ;;
    --help|-h|"")
      echo ""
      echo -e "${BOLD}TPL OTA Update Script${NC}"
      echo ""
      echo "Uso:"
      echo "  sudo bash $0 --check              Verifica aggiornamenti preparati"
      echo "  sudo bash $0 --apply <tag>         Applica un aggiornamento preparato"
      echo "  sudo bash $0 --rollback            Ripristina dall'ultimo backup"
      echo "  sudo bash $0 --list                Elenca versioni preparate"
      echo "  sudo bash $0 --cleanup <tag>       Rimuovi versione preparata"
      echo ""
      echo "Workflow:"
      echo "  1. Prepara l'aggiornamento dalla Dashboard (Centro Aggiornamenti OTA)"
      echo "  2. Esegui: sudo bash scripts/ota_update.sh --check"
      echo "  3. Esegui: sudo bash scripts/ota_update.sh --apply <tag>"
      echo ""
      ;;
    *)
      die "Opzione sconosciuta: ${1}\nUsa --help per la guida"
      ;;
  esac
}

main "$@"

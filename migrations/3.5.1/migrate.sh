#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# TPL Migration — v3.5.1 Horizon
#
# Called by: migrations/run_migrations.sh
# Args: $1 = phase (pre|post), $2 = TPL_ROOT
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

PHASE="${1:-post}"
TPL_ROOT="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

log() { echo "[v3.5.1] $*"; }

case "$PHASE" in

  pre)
    # ── Pre-apply: prepare before files are overwritten ────────────
    log "Pre-apply: verifica integrità state.json"

    STATE="${TPL_ROOT}/data/ota/state.json"
    if [[ -f "$STATE" ]] && [[ -w "$STATE" ]]; then
      # Ensure installed_version field exists (new field for migration tracking)
      python3 -c "
import json
with open('${STATE}') as f:
    s = json.load(f)
if 'installed_version' not in s:
    # Read current version from VERSION.json
    try:
        with open('${TPL_ROOT}/VERSION.json') as vf:
            v = json.load(vf)
        s['installed_version'] = v.get('version', '3.4.0')
    except Exception:
        s['installed_version'] = '3.4.0'
    s['migration_history'] = s.get('migration_history', [])
    with open('${STATE}', 'w') as f:
        json.dump(s, f, indent=2)
    print('  installed_version inizializzato: ' + s['installed_version'])
else:
    print('  installed_version già presente: ' + s['installed_version'])
"
    elif [[ -f "$STATE" ]]; then
      log "  state.json non scrivibile — skip (verrà aggiornato dal processo OTA)"
    fi

    log "Pre-apply completato"
    ;;

  post)
    # ── Post-apply: after v3.5.1 files are in place ───────────────
    log "Post-apply: configurazione post-aggiornamento"

    # 1. Ensure migration runner is executable
    if [[ -f "${TPL_ROOT}/migrations/run_migrations.sh" ]]; then
      chmod +x "${TPL_ROOT}/migrations/run_migrations.sh"
      log "  migrations/run_migrations.sh reso eseguibile"
    fi

    # 2. Ensure script permissions
    find "${TPL_ROOT}/scripts" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    log "  Permessi script aggiornati"

    # 3. Clear any Python bytecode caches (stale after code changes)
    find "${TPL_ROOT}/apps" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "${TPL_ROOT}/apps" -name "*.pyc" -delete 2>/dev/null || true
    log "  Cache Python ripulita"

    # 4. Update installed_version in state.json
    STATE="${TPL_ROOT}/data/ota/state.json"
    if [[ -f "$STATE" ]] && [[ -w "$STATE" ]]; then
      python3 -c "
import json, time
with open('${STATE}') as f:
    s = json.load(f)
s['installed_version'] = '3.5.1'
hist = s.get('migration_history', [])
hist.append({
    'version': '3.5.1',
    'applied_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'phase': 'post',
    'status': 'ok'
})
s['migration_history'] = hist
with open('${STATE}', 'w') as f:
    json.dump(s, f, indent=2)
print('  state.json aggiornato: installed_version=3.5.1')
"
    elif [[ -f "$STATE" ]]; then
      log "  state.json non scrivibile — skip (verrà aggiornato dal processo OTA)"
    fi

    # 5. Validate nginx config syntax (if available)
    if command -v nginx &>/dev/null; then
      if nginx -t -c "${TPL_ROOT}/infra/web/nginx.conf" 2>/dev/null; then
        log "  nginx.conf sintassi OK"
      else
        log "  WARN: nginx.conf sintassi non valida"
      fi
    fi

    log "Post-apply completato ✓"
    ;;

  *)
    echo "Fase sconosciuta: $PHASE (usa 'pre' o 'post')" >&2
    exit 1
    ;;
esac

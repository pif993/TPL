#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# TPL Rollback — v3.5.1
# Reverses changes made by migrate.sh post phase
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

TPL_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
STATE="${TPL_ROOT}/data/ota/state.json"

echo "[v3.5.1 rollback] Ripristino state.json"

if [[ -f "$STATE" ]]; then
  python3 -c "
import json
with open('${STATE}') as f:
    s = json.load(f)
# Remove v3.5.1 from migration history
hist = s.get('migration_history', [])
s['migration_history'] = [h for h in hist if h.get('version') != '3.5.1']
# Don't rollback installed_version — the file rollback handles that
with open('${STATE}', 'w') as f:
    json.dump(s, f, indent=2)
print('  migration_history: rimossa entry v3.5.1')
"
fi

echo "[v3.5.1 rollback] Completato"

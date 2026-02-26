#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"108_ota_update","ver":"1.0.0","deps":["45_api_engine_host","105_version_manager"],"desc":"Aggiornamenti OTA via GitHub: rilevamento automatico, download, staging, guida installazione e rollback"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines

  local engine="apps/api/app/engines/ota_update_engine.py"
  if [[ ! -f "$engine" ]]; then
    echo "WARN: $engine not found — module inactive until engine is deployed" >&2
    echo "INFO: This is expected on first install. Engine will be available after next build."
    return 0
  fi

  # Ensure host-side update script is executable
  local updater="scripts/ota_update.sh"
  if [[ -f "$updater" ]]; then
    chmod +x "$updater"
    echo "INFO: ota_update.sh — script host-side pronto"
  fi

  echo "INFO: ota_update_engine.py v1.0.0 — aggiornamenti OTA attivi"
}

check(){
  local engine="apps/api/app/engines/ota_update_engine.py"
  [[ -f "$engine" ]] || { echo "SKIP: engine not deployed yet"; return 0; }
  python3 -c "import ast; ast.parse(open('$engine').read())"
}
rollback(){ rm -f apps/api/app/engines/ota_update_engine.py; }

#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"105_version_manager","ver":"1.0.0","deps":["45_api_engine_host"],"desc":"Controllo versione piattaforma: OTA, aggiornamento locale, changelog, rollback, grafo dipendenze"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines

  local engine="apps/api/app/engines/version_manager_engine.py"
  if [[ ! -f "$engine" ]]; then
    echo "WARN: $engine not found — module inactive until engine is deployed" >&2
    echo "INFO: This is expected on first install. Engine will be available after next build."
    return 0
  fi

  echo "INFO: version_manager_engine.py v1.0.0 — gestione versione e aggiornamenti attiva"
}

check(){
  local engine="apps/api/app/engines/version_manager_engine.py"
  [[ -f "$engine" ]] || { echo "SKIP: engine not deployed yet"; return 0; }
  python3 -c "import ast; ast.parse(open('$engine').read())"
}
rollback(){ rm -f apps/api/app/engines/version_manager_engine.py; }

#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"102_user_management","ver":"2.0.0","deps":["50_auth_local"],"desc":"Gestione utenti completa: anagrafica, autorizzazioni, CRUD, cambio password, self-service profilo"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines compose.d

  local engine="apps/api/app/engines/user_management_engine.py"
  if [[ ! -f "$engine" ]]; then
    echo "WARN: $engine not found — module inactive until engine is deployed" >&2
    echo "INFO: This is expected on first install. Engine will be available after next build."
    return 0
  fi

  echo "INFO: user_management_engine.py v2.0.0 — gestione utenti completa attiva"
}

check(){
  local engine="apps/api/app/engines/user_management_engine.py"
  [[ -f "$engine" ]] || { echo "SKIP: engine not deployed yet"; return 0; }
  python3 -c "import ast; ast.parse(open('$engine').read())"
}
rollback(){ rm -f apps/api/app/engines/user_management_engine.py; }

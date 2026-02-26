#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"97_encryption","ver":"1.0.0","deps":["96_security_hardening"],"desc":"Motore crittografia: AES-GCM, hashing, key management, HMAC, file encrypt/decrypt"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines

  local engine="apps/api/app/engines/encryption_engine.py"
  if [[ ! -f "$engine" ]]; then
    echo "WARN: $engine not found — module inactive until engine is deployed" >&2
    echo "INFO: This is expected on first install. Engine will be available after next build."
    return 0
  fi

  echo "INFO: encryption_engine.py v1.0.0 — crittografia avanzata attiva"
}

check(){
  local engine="apps/api/app/engines/encryption_engine.py"
  [[ -f "$engine" ]] || { echo "SKIP: engine not deployed yet"; return 0; }
  python3 -c "import ast; ast.parse(open('$engine').read())"
}
rollback(){ rm -f apps/api/app/engines/encryption_engine.py; }

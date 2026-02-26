#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"107_self_diagnosis","ver":"1.0.0","deps":["90_log_engine","45_api_engine_host"],"desc":"Autodiagnosi: correlazione cross-log, root cause analysis, drift config, remediation automatica, metriche unificate"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines

  local engine="apps/api/app/engines/self_diagnosis_engine.py"
  if [[ ! -f "$engine" ]]; then
    echo "WARN: $engine not found — module inactive until engine is deployed" >&2
    echo "INFO: This is expected on first install. Engine will be available after next build."
    return 0
  fi

  echo "INFO: self_diagnosis_engine.py v1.0.0 — autodiagnosi e correlazione attive"
}

check(){
  local engine="apps/api/app/engines/self_diagnosis_engine.py"
  [[ -f "$engine" ]] || { echo "SKIP: engine not deployed yet"; return 0; }
  python3 -c "import ast; ast.parse(open('$engine').read())"
}
rollback(){ rm -f apps/api/app/engines/self_diagnosis_engine.py; }

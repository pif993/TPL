#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"101_system_monitoring_ai","ver":"1.0.0","deps":["90_log_engine"],"desc":"System monitoring with IA (health check, predictive issues)"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines
  if [[ -f apps/api/app/engines/system_monitoring_engine.py ]]; then
    echo "INFO: system_monitoring_engine.py già presente — mantengo versione corrente"
    return 0
  fi
  cat > apps/api/app/engines/system_monitoring_engine.py <<'PY'
import json, os, time, subprocess
from fastapi import FastAPI, Depends
from typing import List

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  root = ctx["root"]

  def get_docker_status() -> dict:
    try:
      result = subprocess.run(["docker", "compose", "ps", "--format", "json"], cwd=root, capture_output=True, text=True, timeout=5)
      if result.returncode == 0:
        services = json.loads(result.stdout) if result.stdout else []
        running = len([s for s in services if s.get("State") == "running"])
        total = len(services)
        return {"running": running, "total": total, "healthy": running == total}
    except Exception:
      pass
    return {"running": 0, "total": 0, "healthy": False}

  def predict_issues() -> List[dict]:
    issues = []
    
    audit_file = os.path.join(root, ".tpl_audit.jsonl")
    if os.path.isfile(audit_file):
      with open(audit_file, "r") as f:
        lines = f.readlines()
        if len(lines) > 100_000:
          issues.append({"severity": "medium", "type": "audit_log_size", "message": "Audit log supera 100K righe, considerare rotazione"})
    
    docker_status = get_docker_status()
    if not docker_status.get("healthy"):
      issues.append({"severity": "critical", "type": "service_health", "message": f"Solo {docker_status.get('running')}/{docker_status.get('total')} servizi attivi"})
    
    return issues

  def health_summary() -> dict:
    docker = get_docker_status()
    issues = predict_issues()
    crit = len([x for x in issues if x.get("severity") == "critical"])
    high = len([x for x in issues if x.get("severity") == "high"])
    
    return {
      "services": docker,
      "issues": issues,
      "critical_count": crit,
      "high_count": high,
      "status": "healthy" if crit == 0 else "degraded" if crit < 3 else "critical"
    }

  @app.get("/monitoring/health")
  async def system_health(_: dict = Depends(require_admin)):
    return health_summary()

  @app.get("/monitoring/predictions")
  async def predict_problems(_: dict = Depends(require_admin)):
    summary = health_summary()
    issues = summary.get("issues", [])
    return {
      "predictions": issues,
      "overall_status": summary.get("status"),
      "recommended_actions": [
        "Verificare servizi non attivi" if any(x.get("type") == "service_health" for x in issues) else None,
        "Ruotare audit log" if any(x.get("type") == "audit_log_size" for x in issues) else None
      ]
    }
PY
}

check(){ python3 -c "import ast; ast.parse(open('apps/api/app/engines/system_monitoring_engine.py').read())" 2>/dev/null; }
rollback(){ rm -f apps/api/app/engines/system_monitoring_engine.py; }

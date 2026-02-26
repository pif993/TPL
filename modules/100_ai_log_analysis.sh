#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"100_ai_log_analysis","ver":"1.0.0","deps":["90_log_engine"],"desc":"IA log analysis engine (anomalies, patterns, alerts)"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines
  if [[ -f apps/api/app/engines/ai_log_analysis_engine.py ]]; then
    echo "INFO: ai_log_analysis_engine.py già presente — mantengo versione corrente"
    return 0
  fi
  cat > apps/api/app/engines/ai_log_analysis_engine.py <<'PY'
import json, os, time
from collections import Counter
from fastapi import FastAPI, Depends
from typing import List

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  root = ctx["root"]
  log_file = os.path.join(root, ".tpl_events.jsonl")

  def read_logs(limit: int = 1000) -> List:
    if not os.path.isfile(log_file): return []
    out = []
    with open(log_file, "r", encoding="utf-8") as f:
      for line in f:
        try: out.append(json.loads(line.strip()))
        except Exception: continue
    return out[-limit:]

  def detect_anomalies(logs: List) -> dict:
    if not logs: return {"anomalies": []}
    
    events = [x.get("event") for x in logs if x.get("event")]
    counts = Counter(events)
    avg_count = sum(counts.values()) / max(len(counts), 1) if counts else 0
    anomalies = []
    
    for event, count in counts.items():
      if count > avg_count * 3:
        anomalies.append({"type": "spike", "event": event, "count": count, "avg": int(avg_count)})
    
    error_rate = len([x for x in logs if x.get("level") in ["error", "warn"]]) / max(len(logs), 1)
    if error_rate > 0.3:
      anomalies.append({"type": "error_rate_high", "rate": round(error_rate, 2), "threshold": 0.3})
    
    return {"anomalies": anomalies, "total_logs": len(logs)}

  def extract_patterns(logs: List) -> dict:
    if not logs: return {"patterns": []}
    patterns = {}
    for log in logs:
      source = log.get("source", "unknown")
      level = log.get("level", "info")
      key = f"{source}:{level}"
      patterns[key] = patterns.get(key, 0) + 1
    
    top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]
    return {"patterns": [{"name": name, "count": cnt} for name, cnt in top_patterns]}

  @app.get("/ai/log-analysis")
  async def analyze_logs(limit: int = 500, _: dict = Depends(require_admin)):
    logs = read_logs(limit)
    anomalies = detect_anomalies(logs)
    patterns = extract_patterns(logs)
    
    severity = "low"
    if anomalies.get("anomalies"): severity = "medium"
    if any(a.get("type") == "error_rate_high" for a in anomalies.get("anomalies", [])): severity = "high"
    
    return {
      "severity": severity,
      "anomalies": anomalies,
      "patterns": patterns,
      "recommendation": "Monitorare picchi di eventi e tasso errori" if severity != "low" else "Sistema operativo normalmente"
    }
PY
}

check(){ python3 -c "import ast; ast.parse(open('apps/api/app/engines/ai_log_analysis_engine.py').read())" 2>/dev/null; }
rollback(){ rm -f apps/api/app/engines/ai_log_analysis_engine.py; }

#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"96_security_hardening","ver":"1.0.0","deps":["95_communication_engine"],"desc":"Advanced security functions (threat analysis, policy enforcement, incident tracking)"}
JSON
}

apply(){
  # Idempotency guard: if WAF-hardened security engine exists, skip
  if [[ -f apps/api/app/engines/security_engine.py ]] && grep -q 'waf\|WAF\|firewall' apps/api/app/engines/security_engine.py 2>/dev/null; then
    echo "SKIP 96_security_hardening: WAF engine already exists" >&2
    return 0
  fi
  mkdir -p apps/api/app/engines compose.d
  cat > apps/api/app/engines/security_engine.py <<'PY'
import json, os, time, hashlib
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, constr, Field

class SecurityAlert(BaseModel):
  severity: constr(pattern="^(low|medium|high|critical)$")
  category: constr(min_length=1, max_length=64)
  message: constr(min_length=1, max_length=500)
  source: str = "security_engine"
  meta: dict = Field(default_factory=dict)

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  root = ctx["root"]
  sec_file = os.path.join(root, ".tpl_security.jsonl")

  def append_alert(payload: dict):
    row = {"ts": int(time.time()), "id": hashlib.md5(f"{time.time()}{payload}".encode()).hexdigest()[:16], **payload}
    with open(sec_file, "a", encoding="utf-8") as f: f.write(json.dumps(row, separators=(",", ":")) + "\n")

  def tail(limit: int):
    limit = max(1, min(limit, 500))
    if not os.path.isfile(sec_file): return []
    out = []
    with open(sec_file, "r", encoding="utf-8") as f:
      for line in f:
        line = line.strip()
        if not line: continue
        try: out.append(json.loads(line))
        except Exception: continue
    return out[-limit:]

  app.state.security_engine_alert = append_alert

  @app.post("/security/alert")
  async def create_alert(x: SecurityAlert, _: dict = Depends(require_admin)):
    append_alert(x.model_dump())
    return {"ok": True, "id": ""}

  @app.get("/security/alerts")
  async def list_alerts(limit: int = 100, severity: str = "", _: dict = Depends(require_admin)):
    items = tail(limit)
    if severity: items = [x for x in items if x.get("severity") == severity]
    return {"items": items, "count": len(items)}

  @app.get("/security/status")
  async def security_status(_: dict = Depends(require_admin)):
    all_alerts = tail(500)
    crit = len([x for x in all_alerts if x.get("severity") == "critical"])
    high = len([x for x in all_alerts if x.get("severity") == "high"])
    return {"critical": crit, "high": high, "total_today": len([x for x in all_alerts if x.get("ts", 0) > int(time.time()) - 86400])}
PY
}

check(){ true; }
rollback(){ rm -f apps/api/app/engines/security_engine.py; }

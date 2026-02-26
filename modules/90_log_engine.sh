#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"90_log_engine","ver":"1.0.0","deps":["45_api_engine_host"],"desc":"Centralized log engine module"}
JSON
}

apply(){
  # Idempotency guard: if log engine exists, skip
  if [[ -f apps/api/app/engines/log_engine.py ]]; then
    echo "SKIP 90_log_engine: engine already exists" >&2
    return 0
  fi
  mkdir -p apps/api/app/engines
  cat > apps/api/app/engines/log_engine.py <<'PY'
import json, os, time
from fastapi import FastAPI, Depends
from pydantic import BaseModel, constr, Field

class EventIn(BaseModel):
  source: constr(min_length=1, max_length=64)
  level: constr(min_length=1, max_length=16)
  event: constr(min_length=1, max_length=128)
  message: constr(min_length=1, max_length=500)
  meta: dict = Field(default_factory=dict)

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  root = ctx["root"]
  log_file = os.path.join(root, ".tpl_events.jsonl")

  def append_event(payload: dict):
    row = {"ts": int(time.time()), **payload}
    with open(log_file, "a", encoding="utf-8") as f: f.write(json.dumps(row, separators=(",", ":")) + "\n")

  def tail(limit: int):
    limit = max(1, min(limit, 500))
    if not os.path.isfile(log_file): return []
    out = []
    with open(log_file, "r", encoding="utf-8") as f:
      for line in f:
        line = line.strip()
        if not line: continue
        try: out.append(json.loads(line))
        except Exception: continue
    return out[-limit:]

  app.state.log_engine_append = append_event

  @app.post("/log/events")
  async def create_event(x: EventIn, _: dict = Depends(require_admin)):
    append_event(x.model_dump())
    return {"ok": True}

  @app.get("/log/events")
  async def list_events(limit: int = 100, _: dict = Depends(require_admin)):
    items = tail(limit)
    return {"items": items, "count": len(items)}
PY
}

check(){ true; }
rollback(){ rm -f apps/api/app/engines/log_engine.py; }

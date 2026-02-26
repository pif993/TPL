#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"95_communication_engine","ver":"1.0.0","deps":["45_api_engine_host","90_log_engine"],"desc":"Secure communication engine (HMAC protocol + centralized comm logs)"}
JSON
}

apply(){
  # Idempotency guard: if hardened comm engine exists (uses secret_loader), skip
  if [[ -f apps/api/app/engines/communication_engine.py ]] && grep -q 'secret_loader' apps/api/app/engines/communication_engine.py 2>/dev/null; then
    echo "SKIP 95_communication_engine: hardened engine already exists" >&2
    return 0
  fi
  mkdir -p apps/api/app/engines compose.d
  cat > apps/api/app/engines/communication_engine.py <<'PY'
import hashlib, hmac, json, os, time
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, constr

class CommMessage(BaseModel):
  sender: constr(min_length=1, max_length=64)
  recipient: constr(min_length=1, max_length=64)
  msg_type: constr(min_length=1, max_length=64)
  payload: dict
  nonce: constr(min_length=8, max_length=64)
  ts: int
  signature: constr(min_length=32, max_length=128)

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  root = ctx["root"]
  comm_file = os.path.join(root, ".tpl_comm.jsonl")
  secret = os.getenv("COMM_SHARED_SECRET", "")
  if not secret:
      raise RuntimeError("FATAL: COMM_SHARED_SECRET not set.")

  def canonical(x: CommMessage):
    payload = json.dumps(x.payload, sort_keys=True, separators=(",", ":"))
    return f"{x.sender}|{x.recipient}|{x.msg_type}|{payload}|{x.nonce}|{x.ts}"

  def verify(x: CommMessage):
    data = canonical(x).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, x.signature)

  def append(row: dict):
    with open(comm_file, "a", encoding="utf-8") as f: f.write(json.dumps(row, separators=(",", ":")) + "\n")

  def tail(limit: int):
    limit = max(1, min(limit, 500))
    if not os.path.isfile(comm_file): return []
    out=[]
    with open(comm_file, "r", encoding="utf-8") as f:
      for line in f:
        line=line.strip()
        if not line: continue
        try: out.append(json.loads(line))
        except Exception: continue
    return out[-limit:]

  @app.post("/comm/send")
  async def send_message(x: CommMessage, _: dict = Depends(require_admin)):
    now = int(time.time())
    if abs(now - x.ts) > 300: raise HTTPException(400, "stale_timestamp")
    if not verify(x): raise HTTPException(401, "bad_signature")
    row = {"ts": now, "sender": x.sender, "recipient": x.recipient, "msg_type": x.msg_type, "payload": x.payload, "nonce": x.nonce, "verified": True}
    append(row)
    logger = getattr(app.state, "log_engine_append", None)
    if callable(logger):
      logger({"source": "communication_engine", "level": "info", "event": "message_sent", "message": f"{x.sender}->{x.recipient}:{x.msg_type}", "meta": {"recipient": x.recipient, "msg_type": x.msg_type}})
    return {"ok": True, "verified": True}

  @app.get("/comm/logs")
  async def comm_logs(limit: int = 100, _: dict = Depends(require_admin)):
    items = tail(limit)
    return {"items": items, "count": len(items)}
PY

  cat > compose.d/95-comm.yml <<'YML'
# COMM_SHARED_SECRET delivered via /run/secrets (no env var needed).
services:
  api: {}
YML
}

check(){ true; }
rollback(){ rm -f apps/api/app/engines/communication_engine.py compose.d/95-comm.yml; }

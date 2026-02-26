import fcntl, json, os, time, threading
from collections import deque
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
  _lock = threading.Lock()

  # Max log file size before rotation (10 MB)
  MAX_LOG_SIZE = 10 * 1024 * 1024

  def _rotate_if_needed():
    """Rotate log file if it exceeds MAX_LOG_SIZE."""
    try:
      if os.path.isfile(log_file) and os.path.getsize(log_file) > MAX_LOG_SIZE:
        rotated = log_file + ".1"
        if os.path.isfile(rotated):
          os.remove(rotated)
        os.rename(log_file, rotated)
    except Exception:
      pass

  def append_event(payload: dict):
    row = {"ts": int(time.time()), **payload}
    with _lock:
      _rotate_if_needed()
      fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
      try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8"))
      finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

  def tail(limit: int):
    limit = max(1, min(limit, 500))
    if not os.path.isfile(log_file): return []
    out = deque(maxlen=limit)
    with _lock:
      with open(log_file, "r", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
          for line in f:
            line = line.strip()
            if not line: continue
            try: out.append(json.loads(line))
            except Exception: continue
        finally:
          fcntl.flock(f, fcntl.LOCK_UN)
    return list(out)

  app.state.log_engine_append = append_event

  @app.post("/log/events")
  async def create_event(x: EventIn, _: dict = Depends(require_admin)):
    append_event(x.model_dump())
    return {"ok": True}

  @app.get("/log/events")
  async def list_events(limit: int = 100, _: dict = Depends(require_admin)):
    items = tail(limit)
    return {"items": items, "count": len(items)}

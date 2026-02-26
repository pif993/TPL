#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"40_api_base","ver":"1.2.0","deps":["10_traefik"],"desc":"FastAPI base hardened + audit logging"}
JSON
}

apply(){
  # Idempotency guard: if hardened main.py already exists, skip
  if [[ -f apps/api/app/main.py ]] && grep -q 'secret_loader' apps/api/app/main.py 2>/dev/null; then
    echo "SKIP 40_api_base: hardened code already exists" >&2
    return 0
  fi
  mkdir -p apps/api/app compose.d

  cat > apps/api/requirements.txt <<'REQ'
fastapi==0.115.7
uvicorn[standard]==0.34.0
httpx==0.27.2
pyjwt==2.10.1
REQ

  cat > apps/api/Dockerfile <<'DF'
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
DF

  # Only write stub auth_impl.py if no auth dispatcher exists yet.
  # The real auth_impl.py is a multi-backend dispatcher (keycloak/local).
  if [[ ! -f apps/api/app/auth_impl.py ]] || ! grep -q 'AUTH_MODE' apps/api/app/auth_impl.py 2>/dev/null; then
    cat > apps/api/app/auth_impl.py <<'PY'
"""Stub — will be replaced by the auth dispatcher on module install."""
from typing import Dict,Any
async def login(username:str,password:str)->str: raise RuntimeError("auth_not_installed — run: ./init.sh auto-install")
async def me(token:str)->Dict[str,Any]: raise RuntimeError("auth_not_installed — run: ./init.sh auto-install")
def set_app(app): pass
PY
  fi

  cat > apps/api/app/main.py <<'PY'
import json
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr

from . import auth_impl

ROOT = "/work" if os.path.isdir("/work/modules") else "/"
MOD = os.path.join(ROOT, "modules")
STATE = os.path.join(ROOT, ".tpl_state.json")
AUDIT_LOG = os.path.join(ROOT, ".tpl_audit.jsonl")

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "120"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "8"))

_ATTEMPTS: dict[str, list[float]] = defaultdict(list)
_LOCK = threading.Lock()

app = FastAPI(title="TPL API", version="1.2.0", root_path="/api")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGINS", "*")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class L(BaseModel):
    username: constr(strip_whitespace=True, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: constr(min_length=1, max_length=128)


class M(BaseModel):
    modules: list[str]


@app.middleware("http")
async def hardening_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", uuid4().hex)
    return response


def _login_key(request: Request, username: str) -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    ip = (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown"))
    return f"{ip}:{username.lower()}"


def _register_fail(key: str):
    now = time.time()
    threshold = now - LOGIN_WINDOW_SECONDS
    with _LOCK:
        _ATTEMPTS[key] = [x for x in _ATTEMPTS[key] if x >= threshold]
        _ATTEMPTS[key].append(now)


def _clear_fails(key: str):
    with _LOCK:
        _ATTEMPTS.pop(key, None)


def _is_limited(key: str) -> bool:
    now = time.time()
    threshold = now - LOGIN_WINDOW_SECONDS
    with _LOCK:
        values = [x for x in _ATTEMPTS[key] if x >= threshold]
        _ATTEMPTS[key] = values
        return len(values) >= LOGIN_MAX_ATTEMPTS


def _load():
    try:
        with open(STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"installed": {}, "updated": 0}


def _save(o):
    o["updated"] = int(time.time())
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(o, f, separators=(",", ":"))


def _mods():
    if not os.path.isdir(MOD):
        return []
    out = []
    for fn in sorted(os.listdir(MOD)):
        if fn.endswith(".sh") and re.fullmatch(r"[0-9A-Za-z_.-]+\.sh", fn):
            out.append(fn[:-3])
    return out


async def _tok(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing_token")
    return authorization.split(None, 1)[1].strip()


async def _me(token=Depends(_tok)):
    try:
        return await auth_impl.me(token)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(401, str(e))


def _need(role: str):
    async def dep(u=Depends(_me)):
        if role not in set(u.get("roles", [])):
            raise HTTPException(403, "forbidden")
        return u

    return dep


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _audit(request: Request, action: str, outcome: str, actor: str = "anonymous", details: dict | None = None):
    entry = {
        "ts": int(time.time()),
        "action": action,
        "outcome": outcome,
        "actor": actor,
        "ip": _client_ip(request),
        "request_id": request.headers.get("X-Request-ID", ""),
        "details": details or {},
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception:
        pass


def _audit_tail(limit: int = 100):
    limit = max(1, min(limit, 500))
    if not os.path.isfile(AUDIT_LOG):
        return []

    out = []
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out[-limit:]


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/status")
def status():
    return {
        "ok": True,
        "ts": int(time.time()),
        "auth": os.getenv("AUTH_MODE", "none"),
        "login_window_seconds": LOGIN_WINDOW_SECONDS,
        "login_max_attempts": LOGIN_MAX_ATTEMPTS,
    }


@app.post("/token")
async def token(x: L, request: Request):
    key = _login_key(request, x.username)
    if _is_limited(key):
        _audit(request, action="auth.login", outcome="rate_limited", actor=x.username, details={"username": x.username})
        raise HTTPException(429, "too_many_attempts")

    try:
        token_value = await auth_impl.login(x.username, x.password)
        _clear_fails(key)
        _audit(request, action="auth.login", outcome="success", actor=x.username, details={"username": x.username})
        return {"access_token": token_value, "token_type": "bearer"}
    except HTTPException:
        _register_fail(key)
        _audit(request, action="auth.login", outcome="failed", actor=x.username, details={"username": x.username})
        raise
    except Exception as e:
        _register_fail(key)
        _audit(request, action="auth.login", outcome="failed", actor=x.username, details={"username": x.username})
        raise HTTPException(401, str(e))


@app.get("/me")
async def me(u=Depends(_me)):
    return {"sub": u.get("sub"), "roles": u.get("roles", [])}


@app.get("/modules/state")
async def modules_state(u=Depends(_need("admin"))):
    st = _load().get("installed", {})
    ms = []
    for m in _mods():
        ms.append({"id": m, "installed": (m in st), "desc": ""})
    return {"modules": ms, "updated": _load().get("updated", 0)}


@app.post("/modules/apply")
async def modules_apply(
    x: M,
    request: Request,
    confirm: str | None = Header(default=None, alias="X-Confirm"),
    u=Depends(_need("admin")),
):
    if confirm != "YES":
        raise HTTPException(428, "missing_confirm")

    req = []
    for m in x.modules:
        if not re.fullmatch(r"[0-9A-Za-z_.-]+", m):
            raise HTTPException(400, f"bad:{m}")
        if m not in _mods():
            raise HTTPException(404, f"not_found:{m}")
        req.append(m)

    run = subprocess.run(["./init.sh", "apply", *req], cwd=ROOT, capture_output=True, text=True)
    if run.returncode != 0:
        _audit(
            request,
            action="modules.apply",
            outcome="failed",
            actor=u.get("sub", "admin"),
            details={"modules": req, "stderr": run.stderr[-500:]},
        )
        raise HTTPException(500, {"out": run.stdout[-2000:], "err": run.stderr[-2000:]})
    _audit(request, action="modules.apply", outcome="success", actor=u.get("sub", "admin"), details={"modules": req})
    return {"ok": True, "applied": req}


@app.post("/modules/reset")
async def modules_reset(
    request: Request,
    confirm: str | None = Header(default=None, alias="X-Confirm"),
    u=Depends(_need("admin")),
):
    if confirm != "YES":
        raise HTTPException(428, "missing_confirm")
    _save({"installed": {}})
    _audit(request, action="modules.reset", outcome="success", actor=u.get("sub", "admin"))
    return {"ok": True}


@app.get("/audit/logs")
async def audit_logs(limit: int = 100, u=Depends(_need("admin"))):
    items = _audit_tail(limit)
    return {"items": items, "count": len(items)}
PY

  cat > compose.d/40-api.yml <<'YML'
services:
  api:
    build: ./apps/api
    # Run as non-root user (matches Dockerfile USER appuser → UID 999)
    user: "999:999"
    environment:
      # ── Configuration ONLY — no secrets here ──────────────────────
      CORS_ORIGINS: ${CORS_ORIGINS:-https://localhost}
      AUTH_MODE: ${AUTH_MODE:-keycloak}
      OIDC_ISSUER: ${OIDC_ISSUER:-}
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID:-myapp-web}
      ENABLE_CONTROL_PLANE: ${ENABLE_CONTROL_PLANE:-0}
      BOOTSTRAP_MODE: ${BOOTSTRAP_MODE:-false}
      TRUSTED_PROXY_IPS: ${TRUSTED_PROXY_IPS:-172.16.0.0/12,10.0.0.0/8,192.168.0.0/16}
      FORCE_HTTPS: ${FORCE_HTTPS:-false}
      LOGIN_WINDOW_SECONDS: ${LOGIN_WINDOW_SECONDS:-120}
      LOGIN_MAX_ATTEMPTS: ${LOGIN_MAX_ATTEMPTS:-8}
      JWT_TTL_SECONDS: ${JWT_TTL_SECONDS:-3600}
      TPL_DATA_DIR: ${TPL_DATA_DIR:-/data}
      TPL_SECRETS_DIR: /run/secrets
    volumes:
      # State volume (API keys, users, audit logs)
      - ${TPL_DATA_DIR_HOST:-./data}:/data
      # Secrets: host secrets directory mounted read-only to /run/secrets
      # In Vault mode, 21-vault-agent.yml overrides this with tmpfs.
      - ${TPL_SECRETS_DIR_HOST:-./.secrets}:/run/secrets:ro
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
          pids: 100
        reservations:
          memory: 128M
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 30s
      timeout: 5s
      retries: 3

YML
}

check(){ true; }
rollback(){ rm -f compose.d/40-api.yml; }

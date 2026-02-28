import hashlib
import importlib.util
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr
from starlette.responses import JSONResponse

from . import auth_impl
from .secret_loader import get_secret, get_secret_metadata, load_all_secrets, reload_secrets, is_vault_mode
from .utils import file_lock, jsonl_append, jsonl_tail, RateLimiter

logger = logging.getLogger("tpl.api")

# ── Fail-fast: load & validate all secrets at import time ─────────────
# Secrets are loaded from (in priority order):
#   1. Vault tmpfs (/run/secrets/*) — RAM-only, encrypted at rest
#   2. *_FILE env vars (Docker secrets)
# No env var fallback — API refuses to start if secrets are missing.
load_all_secrets()

# ── Paths — state lives on the TPL_DATA_DIR volume ────────────────────
DATA = os.getenv("TPL_DATA_DIR", "/data")
os.makedirs(DATA, exist_ok=True)
# Modules live on the data volume as artifacts; /work/modules is a ro mount
# of /data/modules/current. Fallback to /work/modules for backwards compat.
MOD_DATA = os.path.join(DATA, "modules", "current")
ROOT = "/work" if os.path.isdir("/work/modules") else "/"
MOD = MOD_DATA if os.path.isdir(MOD_DATA) else os.path.join(ROOT, "modules")
STATE = os.path.join(DATA, ".tpl_state.json")
AUDIT_LOG = os.path.join(DATA, ".tpl_audit.jsonl")

# ── Platform version (single source of truth: VERSION.json) ───────────
_VERSION_INFO: dict = {}
def _load_version_info() -> dict:
    """Load VERSION.json from repo root / Docker mount."""
    global _VERSION_INFO
    if _VERSION_INFO:
        return _VERSION_INFO
    # parents[3] reaches project root on host; inside Docker the path is
    # shallower so we guard with a length check.
    _p = Path(__file__).resolve().parents
    candidates = [
        _p[3] / "VERSION.json" if len(_p) > 3 else None,
        Path("/app/VERSION.json"),
        Path(os.environ.get("TPL_ROOT", "")) / "VERSION.json",
        Path(DATA) / "VERSION.json",
    ]
    for p in candidates:
        try:
            if p and p.is_file():
                _VERSION_INFO = json.loads(p.read_text(encoding="utf-8"))
                return _VERSION_INFO
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    _VERSION_INFO = {"version": "3.5.1", "build": 0, "full_version": "3.5.1", "codename": "Horizon"}
    return _VERSION_INFO
ENGINES_DIR = Path(__file__).resolve().parent / "engines"

LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "120"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "8"))
# Control plane (module apply + reset) is DISABLED by default for security.
# Set ENABLE_CONTROL_PLANE=1 to allow runtime module management via API.
ENABLE_CONTROL_PLANE = os.getenv("ENABLE_CONTROL_PLANE", "0") == "1"
# Control plane hardening: restrict to admin-net CIDRs only (break-glass pattern)
# Set CONTROL_PLANE_CIDRS to a comma-separated list of allowed source CIDRs.
# Default: only loopback + RFC1918 (no public internet).
_CP_NETS: list = []
for _cp_cidr in os.getenv("CONTROL_PLANE_CIDRS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128").split(","):
    _cp_cidr = _cp_cidr.strip()
    if _cp_cidr:
        try:
            _CP_NETS.append(ipaddress.ip_network(_cp_cidr, strict=False))
        except ValueError:
            pass
# Rate limiter for control plane operations (stricter than login)
_cp_rate = RateLimiter(max_attempts=5, window_seconds=300)

def _guard_control_plane(request: Request, u: dict):
    """Break-glass guard: enforce network restriction + rate limit + severe audit."""
    client = _client_ip(request)
    actor = u.get("sub", "admin")
    # Network restriction
    try:
        addr = ipaddress.ip_address(client)
        allowed = any(addr in net for net in _CP_NETS)
    except ValueError:
        allowed = False
    if not allowed:
        _audit(request, "control_plane.denied", "network_blocked", actor,
               {"ip": client, "reason": "source_ip_outside_control_plane_cidr"})
        raise HTTPException(403, {
            "error": "control_plane_network_denied",
            "message": f"Control plane access denied from {client}. Must originate from admin network.",
        })
    # Rate limit control plane operations (per actor)
    if _cp_rate.is_limited(actor):
        _audit(request, "control_plane.denied", "rate_limited", actor,
               {"ip": client, "reason": "control_plane_rate_limit_exceeded"})
        raise HTTPException(429, "control_plane_rate_limited")
    _cp_rate.register_attempt(actor)

# ── API Key Manager (HMAC-peppered hashing, per-key scope/rate) ───────
from .api_key_manager import ApiKeyManager
_api_key_mgr = ApiKeyManager(data_dir=DATA)

_META_RE = re.compile(r"meta\s*\(\)\s*\{[\s\S]*?cat\s+<<[\'\"]JSON[\'\"]\s*\n([\s\S]*?)\nJSON", re.M)

def _extract_mod_meta(mod_id: str) -> dict:
    """Extract metadata (id, ver, desc, deps) from a shell module's meta() function."""
    path = os.path.join(MOD, mod_id + ".sh")
    if not os.path.isfile(path):
        return {"id": mod_id, "ver": "0.0.0", "desc": "", "deps": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read(8192)
        m = _META_RE.search(src)
        if m:
            return json.loads(m.group(1))
    except Exception:
        pass
    return {"id": mod_id, "ver": "0.0.0", "desc": "", "deps": []}

_rate_limiter = RateLimiter(max_attempts=LOGIN_MAX_ATTEMPTS, window_seconds=LOGIN_WINDOW_SECONDS)

# ── Lifespan — non-blocking startup probe for auth backend ────────
@asynccontextmanager
async def _lifespan(app: FastAPI):
    """FastAPI lifespan: launch OIDC startup probe (runs in a daemon thread)."""
    await auth_impl.run_startup_probe()  # fires a daemon thread, returns immediately
    yield

app = FastAPI(title="TPL API", version=_load_version_info().get("version", "3.5.1"), root_path="/api", lifespan=_lifespan)

# CORS: parse explicit origins from env (comma-separated). Never allow "*" with credentials.
_cors_origins_raw = os.getenv("CORS_ORIGINS", "")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip() and o.strip() != "*"]
if not _cors_origins:
    # Safe fallback: only allow same-origin (no CORS) when unconfigured
    _tpl_url = os.getenv("TPL_URL", "https://localhost:8443")
    _cors_origins = [_tpl_url]
    logger.warning("CORS_ORIGINS empty or wildcard — restricting to %s", _tpl_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Confirm", "X-Request-ID", "X-API-Key"],
)

class LoginRequest(BaseModel):
  username: constr(strip_whitespace=True, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
  password: constr(min_length=1, max_length=128)
class RefreshRequest(BaseModel):
  refresh_token: constr(min_length=1, max_length=512)
class LogoutRequest(BaseModel):
  session_id: str = ""
class ModuleApplyRequest(BaseModel):
  modules: list[str]

# ── Trusted proxy CIDR list (only trust X-Forwarded-For from these) ───
_TRUSTED_PROXY_NETS: list = []
_trusted_raw = os.getenv("TRUSTED_PROXY_IPS", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.0/8,::1/128")
for _cidr in _trusted_raw.split(","):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            _TRUSTED_PROXY_NETS.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            pass

def _ip_is_trusted(ip_str: str) -> bool:
    """Check if an IP address falls within trusted proxy CIDRs."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _TRUSTED_PROXY_NETS)
    except ValueError:
        return False

FORCE_HTTPS = os.getenv("FORCE_HTTPS", "false").lower() in ("true", "1", "yes")

# ── Must-change-password guard ─────────────────────────────────────────────
# If the JWT contains must_change_password=true, block ALL endpoints except
# the ones needed to actually change the password and re-authenticate.
_MCP_ALLOWED = {"/health", "/status", "/token", "/me", "/users/me/password",
                "/auth/refresh", "/auth/logout", "/auth/logout-all",
                "/auth/password-policy", "/auth/keys/public"}

@app.middleware("http")
async def must_change_password_guard(request: Request, call_next):
  from urllib.parse import unquote
  path = unquote(request.url.path).rstrip("/")
  # Normalize double slashes
  while "//" in path:
    path = path.replace("//", "/")
  # Strip /api prefix (root_path) if present
  if path.startswith("/api"):
    path = path[4:] or "/"
  # Only guard authenticated endpoints (skip allowed ones)
  if path not in _MCP_ALLOWED:
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
      tok = auth_header.split(None, 1)[1].strip()
      try:
        u = await auth_impl.me(tok)
        if u.get("must_change_password", False):
          return JSONResponse(
            status_code=403,
            content={"detail": "must_change_password", "message": "Devi cambiare la password prima di accedere."},
          )
      except Exception:
        pass  # invalid token — let downstream handle it
  return await call_next(request)

@app.middleware("http")
async def hardening_headers(request: Request, call_next):
  response = await call_next(request)
  response.headers.setdefault("X-Content-Type-Options", "nosniff")
  response.headers.setdefault("X-Frame-Options", "DENY")
  response.headers.setdefault("Referrer-Policy", "no-referrer")
  response.headers.setdefault("Cache-Control", "no-store")
  response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", uuid4().hex)
  # HSTS: only when FORCE_HTTPS=true or request came via HTTPS
  if FORCE_HTTPS or request.headers.get("X-Forwarded-Proto") == "https":
    response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
  return response

def _client_ip(request: Request) -> str:
  """Extract client IP safely. Only trust X-Forwarded-For when the direct
  peer (request.client.host) is in TRUSTED_PROXY_IPS. When trusted, take the
  rightmost non-trusted IP from the XFF chain."""
  peer = request.client.host if request.client else "unknown"
  fwd = request.headers.get("X-Forwarded-For", "")
  if fwd and _ip_is_trusted(peer):
    parts = [p.strip() for p in fwd.split(",") if p.strip()]
    # Walk from right to left, skip trusted proxies, return first untrusted
    for ip in reversed(parts):
      if not _ip_is_trusted(ip):
        return ip
    # All IPs in chain are trusted → return leftmost
    return parts[0] if parts else peer
  return peer

@contextmanager
def _file_lock(filepath: str, exclusive: bool = True):
  """Delegate to shared utils.file_lock for backward compatibility."""
  with file_lock(filepath, exclusive):
    yield

_AUDIT_PREV_HASH = "0" * 64  # genesis hash for audit chain
_AUDIT_CHAIN_LOCK = threading.Lock()  # protects hash chain computation

def _recover_audit_hash():
  """Recover last audit hash from log file on startup to maintain chain integrity."""
  global _AUDIT_PREV_HASH
  if not os.path.isfile(AUDIT_LOG):
    return
  try:
    last_line = ""
    with open(AUDIT_LOG, "rb") as f:
      # Seek from end to find last non-empty line efficiently
      f.seek(0, 2)
      pos = f.tell()
      if pos == 0:
        return
      buf = b""
      while pos > 0:
        pos = max(pos - 4096, 0)
        f.seek(pos)
        buf = f.read(4096) + buf
        lines = buf.split(b"\n")
        non_empty = [l for l in lines if l.strip()]
        if non_empty:
          last_line = non_empty[-1].decode("utf-8", errors="replace")
          break
    if last_line:
      entry = json.loads(last_line)
      if "hash" in entry:
        _AUDIT_PREV_HASH = entry["hash"]
  except Exception:
    pass  # start fresh if recovery fails

_recover_audit_hash()

def _audit(request: Request, action: str, outcome: str, actor: str = "anonymous", details: dict | None = None):
  global _AUDIT_PREV_HASH
  entry = {"ts": int(time.time()),"action": action,"outcome": outcome,"actor": actor,"ip": _client_ip(request),"request_id": request.headers.get("X-Request-ID", ""),"details": details or {}}
  try:
    with _AUDIT_CHAIN_LOCK:
      # Tamper-evident hash chain: each record includes hash of previous record
      entry["prev_hash"] = _AUDIT_PREV_HASH
      record_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
      entry["hash"] = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
      _AUDIT_PREV_HASH = entry["hash"]
      with _file_lock(AUDIT_LOG, exclusive=True):
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
          f.write(json.dumps(entry, separators=(",", ":")) + "\n")
  except Exception as e:
    print(f"WARN: audit write failed: {e}", file=sys.stderr)

def _audit_internal(action: str, outcome: str, actor: str = "system", details: dict | None = None):
  """Audit helper for non-request contexts (startup, engine loading, etc.)."""
  global _AUDIT_PREV_HASH
  entry = {"ts": int(time.time()),"action": action,"outcome": outcome,"actor": actor,"ip": "127.0.0.1","request_id": "","details": details or {}}
  try:
    with _AUDIT_CHAIN_LOCK:
      entry["prev_hash"] = _AUDIT_PREV_HASH
      record_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
      entry["hash"] = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
      _AUDIT_PREV_HASH = entry["hash"]
      with _file_lock(AUDIT_LOG, exclusive=True):
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
          f.write(json.dumps(entry, separators=(",", ":")) + "\n")
  except Exception as e:
    print(f"WARN: audit write failed: {e}", file=sys.stderr)

def _audit_tail(limit: int = 100):
  """Read last N audit records using shared JSONL utility."""
  return jsonl_tail(AUDIT_LOG, limit)

def _login_key(request: Request, username: str) -> str: return f"{_client_ip(request)}:{username.lower()}"
def _register_fail(key: str): _rate_limiter.register_attempt(key)
def _clear_fails(key: str): _rate_limiter.clear(key)
def _is_limited(key: str) -> bool: return _rate_limiter.is_limited(key)

def _load():
  try:
    with _file_lock(STATE, exclusive=False):
      with open(STATE, "r", encoding="utf-8") as f: return json.load(f)
  except Exception:
    return {"installed": {}, "updated": 0}
def _save(o):
  o["updated"] = int(time.time())
  with _file_lock(STATE, exclusive=True):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(o, f, separators=(",", ":"))
    os.replace(tmp, STATE)  # atomic rename
def _mods():
  if not os.path.isdir(MOD): return []
  out=[]
  for fn in sorted(os.listdir(MOD)):
    if fn.endswith(".sh") and re.fullmatch(r"[0-9A-Za-z_.-]+\.sh", fn): out.append(fn[:-3])
  return out

async def _tok(authorization: str | None = Header(default=None)):
  if not authorization or not authorization.lower().startswith("bearer "): raise HTTPException(401, "missing_token")
  return authorization.split(None, 1)[1].strip()
async def _me(token=Depends(_tok)):
  try: return await auth_impl.me(token)
  except HTTPException: raise
  except Exception as e: raise HTTPException(401, str(e))
async def _me_or_apikey(request: Request, authorization: str | None = Header(default=None)):
  """Authenticate via Bearer JWT token OR X-API-Key header.
  X-API-Key is for machine-to-machine calls; returns a synthetic user dict."""
  api_key = request.headers.get("X-API-Key")
  if api_key:
    valid, meta = _api_key_mgr.validate_key(api_key)
    if not valid:
      if meta and meta.get("reason") == "rate_limited":
        raise HTTPException(429, "api_key_rate_limited")
      raise HTTPException(401, "invalid_api_key")
    return {"sub": f"apikey:{meta['owner']}", "roles": meta.get("scopes", ["read"]),
            "key_id": meta["key_id"], "fingerprint": meta["fingerprint"]}
  if not authorization or not authorization.lower().startswith("bearer "):
    raise HTTPException(401, "missing_token")
  token = authorization.split(None, 1)[1].strip()
  try: return await auth_impl.me(token)
  except HTTPException: raise
  except Exception as e: raise HTTPException(401, str(e))
def _need(role: str):
  async def dep(u=Depends(_me)):
    if role not in set(u.get("roles", [])): raise HTTPException(403, "forbidden")
    return u
  return dep

@app.get("/health")
def health(): return {"ok": True}
@app.get("/status")
def status():
  # Expose operational info + auth health + platform version.
  auth_health = auth_impl.get_auth_health()
  vi = _load_version_info()
  return {
      "ok": True,
      "ts": int(time.time()),
      "auth": auth_health,
      "platform": {
          "version": vi.get("version", ""),
          "build": vi.get("build", 0),
          "full_version": vi.get("full_version", ""),
          "codename": vi.get("codename", ""),
          "channel": vi.get("channel", "stable"),
      },
  }
@app.post("/token")
async def token(x: LoginRequest, request: Request):
  key = _login_key(request, x.username)
  if _is_limited(key):
    _audit(request, "auth.login", "rate_limited", x.username, {"username": x.username})
    raise HTTPException(429, "too_many_attempts")
  try:
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "unknown")
    result = await auth_impl.login(x.username, x.password, ip=ip, user_agent=ua)
    _clear_fails(key)
    _audit(request, "auth.login", "success", x.username, {"username": x.username})
    # result is a dict (fortress) or string (keycloak)
    if isinstance(result, dict):
      return result
    return {"access_token": result, "token_type": "bearer"}
  except HTTPException as exc:
    if exc.status_code == 401:
      _register_fail(key)
    _audit(request, "auth.login", "failed", x.username, {"username": x.username, "status": exc.status_code})
    raise
  except Exception:
    _register_fail(key)
    _audit(request, "auth.login", "failed", x.username, {"username": x.username})
    raise HTTPException(401, "bad_creds")

@app.post("/auth/refresh")
async def auth_refresh(x: RefreshRequest, request: Request):
  """Refresh access token using a one-time-use refresh token.
  Returns new access_token + new refresh_token (rotation)."""
  ip = _client_ip(request)
  ua = request.headers.get("User-Agent", "unknown")
  try:
    result = await auth_impl.do_refresh(x.refresh_token, ip, ua)
    _audit(request, "auth.refresh", "success", result.get("session_id", "")[:8])
    return result
  except HTTPException:
    _audit(request, "auth.refresh", "failed", "unknown")
    raise
  except NotImplementedError:
    raise HTTPException(501, "refresh_not_available")

@app.post("/auth/logout")
async def auth_logout(request: Request, x: LogoutRequest = None, token=Depends(_tok)):
  """Logout: revoke current session and block access token."""
  session_id = x.session_id if x else ""
  result = await auth_impl.do_logout(token, session_id or None)
  _audit(request, "auth.logout", "success", "user", {"session_id": session_id})
  return result

@app.post("/auth/logout-all")
async def auth_logout_all(request: Request, token=Depends(_tok)):
  """Logout from ALL sessions. Blocks all current access tokens."""
  result = await auth_impl.do_logout_all(token)
  _audit(request, "auth.logout_all", "success", "user")
  return result

@app.get("/auth/sessions")
async def auth_sessions(u=Depends(_me)):
  """List active sessions for the current user."""
  sessions = auth_impl.do_list_sessions(u.get("sub", ""))
  return {"sessions": sessions, "count": len(sessions)}

@app.delete("/auth/sessions/{session_id}")
async def auth_revoke_session(session_id: str, request: Request, u=Depends(_me)):
  """Revoke a specific session (own sessions or admin for any)."""
  ok = auth_impl.do_revoke_session(session_id, "user_revoke")
  if not ok:
    raise HTTPException(404, "session_not_found")
  _audit(request, "auth.session_revoke", "success", u.get("sub", ""), {"session_id": session_id})
  return {"ok": True, "revoked": session_id}

@app.get("/auth/password-policy")
async def auth_password_policy():
  """Get current password policy for client-side validation display."""
  return auth_impl.do_get_password_policy()

@app.get("/auth/keys/public")
async def auth_public_key():
  """Get the current Ed25519 public key (PEM) for external JWT verification.
  Safe to expose — this is the PUBLIC key."""
  if auth_impl.AUTH_MODE in ("keycloak", "oidc"):
    raise HTTPException(501, "Use JWKS endpoint for Keycloak mode")
  from . import crypto_keys
  return {
    "algorithm": crypto_keys.get_algorithm(),
    "key_id": crypto_keys.get_current_key_id(),
    "public_key_pem": crypto_keys.get_public_key_pem(),
  }

@app.post("/auth/keys/rotate")
async def auth_rotate_keys(request: Request, u=Depends(_need("admin"))):
  """Rotate Ed25519 signing keys. Previous key enters grace period."""
  if auth_impl.AUTH_MODE in ("keycloak", "oidc"):
    raise HTTPException(501, "Key rotation managed by Keycloak")
  from . import crypto_keys
  new_kid = crypto_keys.rotate_keys()
  _audit(request, "auth.key_rotate", "success", u.get("sub", "admin"), {"new_key_id": new_kid})
  return {"ok": True, "new_key_id": new_kid, "status": crypto_keys.get_status()}

@app.get("/me")
async def me(u=Depends(_me)):
  return {
      "sub": u.get("sub"),
      "roles": u.get("roles", []),
      "must_change_password": u.get("must_change_password", False),
  }

# ── Engine Registry ───────────────────────────────────────────────────
@app.get("/engines/registry")
async def engines_registry(u=Depends(_need("admin"))):
  """Return the engine registry with SHA-256 hashes and load status."""
  registry = getattr(app.state, "engine_registry", {})
  return {"engines": registry, "count": len(registry)}

@app.get("/modules/state")
async def modules_state(u=Depends(_need("admin"))):
  st = _load(); installed = st.get("installed", {}); ms=[]
  for m in _mods():
    meta = _extract_mod_meta(m)
    inst_info = installed.get(m, {})
    ms.append({
      "id": m,
      "installed": (m in installed),
      "desc": meta.get("desc", ""),
      "ver": meta.get("ver", "0.0.0"),
      "installed_version": inst_info.get("ver", "") if m in installed else "",
      "available_version": meta.get("ver", "0.0.0"),
      "deps": meta.get("deps", []),
      "installed_at": inst_info.get("ts", 0) if m in installed else 0,
      "needs_update": (m in installed and inst_info.get("ver", "0") != meta.get("ver", "0")),
    })
  return {"modules": ms, "updated": st.get("updated", 0)}
@app.post("/modules/apply")
async def modules_apply(x: ModuleApplyRequest, request: Request, confirm: str | None = Header(default=None, alias="X-Confirm"), u=Depends(_need("admin"))):
  # ── DEPRECATED: Module apply via HTTP is disabled in production. ──
  # Module installation now happens ONLY via the tpl-modules CLI tool
  # which provides signed bundle verification, atomic updates, and rollback.
  # Set ENABLE_CONTROL_PLANE=1 ONLY for development/bootstrap.
  _audit(request, "modules.apply", "rejected", u.get("sub", "admin"),
         {"reason": "deprecated_use_cli" if not ENABLE_CONTROL_PLANE else "control_plane_active",
          "modules": x.modules})
  if not ENABLE_CONTROL_PLANE:
    raise HTTPException(403, {
      "error": "module_apply_disabled",
      "message": "L'installazione moduli via API è disabilitata in produzione. "
                 "Utilizzare il CLI: scripts/tpl-modules install <bundle.tar.gz>",
      "docs": "https://github.com/tpl/docs/blob/main/modules.md",
      "cli_command": "scripts/tpl-modules install <bundle.tar.gz>",
    })
  # ── Break-glass hardening: network restriction + rate limit ──
  _guard_control_plane(request, u)
  # Dev-only fallback: still allow subprocess execution when ENABLE_CONTROL_PLANE=1
  if not os.path.isdir(MOD):
    raise HTTPException(503, "modules_dir_missing: mount modules volume when ENABLE_CONTROL_PLANE=1")
  if confirm != "YES": raise HTTPException(428, "missing_confirm")
  req=[]
  allowed = _mods()
  for m in x.modules:
    if not re.fullmatch(r"[0-9A-Za-z_.-]+", m): raise HTTPException(400, f"bad:{m}")
    if m not in allowed: raise HTTPException(404, f"not_found:{m}")
    req.append(m)
  _audit(request,"modules.apply","started",u.get("sub","admin"),{"modules":req,"mode":"dev_control_plane"})
  run = subprocess.run(["./init.sh", "apply", *req], cwd=ROOT, capture_output=True, text=True, timeout=300)
  if run.returncode != 0:
    _audit(request,"modules.apply","failed",u.get("sub","admin"),{"modules":req,"stderr":run.stderr[-500:]})
    raise HTTPException(500,{"out":run.stdout[-2000:],"err":run.stderr[-2000:]})
  _audit(request,"modules.apply","success",u.get("sub","admin"),{"modules":req,"mode":"dev_control_plane"})
  return {"ok": True, "applied": req, "warning": "DEPRECATED: Use tpl-modules CLI for production installs"}
@app.post("/modules/reset")
async def modules_reset(request: Request, confirm: str | None = Header(default=None, alias="X-Confirm"), u=Depends(_need("admin"))):
  # ── DEPRECATED: Use tpl-modules rollback instead ──
  _audit(request, "modules.reset", "rejected", u.get("sub", "admin"),
         {"reason": "deprecated_use_cli" if not ENABLE_CONTROL_PLANE else "control_plane_active"})
  if not ENABLE_CONTROL_PLANE:
    raise HTTPException(403, {
      "error": "module_reset_disabled",
      "message": "Il reset moduli via API è disabilitato in produzione. "
                 "Utilizzare il CLI: scripts/tpl-modules rollback",
      "cli_command": "scripts/tpl-modules rollback",
    })
  # ── Break-glass hardening: network restriction + rate limit ──
  _guard_control_plane(request, u)
  # Dev-only fallback
  if confirm != "YES": raise HTTPException(428, "missing_confirm")
  _save({"installed": {}})
  _audit(request,"modules.reset","success",u.get("sub","admin"),{"mode":"dev_control_plane"})
  return {"ok": True, "warning": "DEPRECATED: Use tpl-modules CLI for production management"}
@app.get("/audit/logs")
async def audit_logs(limit: int = 100, u=Depends(_need("admin"))):
  items = _audit_tail(limit)
  return {"items": items, "count": len(items)}

# ── Secrets management endpoints (admin only) ─────────────────────────
@app.get("/secrets/status")
async def secrets_status(u=Depends(_need("admin"))):
  """Show secret sources and metadata — NEVER reveals secret values."""
  meta = get_secret_metadata()
  return {
    "vault_mode": is_vault_mode(),
    "secrets": meta,
    "ts": int(time.time()),
  }

@app.post("/secrets/reload")
async def secrets_reload(request: Request, u=Depends(_need("admin"))):
  """Hot-reload secrets from Vault tmpfs / files. For zero-downtime rotation."""
  _audit(request, "secrets.reload", "started", u.get("sub", "admin"))
  try:
    changes = reload_secrets()
    _audit(request, "secrets.reload", "success", u.get("sub", "admin"),
           {"changes": {k: v for k, v in changes.items() if v.get("changed")}})
    return {"ok": True, "changes": changes}
  except Exception as e:
    _audit(request, "secrets.reload", "failed", u.get("sub", "admin"),
           {"error": str(e)[:200]})
    raise HTTPException(500, f"Secret reload failed: {e}")

# ── API Key management endpoints (admin only) ────────────────────────

class ApiKeyCreate(BaseModel):
  owner: constr(strip_whitespace=True, min_length=1, max_length=64)
  scopes: list[str] = ["read"]
  rate_limit: int = 100
  rate_window: int = 60
  expires_in: int | None = None
  description: str = ""

@app.post("/api-keys")
async def create_api_key(x: ApiKeyCreate, request: Request, u=Depends(_need("admin"))):
  """Create a new API key. Returns the raw key ONCE — it cannot be recovered."""
  key_id, raw_key = _api_key_mgr.create_key(
    owner=x.owner, scopes=x.scopes, rate_limit=x.rate_limit,
    rate_window=x.rate_window, expires_in=x.expires_in, description=x.description,
  )
  _audit(request, "api_key.create", "success", u.get("sub", "admin"),
         {"key_id": key_id, "owner": x.owner, "fingerprint": _api_key_mgr.fingerprint(raw_key)})
  return {
    "key_id": key_id,
    "raw_key": raw_key,        # shown ONCE, never stored
    "fingerprint": _api_key_mgr.fingerprint(raw_key),
    "warning": "Save this key now — it cannot be retrieved again.",
  }

@app.get("/api-keys")
async def list_api_keys(u=Depends(_need("admin"))):
  """List all API keys (metadata only — never returns raw keys or hashes)."""
  return {"keys": _api_key_mgr.list_keys()}

@app.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, request: Request, u=Depends(_need("admin"))):
  """Immediately revoke an API key."""
  ok = _api_key_mgr.revoke_key(key_id)
  if not ok:
    raise HTTPException(404, "key_not_found")
  _audit(request, "api_key.revoke", "success", u.get("sub", "admin"), {"key_id": key_id})
  return {"ok": True, "revoked": key_id}

@app.post("/api-keys/validate")
async def validate_api_key_endpoint(request: Request, u=Depends(_need("admin"))):
  """Validate an API key (admin diagnostic endpoint)."""
  api_key = request.headers.get("X-API-Key", "")
  if not api_key:
    raise HTTPException(400, "missing X-API-Key header")
  valid, meta = _api_key_mgr.validate_key(api_key)
  return {"valid": valid, "meta": meta}

@app.post("/api-keys/cleanup")
async def cleanup_api_keys(request: Request, u=Depends(_need("admin"))):
  """Remove expired API keys from storage."""
  removed = _api_key_mgr.cleanup_expired()
  _audit(request, "api_key.cleanup", "success", u.get("sub", "admin"), {"removed": removed})
  return {"ok": True, "removed": removed}

def _register_builtin_context():
  app.state.tpl_context = {"require_role": _need,"audit": _audit,"client_ip": _client_ip,"auth_me": _me,"audit_tail": _audit_tail,"root": DATA,"engines_dir": str(ENGINES_DIR),"modules_dir": MOD}

def _load_engines():
  if not ENGINES_DIR.is_dir(): return
  registry_path = Path(DATA) / ".tpl_engine_registry.json"
  prev_registry = {}
  if registry_path.is_file():
    try:
      prev_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception:
      pass
  new_registry = {}
  tampered = []
  for file in sorted(ENGINES_DIR.glob("*_engine.py")):
    mod_name = f"app.engines.{file.stem}"
    try:
      raw = file.read_bytes()
      sha = hashlib.sha256(raw).hexdigest()
      # Check for drift against previous registry
      if file.name in prev_registry and prev_registry[file.name]["sha256"] != sha:
        tampered.append(file.name)
        _audit_internal("engine.drift", "warning", "system",
                        {"engine": file.name, "expected": prev_registry[file.name]["sha256"], "actual": sha})
      spec = importlib.util.spec_from_file_location(mod_name, file)
      if not spec or not spec.loader: continue
      module = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(module)
      register = getattr(module, "register", None)
      if callable(register): register(app)
      new_registry[file.name] = {"sha256": sha, "loaded_at": time.time(), "status": "ok"}
    except Exception as e:
      new_registry[file.name] = {"sha256": "", "loaded_at": time.time(), "status": f"error: {e}"}
      print(f"WARN: engine load failed: {file.name}: {e}")
  if tampered:
    print(f"SECURITY: engine drift detected in: {', '.join(tampered)}")
  # Persist registry
  try:
    registry_path.write_text(json.dumps(new_registry, indent=2), encoding="utf-8")
  except Exception:
    pass
  app.state.engine_registry = new_registry

_register_builtin_context(); auth_impl.set_app(app); _load_engines()

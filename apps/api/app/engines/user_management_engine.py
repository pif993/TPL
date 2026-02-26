"""
User Management Engine — gestione completa utenti TPL
=====================================================
- Anagrafica completa (nome, cognome, email, telefono, codice fiscale,
  indirizzo, città, provincia, CAP, data/luogo nascita, genere, note)
- CRUD utenti con validazione
- Gestione ruoli e autorizzazioni
- Cambio password self-service e admin-reset
- Attivazione / disattivazione / revoca account
- Ricerca e filtro utenti
- Tracciamento ultimo accesso
- Policy password (lunghezza, complessità)
"""

import json, os, re, time, hashlib, secrets, fcntl, tempfile
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, constr, Field, field_validator

from ..secret_loader import get_secret as _get_secret

# Argon2id hasher — OWASP recommended parameters
_ph = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=19456,  # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=__import__("argon2").Type.ID,  # Argon2id
)

# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------
PW_MIN = 8
PW_MAX = 128
PW_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{8,128}$"
)

VALID_ROLES = {"admin", "user", "editor", "viewer", "operator", "auditor"}

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class UserProfile(BaseModel):
  first_name: str = ""
  last_name: str = ""
  email: str = ""
  phone: str = ""
  fiscal_code: str = ""
  address: str = ""
  city: str = ""
  province: str = ""
  zip_code: str = ""
  birth_date: str = ""
  birth_place: str = ""
  gender: str = ""
  notes: str = ""

class UserCreate(BaseModel):
  username: constr(min_length=1, max_length=64, pattern="^[A-Za-z0-9_.-]+$")
  password: constr(min_length=8, max_length=128)
  roles: list = Field(default_factory=lambda: ["user"])
  profile: UserProfile = Field(default_factory=UserProfile)

  @field_validator("password")
  @classmethod
  def password_strength(cls, v):
    if not PW_PATTERN.match(v):
      raise ValueError(
        "La password deve contenere almeno: 1 maiuscola, 1 minuscola, "
        "1 numero, 1 carattere speciale e 8+ caratteri."
      )
    return v

  @field_validator("roles")
  @classmethod
  def validate_roles(cls, v):
    invalid = set(v) - VALID_ROLES
    if invalid:
      raise ValueError(f"Ruoli non validi: {', '.join(invalid)}. Ruoli ammessi: {', '.join(sorted(VALID_ROLES))}")
    return v

class UserUpdate(BaseModel):
  roles: list = Field(default_factory=list)
  active: bool = True
  profile: Optional[UserProfile] = None

  @field_validator("roles")
  @classmethod
  def validate_roles(cls, v):
    if v:
      invalid = set(v) - VALID_ROLES
      if invalid:
        raise ValueError(f"Ruoli non validi: {', '.join(invalid)}")
    return v

class ProfileUpdate(BaseModel):
  first_name: Optional[str] = None
  last_name: Optional[str] = None
  email: Optional[str] = None
  phone: Optional[str] = None
  fiscal_code: Optional[str] = None
  address: Optional[str] = None
  city: Optional[str] = None
  province: Optional[str] = None
  zip_code: Optional[str] = None
  birth_date: Optional[str] = None
  birth_place: Optional[str] = None
  gender: Optional[str] = None
  notes: Optional[str] = None

class PasswordChange(BaseModel):
  current_password: constr(min_length=1, max_length=128)
  new_password: constr(min_length=8, max_length=128)

  @field_validator("new_password")
  @classmethod
  def password_strength(cls, v):
    if not PW_PATTERN.match(v):
      raise ValueError(
        "La password deve contenere almeno: 1 maiuscola, 1 minuscola, "
        "1 numero, 1 carattere speciale e 8+ caratteri."
      )
    return v

class AdminPasswordReset(BaseModel):
  new_password: constr(min_length=8, max_length=128)
  force_change: bool = True

  @field_validator("new_password")
  @classmethod
  def password_strength(cls, v):
    if not PW_PATTERN.match(v):
      raise ValueError(
        "La password deve contenere almeno: 1 maiuscola, 1 minuscola, "
        "1 numero, 1 carattere speciale e 8+ caratteri."
      )
    return v

class RolesUpdate(BaseModel):
  roles: list

  @field_validator("roles")
  @classmethod
  def validate_roles(cls, v):
    invalid = set(v) - VALID_ROLES
    if invalid:
      raise ValueError(f"Ruoli non validi: {', '.join(invalid)}")
    return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_pw(password: str, salt: str = "") -> str:
  """Hash password with Argon2id. Returns PHC-format string ($argon2id$...)."""
  return _ph.hash(password)

def _verify_pw(password: str, stored: str) -> bool:
  """Verify password against stored hash.
  Supports Argon2id (preferred) and legacy salted-SHA256 for migration."""
  if stored.startswith("$argon2"):
    # Argon2id hash
    try:
      return _ph.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
      return False
  # Legacy: salted SHA-256 (salt:hex_digest) or unsalted SHA-256
  if ":" in stored:
    salt, expected = stored.split(":", 1)
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest() == expected
  return hashlib.sha256(password.encode("utf-8")).hexdigest() == stored

def _needs_rehash(stored: str) -> bool:
  """Check if hash needs upgrade to Argon2id (legacy SHA-256 → Argon2id)."""
  if not stored.startswith("$argon2"):
    return True  # Legacy hash needs migration
  try:
    return _ph.check_needs_rehash(stored)
  except Exception:
    return False

def _sanitize_profile(profile: dict) -> dict:
  """Sanitizza e valida il profilo anagrafico."""
  clean = {}
  for k in ("first_name", "last_name", "email", "phone", "fiscal_code",
            "address", "city", "province", "zip_code", "birth_date",
            "birth_place", "gender", "notes"):
    val = str(profile.get(k, "")).strip()[:256]
    clean[k] = val
  # Validazione email basilare
  if clean["email"] and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean["email"]):
    raise HTTPException(422, "invalid_email_format")
  # Validazione codice fiscale (formato IT: 16 chars alfanumerico)
  if clean["fiscal_code"]:
    cf = clean["fiscal_code"].upper().replace(" ", "")
    if not re.match(r"^[A-Z0-9]{16}$", cf):
      raise HTTPException(422, "invalid_fiscal_code_format")
    clean["fiscal_code"] = cf
  # Validazione genere
  if clean["gender"] and clean["gender"].upper() not in ("M", "F", "X", ""):
    raise HTTPException(422, "invalid_gender_value")
  if clean["gender"]:
    clean["gender"] = clean["gender"].upper()
  # Validazione CAP
  if clean["zip_code"] and not re.match(r"^\d{5}$", clean["zip_code"]):
    raise HTTPException(422, "invalid_zip_code_format")
  # Validazione provincia (2 lettere IT)
  if clean["province"]:
    clean["province"] = clean["province"].upper().strip()[:2]
  return clean

def _user_summary(username: str, data: dict) -> dict:
  """Restituisce riepilogo utente per le liste."""
  profile = data.get("profile", {})
  return {
    "username": username,
    "roles": data.get("roles", []),
    "active": data.get("active", True),
    "created": data.get("created", 0),
    "updated": data.get("updated", 0),
    "last_login": data.get("last_login", 0),
    "must_change_password": data.get("must_change_password", False),
    "first_name": profile.get("first_name", ""),
    "last_name": profile.get("last_name", ""),
    "email": profile.get("email", ""),
  }

def _user_detail(username: str, data: dict) -> dict:
  """Restituisce dettaglio completo utente."""
  profile = data.get("profile", {})
  return {
    "username": username,
    "roles": data.get("roles", []),
    "active": data.get("active", True),
    "created": data.get("created", 0),
    "updated": data.get("updated", 0),
    "last_login": data.get("last_login", 0),
    "must_change_password": data.get("must_change_password", False),
    "login_count": data.get("login_count", 0),
    "profile": {
      "first_name": profile.get("first_name", ""),
      "last_name": profile.get("last_name", ""),
      "email": profile.get("email", ""),
      "phone": profile.get("phone", ""),
      "fiscal_code": profile.get("fiscal_code", ""),
      "address": profile.get("address", ""),
      "city": profile.get("city", ""),
      "province": profile.get("province", ""),
      "zip_code": profile.get("zip_code", ""),
      "birth_date": profile.get("birth_date", ""),
      "birth_place": profile.get("birth_place", ""),
      "gender": profile.get("gender", ""),
      "notes": profile.get("notes", ""),
    }
  }

# ---------------------------------------------------------------------------
# Engine registration
# ---------------------------------------------------------------------------

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")
  auth_me = ctx["auth_me"]
  audit = ctx.get("audit")
  root = ctx["root"]
  users_file = os.path.join(root, ".tpl_users.json")
  _users_lock = __import__("threading").Lock()

  def load_users() -> dict:
    with _users_lock:
      if not os.path.isfile(users_file):
        # Seed default users from secret files (Vault tmpfs or *_FILE).
        # NEVER from environment variables — file-only secret model.
        admin_pw = _get_secret("TPL_ADMIN_PASSWORD", required=False) or ""
        user_pw = _get_secret("TPL_USER_PASSWORD", required=False) or ""
        if not admin_pw or not user_pw:
          raise HTTPException(500, "TPL_ADMIN_PASSWORD and TPL_USER_PASSWORD not found in /run/secrets")
        now = int(time.time())
        default_users = {
          "admin": {
            "pw_hash": _hash_pw(admin_pw),
            "roles": ["admin", "user"],
            "active": True,
            "created": now,
            "updated": now,
            "last_login": 0,
            "login_count": 0,
            "must_change_password": True,
            "profile": {
              "first_name": "Amministratore",
              "last_name": "Sistema",
              "email": "", "phone": "", "fiscal_code": "",
              "address": "", "city": "", "province": "", "zip_code": "",
              "birth_date": "", "birth_place": "", "gender": "", "notes": ""
            }
          },
          "user": {
            "pw_hash": _hash_pw(user_pw),
            "roles": ["user"],
            "active": True,
            "created": now,
            "updated": now,
            "last_login": 0,
            "login_count": 0,
            "must_change_password": True,
            "profile": {
              "first_name": "Utente",
              "last_name": "Standard",
              "email": "", "phone": "", "fiscal_code": "",
              "address": "", "city": "", "province": "", "zip_code": "",
              "birth_date": "", "birth_place": "", "gender": "", "notes": ""
            }
          }
        }
        save_users(default_users)
        return default_users
      with open(users_file, "r", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
          return json.load(f)
        finally:
          fcntl.flock(f, fcntl.LOCK_UN)

  def save_users(users: dict):
    """Atomic write: write to temp file, then rename to avoid corruption."""
    dir_name = os.path.dirname(users_file) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp", prefix=".tpl_users_")
    try:
      with os.fdopen(fd, "w", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(users, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
        fcntl.flock(f, fcntl.LOCK_UN)
      os.replace(tmp_path, users_file)
    except Exception:
      try:
        os.unlink(tmp_path)
      except OSError:
        pass
      raise

  # Expose helpers globally for auth_impl integration
  app.state.user_mgmt = {
    "load_users": load_users,
    "save_users": save_users,
    "verify_pw": _verify_pw,
    "hash_pw": _hash_pw,
  }

  # -----------------------------------------------------------------------
  # LIST users (admin)
  # -----------------------------------------------------------------------
  @app.get("/users")
  async def list_users(
    _: dict = Depends(require_admin),
    search: str = Query("", max_length=100),
    role: str = Query("", max_length=32),
    active_only: bool = Query(False),
  ):
    users = load_users()
    results = []
    for u, v in users.items():
      if active_only and not v.get("active", True):
        continue
      if role and role not in v.get("roles", []):
        continue
      if search:
        s = search.lower()
        profile = v.get("profile", {})
        haystack = " ".join([
          u, profile.get("first_name", ""), profile.get("last_name", ""),
          profile.get("email", ""), profile.get("fiscal_code", ""),
          profile.get("city", ""),
        ]).lower()
        if s not in haystack:
          continue
      results.append(_user_summary(u, v))
    return {"users": results, "total": len(results)}

  # -----------------------------------------------------------------------
  # GET user detail (admin)
  # -----------------------------------------------------------------------
  @app.get("/users/{username}")
  async def get_user(username: str, _: dict = Depends(require_admin)):
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    return {"user": _user_detail(username, users[username])}

  # -----------------------------------------------------------------------
  # CREATE user (admin)
  # -----------------------------------------------------------------------
  @app.post("/users")
  async def create_user(x: UserCreate, _: dict = Depends(require_admin)):
    users = load_users()
    if x.username in users:
      raise HTTPException(400, "username_exists")
    profile = _sanitize_profile(x.profile.model_dump())
    now = int(time.time())
    users[x.username] = {
      "pw_hash": _hash_pw(x.password),
      "roles": x.roles,
      "active": True,
      "created": now,
      "updated": now,
      "last_login": 0,
      "login_count": 0,
      "must_change_password": False,
      "profile": profile,
    }
    save_users(users)
    return {"ok": True, "username": x.username}

  # -----------------------------------------------------------------------
  # UPDATE user (admin) — ruoli, stato, profilo
  # -----------------------------------------------------------------------
  @app.put("/users/{username}")
  async def update_user(username: str, x: UserUpdate, _: dict = Depends(require_admin)):
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    user = users[username]
    if x.roles:
      user["roles"] = x.roles
    user["active"] = x.active
    if x.profile:
      profile = _sanitize_profile(x.profile.model_dump())
      user["profile"] = profile
    user["updated"] = int(time.time())
    save_users(users)
    return {"ok": True}

  # -----------------------------------------------------------------------
  # DELETE user (admin)
  # -----------------------------------------------------------------------
  @app.delete("/users/{username}")
  async def delete_user(username: str, _: dict = Depends(require_admin)):
    if username == "admin":
      raise HTTPException(400, "cannot_delete_admin")
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    del users[username]
    save_users(users)
    return {"ok": True}

  # -----------------------------------------------------------------------
  # ROLES management (admin)
  # -----------------------------------------------------------------------
  @app.put("/users/{username}/roles")
  async def update_roles(username: str, x: RolesUpdate, _: dict = Depends(require_admin)):
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    if username == "admin" and "admin" not in x.roles:
      raise HTTPException(400, "cannot_remove_admin_role_from_admin")
    users[username]["roles"] = x.roles
    users[username]["updated"] = int(time.time())
    save_users(users)
    return {"ok": True, "new_roles": x.roles}

  @app.get("/users/roles/available")
  async def available_roles(_: dict = Depends(require_admin)):
    return {"roles": sorted(VALID_ROLES)}

  # -----------------------------------------------------------------------
  # REVOKE / ACTIVATE (admin)
  # -----------------------------------------------------------------------
  @app.post("/users/{username}/revoke")
  async def revoke_user(username: str, _: dict = Depends(require_admin)):
    if username == "admin":
      raise HTTPException(400, "cannot_revoke_admin")
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    users[username]["active"] = False
    users[username]["updated"] = int(time.time())
    save_users(users)
    return {"ok": True, "status": "revoked"}

  @app.post("/users/{username}/activate")
  async def activate_user(username: str, _: dict = Depends(require_admin)):
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    users[username]["active"] = True
    users[username]["updated"] = int(time.time())
    save_users(users)
    return {"ok": True, "status": "active"}

  # -----------------------------------------------------------------------
  # PASSWORD change (self-service)
  # -----------------------------------------------------------------------
  @app.post("/users/me/password")
  async def change_my_password(x: PasswordChange, u: dict = Depends(auth_me)):
    from .. import auth_impl            # deferred to avoid circular import
    username = u.get("sub", "")
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    user = users[username]
    if not _verify_pw(x.current_password, user["pw_hash"]):
      raise HTTPException(400, "wrong_current_password")
    if x.current_password == x.new_password:
      raise HTTPException(400, "password_must_differ")
    # Validate new password against fortress security policy
    try:
      auth_impl.do_validate_new_password(x.new_password, username)
    except Exception as e:
      raise HTTPException(422, getattr(e, "message", str(e)))
    user["pw_hash"] = _hash_pw(x.new_password)
    user["must_change_password"] = False
    user["updated"] = int(time.time())
    save_users(users)
    # Record in credential vault so check_password_age won't re-force change
    auth_impl.do_record_password_change(username, x.new_password)
    return {"ok": True, "message": "password_changed"}

  # -----------------------------------------------------------------------
  # PASSWORD admin reset
  # -----------------------------------------------------------------------
  @app.post("/users/{username}/reset-password")
  async def admin_reset_password(username: str, x: AdminPasswordReset, _: dict = Depends(require_admin)):
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    users[username]["pw_hash"] = _hash_pw(x.new_password)
    users[username]["must_change_password"] = x.force_change
    users[username]["updated"] = int(time.time())
    save_users(users)
    return {"ok": True, "message": "password_reset", "force_change": x.force_change}

  # -----------------------------------------------------------------------
  # PROFILE self-update (authenticated user)
  # -----------------------------------------------------------------------
  @app.get("/users/me/profile")
  async def get_my_profile(u: dict = Depends(auth_me)):
    username = u.get("sub", "")
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    return {"user": _user_detail(username, users[username])}

  @app.put("/users/me/profile")
  async def update_my_profile(x: ProfileUpdate, u: dict = Depends(auth_me)):
    username = u.get("sub", "")
    users = load_users()
    if username not in users:
      raise HTTPException(404, "user_not_found")
    user = users[username]
    current = user.get("profile", {})
    updates = {k: v for k, v in x.model_dump().items() if v is not None}
    merged = {**current, **updates}
    user["profile"] = _sanitize_profile(merged)
    user["updated"] = int(time.time())
    save_users(users)
    return {"ok": True, "profile": user["profile"]}

  # -----------------------------------------------------------------------
  # STATISTICS (admin)
  # -----------------------------------------------------------------------
  @app.get("/users/stats/summary")
  async def user_stats(_: dict = Depends(require_admin)):
    users = load_users()
    total = len(users)
    active = sum(1 for v in users.values() if v.get("active", True))
    inactive = total - active
    roles_count = {}
    for v in users.values():
      for r in v.get("roles", []):
        roles_count[r] = roles_count.get(r, 0) + 1
    must_change = sum(1 for v in users.values() if v.get("must_change_password", False))
    return {
      "total": total,
      "active": active,
      "inactive": inactive,
      "must_change_password": must_change,
      "roles_distribution": roles_count,
    }

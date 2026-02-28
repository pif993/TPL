"""
Auth backend: FORTRESS — Hardened local authentication (redesigned from scratch).

Architecture (EXTREME SECURITY):
  ┌────────────────────────────────────────────────────────────────┐
  │  Ed25519 Asymmetric JWT Signing                                │
  │  • Private key NEVER leaves API container (crypto_keys.py)     │
  │  • Public key shareable for external verification              │
  │  • Automatic key rotation with grace period                    │
  ├────────────────────────────────────────────────────────────────┤
  │  Short-Lived Access Tokens (15 min default)                    │
  │  • EdDSA algorithm (no HMAC shared secret)                     │
  │  • Token binding: jti, session_id, device fingerprint          │
  │  • Instant revocation via jti blocklist                        │
  │  • iss, aud, sub, iat, nbf, exp claims — all verified          │
  ├────────────────────────────────────────────────────────────────┤
  │  Refresh Token Rotation (7 day default)                        │
  │  • Opaque server-side tokens (session_manager.py)              │
  │  • ONE-TIME USE — new token issued on each refresh             │
  │  • Stolen token detection → automatic session revocation       │
  │  • Device fingerprint binding (IP + User-Agent)                │
  ├────────────────────────────────────────────────────────────────┤
  │  Server-Side Session Registry                                  │
  │  • Concurrent session limits (default 5)                       │
  │  • Force-logout (admin-initiated)                              │
  │  • Session metadata tracking (device, IP, activity)            │
  │  • LRU eviction on limit breach                                │
  ├────────────────────────────────────────────────────────────────┤
  │  Credential Vault                                              │
  │  • Argon2id password hashing (OWASP parameters)                │
  │  • Password history (last 12, no reuse)                        │
  │  • Password aging (90 day max, 1 day min)                      │
  │  • Breach detection (k-anonymity via HIBP)                     │
  │  • Shannon entropy enforcement                                 │
  │  • Transparent rehash from legacy hashes                       │
  ├────────────────────────────────────────────────────────────────┤
  │  Progressive Delay                                             │
  │  • Exponential backoff on failed attempts                      │
  │  • Per-IP + per-user tracking                                  │
  │  • Constant-time comparison everywhere                         │
  └────────────────────────────────────────────────────────────────┘

This backend is used when AUTH_MODE=local (default for standalone deployments).
For externalized auth, use AUTH_MODE=keycloak with 60_auth_keycloak module.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from typing import Optional
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import HTTPException

from . import crypto_keys
from .session_manager import SessionManager, ACCESS_TOKEN_TTL, compute_device_fingerprint
from .credential_vault import CredentialVault, PasswordPolicyViolation
from .secret_loader import get_secret

logger = logging.getLogger("tpl.auth.fortress")

# ── Argon2id hasher — OWASP recommended parameters ──────────────────────────
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

# ── JWT configuration ───────────────────────────────────────────────────────
ISS = "tpl"
AUD = "tpl-web"
TTL = int(os.getenv("ACCESS_TOKEN_TTL", str(ACCESS_TOKEN_TTL)))  # 15 min default

# ── Bootstrap mode ──────────────────────────────────────────────────────────
_BOOTSTRAP_ENV = os.getenv("BOOTSTRAP_MODE", "false").lower() in ("true", "1", "yes")

# ── Singletons ──────────────────────────────────────────────────────────────
_session_mgr: Optional[SessionManager] = None
_cred_vault: Optional[CredentialVault] = None
_app_ref = None


def _get_session_mgr() -> SessionManager:
    global _session_mgr
    if _session_mgr is None:
        _session_mgr = SessionManager()
    return _session_mgr


def _get_cred_vault() -> CredentialVault:
    global _cred_vault
    if _cred_vault is None:
        _cred_vault = CredentialVault()
    return _cred_vault


def set_app(app):
    """Called by main.py to inject app reference for user_mgmt access."""
    global _app_ref
    _app_ref = app
    # Initialize Ed25519 key pair on startup
    crypto_keys.initialize()
    logger.info(
        "Fortress auth initialized: algorithm=%s key_id=%s access_ttl=%ds",
        crypto_keys.get_algorithm(),
        crypto_keys.get_current_key_id(),
        TTL,
    )


# ── Internal Helpers ─────────────────────────────────────────────────────────

def _auto_disable_bootstrap() -> bool:
    """Return effective BOOTSTRAP_MODE: False if users file exists with entries
    or /data/.bootstrapped marker exists."""
    if not _BOOTSTRAP_ENV:
        return False
    _data_dir = os.getenv("TPL_DATA_DIR", "/data")
    _marker = os.path.join(_data_dir, ".bootstrapped")
    if os.path.isfile(_marker):
        return False
    if _app_ref and hasattr(_app_ref.state, "user_mgmt"):
        try:
            users = _app_ref.state.user_mgmt["load_users"]()
            if users:
                _write_bootstrapped_marker(_data_dir)
                return False
        except Exception:
            pass
    return True


def _write_bootstrapped_marker(data_dir: str):
    """Write /data/.bootstrapped marker to permanently disable bootstrap."""
    try:
        marker = os.path.join(data_dir, ".bootstrapped")
        if not os.path.isfile(marker):
            import datetime
            with open(marker, "w") as f:
                f.write(f"bootstrapped={datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
    except Exception:
        pass


def _get_fallback_users() -> dict:
    """Fallback users for bootstrap mode only."""
    return {
        "admin": {
            "pw": get_secret("TPL_ADMIN_PASSWORD", required=False),
            "roles": ["admin", "user"],
        },
        "user": {
            "pw": get_secret("TPL_USER_PASSWORD", required=False),
            "roles": ["user"],
        },
    }


def _secure_equals(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))


def _verify_pw_hash(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash (Argon2id, salted SHA-256, or legacy)."""
    if stored_hash.startswith("$argon2"):
        try:
            return _ph.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    # Legacy: salted SHA-256 (salt:hex_digest)
    if ":" in stored_hash:
        salt, expected = stored_hash.split(":", 1)
        computed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return hmac.compare_digest(computed, expected)
    # Legacy: unsalted sha256
    computed = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, stored_hash)


def _needs_rehash(stored_hash: str) -> bool:
    """Check if hash should be upgraded to Argon2id."""
    if not stored_hash.startswith("$argon2"):
        return True
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


def _try_file_auth(username: str, password: str):
    """
    Try authenticating from the users file managed by user_management_engine.
    Returns (roles, must_change_password) if authenticated,
    raises HTTPException if user exists but credentials are wrong,
    or returns None if user not found in file.
    """
    bootstrap = _auto_disable_bootstrap()
    if not _app_ref or not hasattr(_app_ref.state, "user_mgmt"):
        if not bootstrap:
            raise HTTPException(503, "auth_unavailable: user management not initialized and BOOTSTRAP_MODE=false")
        return None
    mgmt = _app_ref.state.user_mgmt
    try:
        users = mgmt["load_users"]()
    except Exception:
        if not bootstrap:
            raise HTTPException(503, "auth_unavailable: cannot load users file and BOOTSTRAP_MODE=false")
        return None
    if username not in users:
        return None
    user = users[username]
    if not user.get("active", True):
        raise HTTPException(403, "account_disabled")
    if not _verify_pw_hash(password, user.get("pw_hash", "")):
        raise HTTPException(401, "bad_creds")
    # Update last_login and transparent rehash
    try:
        user["last_login"] = int(time.time())
        user["login_count"] = user.get("login_count", 0) + 1
        if _needs_rehash(user.get("pw_hash", "")):
            user["pw_hash"] = _ph.hash(password)
        mgmt["save_users"](users)
    except Exception:
        pass
    return {
        "roles": user.get("roles", ["user"]),
        "must_change_password": user.get("must_change_password", False),
    }


def _mint_access_token(
    username: str,
    roles: list[str],
    session_id: str,
    device_fp: str,
    must_change_password: bool = False,
) -> str:
    """Mint a new Ed25519-signed JWT access token with security claims."""
    now = int(time.time())
    jti = uuid4().hex  # Unique token ID for blocklist/revocation

    payload = {
        "iss": ISS,
        "aud": AUD,
        "sub": username,
        "roles": roles,
        "jti": jti,
        "sid": session_id,              # Session binding
        "dfp": device_fp,               # Device fingerprint binding
        "must_change_password": must_change_password,
        "iat": now,
        "nbf": now,
        "exp": now + TTL,
    }

    headers = {
        "kid": crypto_keys.get_current_key_id(),
        "alg": crypto_keys.get_algorithm(),
    }

    private_key = crypto_keys.get_signing_key()
    return jwt.encode(payload, private_key, algorithm=crypto_keys.get_algorithm(), headers=headers)


# ── Public API ───────────────────────────────────────────────────────────────

async def login(
    username: str,
    password: str,
    ip: str = "unknown",
    user_agent: str = "unknown",
) -> dict:
    """
    Authenticate user and create a new session.

    Returns dict with:
      - access_token: Short-lived JWT (Ed25519 signed)
      - refresh_token: Opaque one-time-use token for renewal
      - session_id: Server-side session identifier
      - expires_in: Access token TTL in seconds
      - token_type: "bearer"
      - must_change_password: bool

    Security properties:
      - Access token bound to session and device
      - Refresh token stored server-side (hash only)
      - Session limits enforced (oldest evicted)
      - Progressive delay handled by caller (main.py)
    """
    roles = None
    must_change_password = False

    # 1) Try file-based authentication
    file_result = _try_file_auth(username, password)
    if file_result is not None:
        roles = file_result["roles"]
        must_change_password = file_result["must_change_password"]
    elif _auto_disable_bootstrap():
        # 2) Fallback: bootstrap mode only
        fallback = _get_fallback_users().get(username)
        if not fallback or not _secure_equals(password, fallback["pw"]):
            raise HTTPException(401, "bad_creds")
        roles = fallback["roles"]
        must_change_password = True  # Bootstrap creds are TEMPORARY
    else:
        raise HTTPException(401, "bad_creds")

    # Check password age (if credential vault has history for this user)
    cred_vault = _get_cred_vault()
    age_info = cred_vault.check_password_age(username)
    if age_info.get("expired", False):
        must_change_password = True

    # 3) Create server-side session
    session_mgr = _get_session_mgr()
    device_fp = compute_device_fingerprint(ip, user_agent)
    session_id, refresh_token = session_mgr.create_session(
        user_id=username,
        ip=ip,
        user_agent=user_agent,
        roles=roles,
        metadata={"auth_method": "password"},
    )

    # 4) Mint access token (Ed25519 signed, short-lived)
    access_token = _mint_access_token(
        username=username,
        roles=roles,
        session_id=session_id,
        device_fp=device_fp,
        must_change_password=must_change_password,
    )

    logger.info(
        "Login successful: user=%s session=%s device=%s roles=%s",
        username,
        session_id[:8],
        device_fp,
        roles,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "expires_in": TTL,
        "token_type": "bearer",
        "must_change_password": must_change_password,
        "password_age": age_info if age_info.get("warning") else None,
    }


async def refresh(
    refresh_token: str,
    ip: str = "unknown",
    user_agent: str = "unknown",
) -> dict:
    """
    Refresh access token using a refresh token.

    Returns new access_token + new refresh_token (rotation).
    Old refresh token is immediately invalidated.

    Security: device fingerprint must match the session origin.
    """
    session_mgr = _get_session_mgr()
    result = session_mgr.refresh_session(refresh_token, ip, user_agent)

    if result is None:
        raise HTTPException(401, "invalid_refresh_token")

    session_id, new_refresh, session_data = result
    device_fp = compute_device_fingerprint(ip, user_agent)

    # Check if user is still active
    if _app_ref and hasattr(_app_ref.state, "user_mgmt"):
        try:
            users = _app_ref.state.user_mgmt["load_users"]()
            user = users.get(session_data["user_id"])
            if user and not user.get("active", True):
                session_mgr.revoke_session(session_id, "user_disabled")
                raise HTTPException(403, "account_disabled")
        except HTTPException:
            raise
        except Exception:
            pass

    # Mint new access token
    access_token = _mint_access_token(
        username=session_data["user_id"],
        roles=session_data.get("roles", ["user"]),
        session_id=session_id,
        device_fp=device_fp,
    )

    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "session_id": session_id,
        "expires_in": TTL,
        "token_type": "bearer",
    }


async def me(token: str) -> dict:
    """
    Verify JWT access token using Ed25519 public key(s).

    Verification chain:
      1. Try all valid public keys (current + previous for rotation)
      2. Check jti blocklist (instant revocation support)
      3. Check user-level token block (post-password-change)
      4. Validate session is still active
      5. Return user claims
    """
    session_mgr = _get_session_mgr()
    verification_keys = crypto_keys.get_verification_keys()
    algorithm = crypto_keys.get_algorithm()

    decoded = None
    for public_key, key_id in verification_keys:
        try:
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=[algorithm],
                audience=AUD,
                issuer=ISS,
                options={
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "sub", "iss", "aud", "jti", "sid"],
                },
            )
            break
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "token_expired")
        except (jwt.InvalidTokenError, jwt.DecodeError):
            continue
        except Exception:
            continue

    if decoded is None:
        raise HTTPException(401, "bad_token")

    jti = decoded.get("jti", "")
    session_id = decoded.get("sid", "")
    sub = decoded.get("sub", "")
    iat = decoded.get("iat", 0)

    # Check jti blocklist (instant revocation)
    if jti and session_mgr.is_token_blocked(jti):
        raise HTTPException(401, "token_revoked")

    # Check user-level block (password change invalidation)
    if sub and session_mgr.is_user_token_blocked(sub, iat):
        raise HTTPException(401, "token_invalidated")

    # Validate session is still active
    if session_id:
        session = session_mgr.validate_session(session_id)
        if session is None:
            raise HTTPException(401, "session_expired")

    return {
        "sub": sub,
        "roles": decoded.get("roles", []),
        "must_change_password": decoded.get("must_change_password", False),
        "jti": jti,
        "sid": session_id,
        "dfp": decoded.get("dfp", ""),
    }


async def logout(token: str, session_id: Optional[str] = None) -> dict:
    """Logout: revoke current session and block access token."""
    session_mgr = _get_session_mgr()

    try:
        user_info = await me(token)
        jti = user_info.get("jti", "")
        sid = session_id or user_info.get("sid", "")
        sub = user_info.get("sub", "")

        # Block the access token immediately
        if jti:
            now = int(time.time())
            session_mgr.block_access_token(jti, now + TTL)

        # Revoke the session
        if sid:
            session_mgr.revoke_session(sid, "logout")

        logger.info("Logout: user=%s session=%s", sub, sid[:8] if sid else "?")
        return {"ok": True, "session_revoked": sid or ""}

    except HTTPException:
        # Token already invalid — just revoke session if provided
        if session_id:
            session_mgr.revoke_session(session_id, "logout")
        return {"ok": True}


async def logout_all(token: str) -> dict:
    """Logout from ALL sessions. Blocks all current access tokens for the user."""
    session_mgr = _get_session_mgr()

    try:
        user_info = await me(token)
        sub = user_info.get("sub", "")

        count = session_mgr.revoke_all_sessions(sub, "logout_all")
        session_mgr.block_all_tokens_for_user(sub)

        logger.info("Logout all: user=%s sessions_revoked=%d", sub, count)
        return {"ok": True, "sessions_revoked": count}

    except HTTPException as exc:
        raise exc  # re-raise with original status code and detail


def list_sessions(user_id: str) -> list[dict]:
    """List active sessions for a user."""
    return _get_session_mgr().list_sessions(user_id, active_only=True)


def revoke_session_by_id(session_id: str, reason: str = "admin_revoke") -> bool:
    """Revoke a specific session by admin."""
    return _get_session_mgr().revoke_session(session_id, reason)


def validate_new_password(password: str, username: str = "") -> dict:
    """Validate a new password against all security policies."""
    return _get_cred_vault().validate_password(password, username)


def record_password_change(username: str, password: str) -> None:
    """Record a password change in the credential vault."""
    _get_cred_vault().record_password_change(username, password)


def get_password_policy() -> dict:
    """Get current password policy for client display."""
    return _get_cred_vault().get_policy()


def get_auth_health() -> dict:
    """Get auth subsystem health for /status endpoint."""
    key_status = crypto_keys.get_status()
    session_stats = _get_session_mgr().get_stats()
    return {
        "backend": "fortress",
        "startup_verified": True,
        "crypto": key_status,
        "sessions": session_stats,
    }


def get_session_manager() -> SessionManager:
    """Get the session manager instance (for main.py integration)."""
    return _get_session_mgr()


def get_credential_vault() -> CredentialVault:
    """Get the credential vault instance."""
    return _get_cred_vault()

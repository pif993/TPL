"""
TPL Auth Dispatcher — selects authentication backend based on AUTH_MODE.

Backends:
  local     → FORTRESS hardened local auth (DEFAULT — standalone deployments)
              Features: Ed25519 asymmetric JWT, refresh token rotation,
              server-side sessions, credential vault with breach detection,
              password history, progressive delay, device fingerprint binding.
              Redesigned from scratch for extreme security.

  keycloak  → Enterprise OIDC via Keycloak (external IdP)
              Requires: 60_auth_keycloak module, Keycloak + Postgres containers
              Features: JWKS token verification, realm roles, password policies,
              brute force protection, session management — all at IdP level.
              Pair with 20_vault for full secret management.

Set AUTH_MODE in .env or compose.d/50-auth.yml / compose.d/60-auth.yml.
Default: local (fortress mode).
"""

import os
import logging

AUTH_MODE = os.getenv("AUTH_MODE", "local").lower().strip()

logger = logging.getLogger("tpl.auth")
logger.info("Auth backend: %s", AUTH_MODE)

# ── Backend selection ────────────────────────────────────────────────────────
# Each backend must export: login, me, set_app
# Optional exports: refresh, logout, logout_all, list_sessions,
#                   validate_new_password, record_password_change,
#                   get_password_policy, get_session_manager, get_credential_vault

if AUTH_MODE in ("keycloak", "oidc"):
    from ._auth_keycloak import me, set_app
    from ._auth_keycloak import login as _kc_login

    async def login(username: str, password: str, **kwargs) -> str:
        """Keycloak login — kwargs (ip, user_agent) ignored."""
        return await _kc_login(username, password)

elif AUTH_MODE == "local":
    from ._auth_local import login, me, set_app
else:
    logger.warning("Unknown AUTH_MODE=%r, falling back to local (fortress)", AUTH_MODE)
    from ._auth_local import login, me, set_app


# ── Extended capabilities (fortress local backend) ───────────────────────────

async def do_refresh(refresh_token: str, ip: str = "unknown", user_agent: str = "unknown") -> dict:
    """Refresh access token. Only available with local backend."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import refresh
        return await refresh(refresh_token, ip, user_agent)
    raise NotImplementedError("Refresh tokens are managed by Keycloak in OIDC mode")


async def do_logout(token: str, session_id: str | None = None) -> dict:
    """Logout: revoke session and block token."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import logout
        return await logout(token, session_id)
    # Keycloak mode: no server-side session to revoke (KC manages sessions)
    return {"ok": True, "message": "client_logout_only"}


async def do_logout_all(token: str) -> dict:
    """Logout from ALL sessions."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import logout_all
        return await logout_all(token)
    return {"ok": True, "message": "client_logout_only"}


def do_list_sessions(user_id: str) -> list[dict]:
    """List active sessions for a user."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import list_sessions
        return list_sessions(user_id)
    return []


def do_revoke_session(session_id: str, reason: str = "admin_revoke") -> bool:
    """Revoke a specific session."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import revoke_session_by_id
        return revoke_session_by_id(session_id, reason)
    return False


def do_validate_new_password(password: str, username: str = "") -> dict:
    """Validate a new password against security policies."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import validate_new_password
        return validate_new_password(password, username)
    return {"valid": True, "checks": {}, "strength": "unknown"}


def do_record_password_change(username: str, password: str) -> None:
    """Record a password change in the credential vault."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import record_password_change
        record_password_change(username, password)


def do_get_password_policy() -> dict:
    """Get current password policy for client display."""
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import get_password_policy
        return get_password_policy()
    return {"min_length": 12, "require_uppercase": True, "require_lowercase": True,
            "require_digit": True, "require_special": True}


# ── Startup & Health ─────────────────────────────────────────────────────────

async def run_startup_probe() -> bool:
    """Run auth backend startup probe if available. Returns True on success."""
    if AUTH_MODE in ("keycloak", "oidc"):
        from ._auth_keycloak import startup_probe
        return await startup_probe()
    return True  # Fortress auth has no external dependency


def get_auth_health() -> dict:
    """Get auth backend health info for /status endpoint."""
    if AUTH_MODE in ("keycloak", "oidc"):
        from ._auth_keycloak import get_health
        return get_health()
    if AUTH_MODE not in ("keycloak", "oidc"):
        from ._auth_local import get_auth_health
        return get_auth_health()
    return {"backend": "local", "startup_verified": True}


__all__ = [
    "login", "me", "set_app",
    "run_startup_probe", "get_auth_health",
    "do_refresh", "do_logout", "do_logout_all",
    "do_list_sessions", "do_revoke_session",
    "do_validate_new_password", "do_record_password_change", "do_get_password_policy",
    "AUTH_MODE",
]

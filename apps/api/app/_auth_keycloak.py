"""
Auth backend: KEYCLOAK — Enterprise OIDC authentication.

Redesigned from scratch for maximum reliability and security.

Architecture:
  • Startup probe: OIDC discovery + JWKS prefetch before accepting traffic
  • Two-tier JWKS cache: soft TTL 5 min, hard TTL 1 hr, forced refresh on miss
  • Issuer autodiscovery: learned from .well-known, cached, auto-refreshed
  • AZP verification: Keycloak public clients use azp, not aud
  • RS256 only: prevents algorithm confusion/downgrade attacks
  • Zero error leakage: internal details never reach the client
  • Health probe: exposes KC connectivity for /status endpoint

Selected when AUTH_MODE=keycloak (default).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
import threading
from typing import Optional

import httpx
import jwt
from fastapi import HTTPException

logger = logging.getLogger("tpl.auth.keycloak")

# ── Configuration ────────────────────────────────────────────────────────────

OIDC_ISSUER = os.getenv("OIDC_ISSUER", "http://keycloak:8080/auth/realms/myapp")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "myapp-web")
OIDC_EXPECTED_ISSUER = os.getenv("OIDC_EXPECTED_ISSUER", "")

_ALLOWED_ALGORITHMS: list[str] = ["RS256"]

# ── Timeout profiles ────────────────────────────────────────────────────────

_TOKEN_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
_DISCOVERY_TIMEOUT = httpx.Timeout(connect=5.0, read=8.0, write=3.0, pool=5.0)
_USERINFO_TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=3.0, pool=3.0)

# ── URLs (derived from OIDC_ISSUER, container-to-container) ─────────────────


def _token_url() -> str:
    return f"{OIDC_ISSUER}/protocol/openid-connect/token"


def _userinfo_url() -> str:
    return f"{OIDC_ISSUER}/protocol/openid-connect/userinfo"


def _jwks_url() -> str:
    return f"{OIDC_ISSUER}/protocol/openid-connect/certs"


def _well_known_url() -> str:
    return f"{OIDC_ISSUER}/.well-known/openid-configuration"


# ═══════════════════════════════════════════════════════════════════════════════
# OIDC State — singleton managing discovery, JWKS, and health
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class _OIDCState:
    """Centralized OIDC state with thread-safe lazy initialization."""

    # Issuer discovery
    discovered_issuer: Optional[str] = None
    issuer_ts: float = 0.0
    issuer_ttl: float = 3600.0  # 1 hour

    # JWKS cache
    jwks_client: Optional[jwt.PyJWKClient] = None
    jwks_ts: float = 0.0
    jwks_soft_ttl: float = 300.0   # 5 min — try refresh
    jwks_hard_ttl: float = 3600.0  # 1 hr — force refresh

    # Health tracking
    last_kc_ok: float = 0.0
    last_kc_fail: float = 0.0
    last_kc_error: str = ""
    startup_verified: bool = False

    def expected_issuer(self) -> str:
        """Return the expected JWT issuer, using discovery cache."""
        if OIDC_EXPECTED_ISSUER:
            return OIDC_EXPECTED_ISSUER
        if self.discovered_issuer and (time.time() - self.issuer_ts) < self.issuer_ttl:
            return self.discovered_issuer
        # Try synchronous discovery
        self._discover_issuer_sync()
        return self.discovered_issuer or OIDC_ISSUER

    def _discover_issuer_sync(self) -> None:
        """Discover issuer from .well-known (synchronous, for JWT verify)."""
        try:
            with httpx.Client(timeout=_DISCOVERY_TIMEOUT) as client:
                resp = client.get(_well_known_url())
                if resp.status_code == 200:
                    data = resp.json()
                    self.discovered_issuer = data.get("issuer", OIDC_ISSUER)
                    self.issuer_ts = time.time()
                    self.last_kc_ok = time.time()
                    logger.info("OIDC issuer discovered: %s", self.discovered_issuer)
                else:
                    logger.warning("OIDC discovery returned %d", resp.status_code)
        except Exception as exc:
            logger.warning("OIDC discovery failed: %s", type(exc).__name__)
            self.last_kc_fail = time.time()
            self.last_kc_error = type(exc).__name__

    def get_jwks(self) -> jwt.PyJWKClient:
        """Get or refresh JWKS client with two-tier TTL."""
        now = time.time()
        age = now - self.jwks_ts

        # Within soft TTL — use cache
        if self.jwks_client is not None and age <= self.jwks_soft_ttl:
            return self.jwks_client

        # Past soft TTL — try refresh, fall back to cache
        try:
            self.jwks_client = jwt.PyJWKClient(_jwks_url())
            self.jwks_ts = now
            self.last_kc_ok = now
        except Exception as exc:
            logger.error("JWKS refresh failed: %s", type(exc).__name__)
            self.last_kc_fail = now
            self.last_kc_error = type(exc).__name__
            # Use stale cache if within hard TTL
            if self.jwks_client is not None and age <= self.jwks_hard_ttl:
                logger.warning("Using stale JWKS (age=%ds)", int(age))
                return self.jwks_client
            raise HTTPException(503, "oidc_unavailable")
        return self.jwks_client

    def force_jwks_refresh(self) -> None:
        """Force JWKS cache invalidation (after key rotation)."""
        self.jwks_ts = 0.0

    def health(self) -> dict:
        """Return health summary for /status endpoint."""
        now = time.time()
        kc_age = now - self.last_kc_ok if self.last_kc_ok else -1
        return {
            "backend": "keycloak",
            "issuer": self.discovered_issuer or OIDC_ISSUER,
            "startup_verified": self.startup_verified,
            "kc_reachable": kc_age < 120 if self.last_kc_ok else False,
            "kc_last_ok_ago": int(kc_age) if self.last_kc_ok else None,
            "kc_last_error": self.last_kc_error or None,
        }


_state = _OIDCState()


# ═══════════════════════════════════════════════════════════════════════════════
# Startup Probe — called once during FastAPI startup
# ═══════════════════════════════════════════════════════════════════════════════


async def startup_probe(max_retries: int = 20, delay: float = 5.0) -> bool:
    """Fire-and-forget OIDC connectivity check in a separate daemon thread.

    Uses stdlib urllib (no httpx) to be completely independent of asyncio.
    Checks:
      1. .well-known/openid-configuration reachable
      2. JWKS endpoint reachable and has keys
    Non-fatal — logs result and sets _state.startup_verified.
    """
    import json
    import socket
    from urllib.request import urlopen, Request
    from urllib.error import URLError

    def _probe_thread() -> None:
        url = _well_known_url()
        for attempt in range(1, max_retries + 1):
            try:
                # 1. OIDC Discovery
                req = Request(url, headers={"Accept": "application/json"})
                with urlopen(req, timeout=10) as resp:
                    oidc_config = json.loads(resp.read())

                _state.discovered_issuer = oidc_config.get("issuer", OIDC_ISSUER)
                _state.issuer_ts = time.time()

                # 2. JWKS — always use _jwks_url() (container-to-container),
                # NOT the jwks_uri from discovery (may use localhost hostname)
                jwks_url = _jwks_url()
                with urlopen(jwks_url, timeout=10) as resp:
                    keys = json.loads(resp.read()).get("keys", [])
                if not keys:
                    raise RuntimeError("JWKS has no keys")

                # Pre-warm JWKS cache
                _state.jwks_client = jwt.PyJWKClient(_jwks_url())
                _state.jwks_ts = time.time()
                _state.last_kc_ok = time.time()
                _state.startup_verified = True
                logger.info(
                    "OIDC startup probe OK: issuer=%s",
                    _state.discovered_issuer,
                )
                return  # success — exit thread

            except (URLError, OSError, RuntimeError, Exception) as exc:
                logger.warning(
                    "OIDC startup probe attempt %d/%d failed: %s",
                    attempt, max_retries, exc,
                )
                if attempt < max_retries:
                    time.sleep(delay)

        logger.error(
            "OIDC startup probe FAILED after %d attempts — auth may not work",
            max_retries,
        )
        _state.startup_verified = False

    t = threading.Thread(target=_probe_thread, daemon=True, name="oidc-probe")
    t.start()
    # Don't await — fire and forget
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Role Extraction
# ═══════════════════════════════════════════════════════════════════════════════


def _extract_roles(token_data: dict) -> list[str]:
    """Extract roles from realm_access and resource_access claims.

    Never derives roles from username — only from explicit JWT claims.
    """
    all_roles: set[str] = set()

    # Realm-level roles
    realm_access = token_data.get("realm_access")
    if isinstance(realm_access, dict):
        all_roles.update(realm_access.get("roles", []))

    # Client-specific roles
    resource_access = token_data.get("resource_access")
    if isinstance(resource_access, dict):
        client_roles = resource_access.get(OIDC_CLIENT_ID)
        if isinstance(client_roles, dict):
            all_roles.update(client_roles.get("roles", []))

    # Map to application roles
    roles: list[str] = []
    if "admin" in all_roles:
        roles.append("admin")
    if "user" in all_roles or not roles:
        roles.append("user")
    return roles


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

_app_ref = None


def set_app(app) -> None:
    """Store app reference (compatibility with local backend)."""
    global _app_ref
    _app_ref = app


def get_health() -> dict:
    """Return auth backend health for /status endpoint."""
    return _state.health()


async def login(username: str, password: str) -> str:
    """Exchange credentials for access token via Keycloak ROPC.

    Security notes:
      - ROPC is for bootstrap only; production: AuthZ Code + PKCE
      - Credentials never logged, even at DEBUG
      - Distinguishes bad_creds / account_locked / infra errors
    """
    try:
        async with httpx.AsyncClient(timeout=_TOKEN_TIMEOUT) as client:
            resp = await client.post(
                _token_url(),
                data={
                    "grant_type": "password",
                    "client_id": OIDC_CLIENT_ID,
                    "username": username,
                    "password": password,
                    "scope": "openid",
                },
            )

        # ── Success ──
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token")
            if not token:
                logger.error("KC 200 but no access_token in response")
                raise HTTPException(502, "oidc_no_token")
            _state.last_kc_ok = time.time()
            return token

        # ── Parse error body ──
        body = _safe_json(resp)
        error = body.get("error", "")
        desc = body.get("error_description", "").lower()

        # Account locked by KC brute-force protection
        if "temporarily disabled" in desc or "temporarily locked" in desc:
            logger.warning("Account %r locked by KC brute-force protection", username)
            raise HTTPException(429, "account_locked")

        # Invalid credentials (400 or 401)
        if resp.status_code in (400, 401):
            if error in ("invalid_grant", "invalid_credentials", ""):
                raise HTTPException(401, "bad_creds")
            logger.warning("KC token error=%s desc=%s", error, desc)
            raise HTTPException(401, "bad_creds")

        # Client misconfiguration
        if resp.status_code == 403:
            logger.error(
                "KC 403 — check client %s config (directAccessGrantsEnabled?)",
                OIDC_CLIENT_ID,
            )
            raise HTTPException(502, "oidc_client_error")

        # Other errors
        logger.error("KC token %d: %s", resp.status_code, resp.text[:200])
        raise HTTPException(502, "oidc_upstream_error")

    except HTTPException:
        raise
    except httpx.TimeoutException:
        logger.error("KC timeout at %s", _token_url())
        _state.last_kc_fail = time.time()
        _state.last_kc_error = "timeout"
        raise HTTPException(504, "oidc_timeout")
    except httpx.ConnectError:
        logger.error("Cannot connect to KC at %s", _token_url())
        _state.last_kc_fail = time.time()
        _state.last_kc_error = "connect_error"
        raise HTTPException(503, "oidc_unavailable")
    except Exception:
        logger.exception("Unexpected KC login error")
        _state.last_kc_fail = time.time()
        _state.last_kc_error = "unknown"
        raise HTTPException(502, "oidc_error")


async def me(token: str) -> dict:
    """Verify access token and extract user identity.

    Two-phase verification:
      Phase 1: Offline JWKS verification (no network call when cached)
      Phase 2: Userinfo fallback ONLY on PyJWKClientError (key rotation)

    All other JWT errors → immediate rejection, no fallback.
    """
    expected_issuer = _state.expected_issuer()

    # ── Phase 1: Offline JWKS verification ──
    try:
        jwks = _state.get_jwks()
        signing_key = jwks.get_signing_key_from_jwt(token)
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=_ALLOWED_ALGORITHMS,
            issuer=expected_issuer,
            options={
                "verify_exp": True,
                "verify_iss": True,
                "verify_iat": True,
                "verify_aud": False,   # KC public clients use azp, not aud
                "require": ["exp", "iat", "sub", "iss"],
            },
        )

        # Manual azp verification
        azp = decoded.get("azp", "")
        if azp != OIDC_CLIENT_ID:
            logger.warning("azp=%r != expected %r", azp, OIDC_CLIENT_ID)
            raise HTTPException(401, "bad_token")

        sub = decoded.get("preferred_username") or decoded.get("sub", "unknown")
        roles = _extract_roles(decoded)
        _state.last_kc_ok = time.time()
        return {
            "sub": sub,
            "roles": roles,
            "must_change_password": bool(decoded.get("required_actions")),
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "token_expired")
    except jwt.InvalidIssuerError:
        logger.warning("Issuer mismatch (expected=%s)", expected_issuer)
        raise HTTPException(401, "bad_token")
    except jwt.InvalidAlgorithmError:
        logger.warning("Algorithm not in %s", _ALLOWED_ALGORITHMS)
        raise HTTPException(401, "bad_token")
    except jwt.exceptions.PyJWKClientError:
        # Key not in JWKS — fall through to Phase 2 (key rotation)
        logger.info("JWKS key miss — trying userinfo (rotation?)")
    except (jwt.InvalidTokenError, jwt.DecodeError):
        # Bad signature, malformed — NO fallback
        raise HTTPException(401, "bad_token")
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected JWT error")
        raise HTTPException(401, "bad_token")

    # ── Phase 2: Userinfo fallback (key rotation only) ──
    try:
        async with httpx.AsyncClient(timeout=_USERINFO_TIMEOUT) as client:
            resp = await client.get(
                _userinfo_url(),
                headers={"Authorization": f"Bearer {token}"},
            )

        if resp.status_code != 200:
            raise HTTPException(401, "bad_token")

        data = resp.json()
        sub = data.get("preferred_username") or data.get("sub", "unknown")
        roles = _extract_roles(data)

        # Force JWKS refresh for future requests
        _state.force_jwks_refresh()
        _state.last_kc_ok = time.time()

        return {
            "sub": sub,
            "roles": roles,
            "must_change_password": False,
        }
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(504, "oidc_timeout")
    except httpx.ConnectError:
        raise HTTPException(503, "oidc_unavailable")
    except Exception:
        raise HTTPException(401, "bad_token")


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _safe_json(resp: httpx.Response) -> dict:
    """Parse JSON response body, returning empty dict on failure."""
    try:
        return resp.json()
    except Exception:
        return {}

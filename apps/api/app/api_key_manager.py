"""
TPL API Key Manager — Secure client API key management.

Design principles:
  • API keys are NEVER stored in plaintext — only HMAC(pepper, key) hashes
  • Fingerprint = sha256(key)[:12] for logs (no secret leakage)
  • Per-key: scope, rate limit, expiry, revoke
  • Server pepper loaded from Vault tmpfs via secret_loader
  • Thread-safe operations with file locking

Usage:
    from .api_key_manager import ApiKeyManager
    mgr = ApiKeyManager(data_dir="/data")
    key_id, raw_key = mgr.create_key(owner="svc-billing", scopes=["read"])
    valid, meta = mgr.validate_key(raw_key)
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from .secret_loader import get_secret


# ── Constants ────────────────────────────────────────────────────────────────
_KEY_LENGTH = 48  # 48 bytes → 64 chars url-safe base64
_FINGERPRINT_LENGTH = 12  # hex chars for log-safe fingerprint
_DEFAULT_RATE_LIMIT = 100  # requests per window
_DEFAULT_RATE_WINDOW = 60  # seconds
_PREFIX = "tpl_"  # API key prefix for identification


class ApiKeyManager:
    """Manages API keys with HMAC-peppered hashing and per-key policies."""

    def __init__(self, data_dir: str = "/data"):
        self._data_dir = Path(data_dir)
        self._keys_file = self._data_dir / ".tpl_api_keys.json"
        self._lock = threading.Lock()
        self._rate_counters: dict[str, list[float]] = {}
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def _get_pepper(self) -> str:
        """Get HMAC pepper from Vault/secrets. Uses COMM_SHARED_SECRET as pepper."""
        return get_secret("COMM_SHARED_SECRET")

    def _hmac_hash(self, raw_key: str) -> str:
        """HMAC-SHA256(pepper, raw_key) — the stored hash."""
        pepper = self._get_pepper().encode("utf-8")
        return hmac.new(pepper, raw_key.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def fingerprint(raw_key: str) -> str:
        """SHA-256 fingerprint (first 12 hex chars) — safe for logs."""
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:_FINGERPRINT_LENGTH]

    def _load_keys(self) -> dict:
        """Load API keys database from disk."""
        if not self._keys_file.exists():
            return {"keys": {}, "updated": 0}
        try:
            with open(self._keys_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"keys": {}, "updated": 0}

    def _save_keys(self, data: dict) -> None:
        """Save API keys database to disk with restrictive permissions."""
        data["updated"] = int(time.time())
        tmp = self._keys_file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
        # Atomic rename
        tmp.rename(self._keys_file)
        # Restrictive permissions (owner-only)
        try:
            os.chmod(self._keys_file, 0o600)
        except OSError:
            pass

    def create_key(
        self,
        owner: str,
        scopes: list[str] | None = None,
        rate_limit: int = _DEFAULT_RATE_LIMIT,
        rate_window: int = _DEFAULT_RATE_WINDOW,
        expires_in: int | None = None,
        description: str = "",
    ) -> tuple[str, str]:
        """
        Create a new API key. Returns (key_id, raw_key).

        The raw_key is returned ONCE — it cannot be recovered.
        Only the HMAC hash is stored.

        Args:
            owner: Key owner identifier (e.g., "svc-billing")
            scopes: List of allowed scopes (e.g., ["read", "write"])
            rate_limit: Max requests per rate_window
            rate_window: Rate limit window in seconds
            expires_in: Seconds until expiry (None = no expiry)
            description: Human-readable description

        Returns:
            (key_id, raw_key) — raw_key is shown ONCE
        """
        # Generate cryptographically strong key
        raw_key = _PREFIX + secrets.token_urlsafe(_KEY_LENGTH)
        key_id = secrets.token_hex(8)  # 16-char hex ID
        key_hash = self._hmac_hash(raw_key)
        fp = self.fingerprint(raw_key)
        now = int(time.time())

        key_record = {
            "id": key_id,
            "hash": key_hash,
            "fingerprint": fp,
            "owner": owner,
            "scopes": scopes or ["read"],
            "rate_limit": rate_limit,
            "rate_window": rate_window,
            "description": description,
            "created_at": now,
            "expires_at": (now + expires_in) if expires_in else None,
            "last_used": None,
            "use_count": 0,
            "active": True,
        }

        with self._lock:
            data = self._load_keys()
            data["keys"][key_id] = key_record
            self._save_keys(data)

        return key_id, raw_key

    def validate_key(self, raw_key: str) -> tuple[bool, dict | None]:
        """
        Validate an API key. Returns (is_valid, metadata_or_None).

        Checks:
          1. HMAC hash matches
          2. Key is active (not revoked)
          3. Key is not expired
          4. Rate limit not exceeded

        Returns:
            (True, {owner, scopes, ...}) or (False, None)
        """
        if not raw_key or not raw_key.startswith(_PREFIX):
            return False, None

        key_hash = self._hmac_hash(raw_key)
        fp = self.fingerprint(raw_key)

        with self._lock:
            data = self._load_keys()

            for key_id, record in data["keys"].items():
                if not hmac.compare_digest(record["hash"], key_hash):
                    continue

                # Found matching key
                if not record.get("active", False):
                    return False, None  # Revoked

                # Check expiry
                expires_at = record.get("expires_at")
                if expires_at and time.time() > expires_at:
                    return False, None  # Expired

                # Check rate limit
                if not self._check_rate(fp, record.get("rate_limit", _DEFAULT_RATE_LIMIT),
                                        record.get("rate_window", _DEFAULT_RATE_WINDOW)):
                    return False, {"reason": "rate_limited", "fingerprint": fp}

                # Update usage stats
                record["last_used"] = int(time.time())
                record["use_count"] = record.get("use_count", 0) + 1
                self._save_keys(data)

                return True, {
                    "key_id": key_id,
                    "owner": record["owner"],
                    "scopes": record["scopes"],
                    "fingerprint": fp,
                }

        return False, None  # No match

    def _check_rate(self, fp: str, limit: int, window: int) -> bool:
        """Check rate limit for a key (by fingerprint). Returns True if OK."""
        now = time.time()
        cutoff = now - window
        counts = self._rate_counters.get(fp, [])
        counts = [t for t in counts if t > cutoff]
        if len(counts) >= limit:
            self._rate_counters[fp] = counts
            return False
        counts.append(now)
        self._rate_counters[fp] = counts
        return True

    def revoke_key(self, key_id: str) -> bool:
        """Immediately revoke an API key by ID."""
        with self._lock:
            data = self._load_keys()
            if key_id not in data["keys"]:
                return False
            data["keys"][key_id]["active"] = False
            data["keys"][key_id]["revoked_at"] = int(time.time())
            self._save_keys(data)
        return True

    def list_keys(self) -> list[dict]:
        """
        List all API keys (metadata only — NEVER returns hashes or raw keys).
        Safe for admin API responses.
        """
        with self._lock:
            data = self._load_keys()
        result = []
        for key_id, record in data["keys"].items():
            result.append({
                "id": key_id,
                "fingerprint": record.get("fingerprint", ""),
                "owner": record.get("owner", ""),
                "scopes": record.get("scopes", []),
                "description": record.get("description", ""),
                "active": record.get("active", False),
                "created_at": record.get("created_at", 0),
                "expires_at": record.get("expires_at"),
                "last_used": record.get("last_used"),
                "use_count": record.get("use_count", 0),
            })
        return result

    def cleanup_expired(self) -> int:
        """Remove expired keys from storage. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            data = self._load_keys()
            to_remove = []
            for key_id, record in data["keys"].items():
                expires_at = record.get("expires_at")
                if expires_at and now > expires_at:
                    to_remove.append(key_id)
            for key_id in to_remove:
                del data["keys"][key_id]
                removed += 1
            if removed:
                self._save_keys(data)
        return removed

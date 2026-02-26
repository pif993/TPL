"""
TPL Secret Loader — Maximum Security Secret Delivery

Reads secrets from TWO sources with strict priority (NO env var fallback):
  1. Vault tmpfs files (/run/secrets/*) — preferred, RAM-only, no disk
  2. *_FILE environment variables — Docker secrets / custom file paths

Env var fallback is INTENTIONALLY REMOVED. If a required secret is
not found in a file, the API refuses to start.

Features:
  • Fail-fast: API refuses to start if critical secrets are missing
  • No secrets in logs: values are NEVER printed or logged
  • Weak-secret blocklist applied regardless of source
  • Hot-reload support: secrets can be re-read at runtime (rotation)
  • Audit: logs SECRET SOURCE (not value) for traceability
  • Key ring: supports current + previous key for zero-downtime rotation

Usage:
    from .secret_loader import get_secret, reload_secrets, get_secret_metadata
    from .secret_loader import get_key_ring

    api_secret = get_secret("API_SECRET")  # raises RuntimeError if missing
    current, previous = get_key_ring("API_SECRET")  # for JWT verify with old key
"""

import os
import time
import threading
import warnings
from pathlib import Path
from typing import Optional

# ── Configuration ────────────────────────────────────────────────────────────
SECRETS_DIR = Path(os.getenv("TPL_SECRETS_DIR", "/run/secrets"))
VAULT_MODE = os.getenv("TPL_VAULT_MODE", "auto")  # auto | vault | env | disabled

_WEAK_VALUES = frozenset({
    "change-me-please", "change-me", "changeme", "secret", "admin",
    "password", "", "test", "default", "12345", "admin123",
    "user", "comm-secret-change-me",
})

# Map: ENV_VAR_NAME → tmpfs filename
_SECRET_MAP = {
    "API_SECRET":         "api_secret",
    "TPL_ADMIN_PASSWORD": "tpl_admin_password",
    "TPL_USER_PASSWORD":  "tpl_user_password",
    "COMM_SHARED_SECRET": "comm_shared_secret",
    "TPL_MASTER_KEY":     "tpl_master_key",
}

# Key ring: secrets that support current + previous for zero-downtime rotation.
# The previous key file is named <base>_previous in the secrets dir.
_KEY_RING_SECRETS = frozenset({
    "API_SECRET",
    "TPL_MASTER_KEY",
    "COMM_SHARED_SECRET",
})

# Which secrets are REQUIRED (API refuses to start without them)
_REQUIRED_SECRETS = frozenset({
    "API_SECRET",
    "COMM_SHARED_SECRET",
    "TPL_MASTER_KEY",
})

# ── Internal State ───────────────────────────────────────────────────────────
_cache: dict[str, str] = {}
_previous_cache: dict[str, str] = {}  # previous key ring values
_metadata: dict[str, dict] = {}
_lock = threading.Lock()
_loaded = False


def _read_file_secret(filepath: Path) -> Optional[str]:
    """Read a secret from a file, stripping trailing whitespace."""
    try:
        if filepath.exists() and filepath.is_file():
            val = filepath.read_text(encoding="utf-8").strip()
            if val:
                return val
    except (PermissionError, OSError) as e:
        warnings.warn(f"SECRET_LOADER: Cannot read {filepath}: {e}", stacklevel=3)
    return None


def _load_secret(name: str) -> tuple[Optional[str], str]:
    """
    Load a single secret. Returns (value, source).
    Source is one of: 'vault_tmpfs', 'file_env', 'missing'.
    NO env var fallback — secrets MUST come from files.
    """
    tmpfs_name = _SECRET_MAP.get(name, name.lower())

    # Priority 1: Vault tmpfs (/run/secrets/*)
    tmpfs_path = SECRETS_DIR / tmpfs_name
    val = _read_file_secret(tmpfs_path)
    if val is not None:
        return val, "vault_tmpfs"

    # Priority 2: *_FILE env var (Docker secrets pattern)
    file_env = os.getenv(f"{name}_FILE")
    if file_env:
        val = _read_file_secret(Path(file_env))
        if val is not None:
            return val, "file_env"

    # NO Priority 3: env var fallback intentionally removed.
    # Secrets must come from files (/run/secrets or *_FILE).
    return None, "missing"


def _validate_secret(name: str, value: str, source: str) -> str:
    """Validate a secret value. Raises RuntimeError for weak/invalid values."""
    if value.lower() in _WEAK_VALUES:
        raise RuntimeError(
            f"FATAL: {name} has a weak/default value. "
            f"Source: {source}. Generate a strong value."
        )
    if len(value) < 8:
        raise RuntimeError(
            f"FATAL: {name} is too short ({len(value)} chars). "
            f"Minimum 8 characters required."
        )
    return value


def _load_previous_secret(name: str) -> Optional[str]:
    """
    Load the previous version of a key-ring secret (for rotation).
    Only checks tmpfs: /run/secrets/<name>_previous
    """
    tmpfs_name = _SECRET_MAP.get(name, name.lower())
    prev_path = SECRETS_DIR / (tmpfs_name + "_previous")
    val = _read_file_secret(prev_path)
    if val is not None:
        return val

    # Also check *_PREVIOUS_FILE (file-based previous key)
    prev_file_env = os.getenv(f"{name}_PREVIOUS_FILE")
    if prev_file_env:
        val = _read_file_secret(Path(prev_file_env))
        if val is not None:
            return val

    return None


def load_all_secrets() -> dict[str, str]:
    """
    Load all configured secrets. Called at startup and on rotation.
    Returns dict of {name: value}.
    Raises RuntimeError if any REQUIRED secret is missing or weak.
    """
    global _loaded
    secrets = {}
    previous = {}
    meta = {}

    for name in _SECRET_MAP:
        value, source = _load_secret(name)

        if value is None:
            if name in _REQUIRED_SECRETS:
                raise RuntimeError(
                    f"FATAL: Required secret {name} is missing. "
                    f"Checked: {SECRETS_DIR / _SECRET_MAP[name]}, "
                    f"${name}_FILE env var. "
                    f"Env var fallback is disabled — secrets must be in files."
                )
            meta[name] = {"source": "missing", "loaded_at": int(time.time())}
            continue

        # Validate
        _validate_secret(name, value, source)

        secrets[name] = value

        # Key ring: also load the previous key if it exists
        has_previous = False
        if name in _KEY_RING_SECRETS:
            prev_val = _load_previous_secret(name)
            if prev_val is not None:
                previous[name] = prev_val
                has_previous = True
                print(f"SECRET_LOADER: {name}_previous loaded (key ring active)")

        meta[name] = {
            "source": source,
            "loaded_at": int(time.time()),
            "length": len(value),
            "key_ring": has_previous,
        }

        # Log source (NEVER the value)
        print(f"SECRET_LOADER: {name} loaded from {source} ({len(value)} chars)")

    with _lock:
        _cache.clear()
        _cache.update(secrets)
        _previous_cache.clear()
        _previous_cache.update(previous)
        _metadata.clear()
        _metadata.update(meta)
        _loaded = True

    return secrets


def get_secret(name: str, required: bool = True) -> str:
    """
    Get a secret by name. Returns cached value.
    Raises RuntimeError if required and not available.
    """
    global _loaded
    if not _loaded:
        load_all_secrets()

    with _lock:
        val = _cache.get(name)

    if val is None and required:
        raise RuntimeError(
            f"FATAL: Secret {name} not available. Check Vault or environment."
        )
    return val or ""


def get_key_ring(name: str) -> tuple[str, Optional[str]]:
    """
    Get the key ring for a secret: (current, previous).
    Returns (current_value, previous_value_or_None).

    Use this for JWT verification or decryption:
      - Sign/encrypt with current only
      - Verify/decrypt with current first, then previous
    """
    global _loaded
    if not _loaded:
        load_all_secrets()

    with _lock:
        current = _cache.get(name, "")
        previous = _previous_cache.get(name)

    return current, previous


def reload_secrets() -> dict[str, dict]:
    """
    Reload all secrets from their sources. Used for rotation.
    Returns metadata about what changed.
    """
    with _lock:
        old_meta = dict(_metadata)

    new_secrets = load_all_secrets()

    changes = {}
    with _lock:
        for name, meta in _metadata.items():
            old = old_meta.get(name, {})
            if old.get("source") != meta.get("source") or old.get("length") != meta.get("length"):
                changes[name] = {
                    "old_source": old.get("source", "missing"),
                    "new_source": meta["source"],
                    "changed": True,
                }
            else:
                changes[name] = {"changed": False}

    return changes


def get_secret_metadata() -> dict[str, dict]:
    """
    Get metadata about loaded secrets (source, timing — NEVER values).
    Safe for API responses and logging.
    """
    with _lock:
        return {
            name: {
                "source": m.get("source", "unknown"),
                "loaded_at": m.get("loaded_at", 0),
                "length": m.get("length", 0),
                "is_vault": m.get("source") == "vault_tmpfs",
                "key_ring": m.get("key_ring", False),
            }
            for name, m in _metadata.items()
        }


def is_vault_mode() -> bool:
    """Check if we're running with Vault-backed secrets."""
    with _lock:
        return any(m.get("source") == "vault_tmpfs" for m in _metadata.values())

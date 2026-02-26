"""
TPL Crypto Key Manager — Ed25519 Asymmetric JWT Signing
========================================================

Replaces HMAC shared-secret JWT signing with Ed25519 (EdDSA):
  • Private key NEVER leaves the API container
  • Public key can be shared for verification (microservices, gateways)
  • Automatic key pair generation on first boot
  • Key rotation with configurable grace period (previous key accepted)
  • Keys stored in DATA_DIR/.tpl_keys/ with 0600 permissions
  • Thread-safe key access with lazy loading

Security advantages over HMAC:
  • No shared secret to leak
  • Asymmetric: verifiers don't need signing capability
  • Ed25519: immune to timing attacks by design
  • Short keys (32 bytes) with 128-bit security level
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("tpl.crypto_keys")

# ── Configuration ────────────────────────────────────────────────────────────
_DATA_DIR = Path(os.getenv("TPL_DATA_DIR", "/data"))
_KEYS_DIR = _DATA_DIR / ".tpl_keys"

_ROTATION_GRACE_SECONDS = int(os.getenv("KEY_ROTATION_GRACE", "86400"))  # 24h default

_ALG = "EdDSA"


# ── Internal state ───────────────────────────────────────────────────────────

class _KeyState:
    """Thread-safe key pair state."""

    def __init__(self):
        self._lock = threading.Lock()
        self._current_private: Optional[Ed25519PrivateKey] = None
        self._current_public: Optional[Ed25519PublicKey] = None
        self._previous_public: Optional[Ed25519PublicKey] = None
        self._key_id: str = ""
        self._previous_key_id: str = ""
        self._loaded_at: float = 0.0
        self._generation: int = 0

    @property
    def algorithm(self) -> str:
        return _ALG

    def _ensure_keys_dir(self) -> None:
        """Create keys directory with strict permissions."""
        _KEYS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(_KEYS_DIR, 0o700)
        except OSError:
            pass

    def _generate_key_pair(self) -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
        """Generate a new Ed25519 key pair with a unique key ID."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        # Key ID: timestamp-based for ordering + random suffix
        key_id = f"{int(time.time())}-{os.urandom(4).hex()}"
        return private_key, public_key, key_id

    def _save_key_pair(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        key_id: str,
        suffix: str = "current",
    ) -> None:
        """Save key pair to disk with restrictive permissions."""
        self._ensure_keys_dir()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        priv_path = _KEYS_DIR / f"ed25519_{suffix}.pem"
        pub_path = _KEYS_DIR / f"ed25519_{suffix}.pub"
        kid_path = _KEYS_DIR / f"ed25519_{suffix}.kid"

        # Atomic write: temp file + rename
        for path, data in [
            (priv_path, priv_pem),
            (pub_path, pub_pem),
            (kid_path, key_id.encode("utf-8")),
        ]:
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.rename(path)

    def _load_key_pair(
        self,
        suffix: str = "current",
    ) -> tuple[Optional[Ed25519PrivateKey], Optional[Ed25519PublicKey], str]:
        """Load key pair from disk. Returns (private, public, key_id) or (None, None, '')."""
        priv_path = _KEYS_DIR / f"ed25519_{suffix}.pem"
        pub_path = _KEYS_DIR / f"ed25519_{suffix}.pub"
        kid_path = _KEYS_DIR / f"ed25519_{suffix}.kid"

        if not priv_path.exists() or not pub_path.exists():
            return None, None, ""

        try:
            priv_pem = priv_path.read_bytes()
            private_key = serialization.load_pem_private_key(priv_pem, password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                logger.error("Key %s is not Ed25519", priv_path)
                return None, None, ""

            pub_pem = pub_path.read_bytes()
            public_key = serialization.load_pem_public_key(pub_pem)
            if not isinstance(public_key, Ed25519PublicKey):
                logger.error("Public key %s is not Ed25519", pub_path)
                return None, None, ""

            key_id = ""
            if kid_path.exists():
                key_id = kid_path.read_text("utf-8").strip()

            return private_key, public_key, key_id

        except Exception as exc:
            logger.error("Failed to load key pair (%s): %s", suffix, exc)
            return None, None, ""

    def initialize(self) -> None:
        """Load or generate key pair. Called once at startup."""
        with self._lock:
            if self._current_private is not None:
                return

            # Try loading current key
            priv, pub, kid = self._load_key_pair("current")
            if priv is not None and pub is not None:
                self._current_private = priv
                self._current_public = pub
                self._key_id = kid
                self._loaded_at = time.time()
                logger.info("Ed25519 key pair loaded (kid=%s)", kid)

                # Try loading previous key for rotation grace
                _, prev_pub, prev_kid = self._load_key_pair("previous")
                if prev_pub is not None:
                    self._previous_public = prev_pub
                    self._previous_key_id = prev_kid
                    logger.info("Previous key loaded for rotation (kid=%s)", prev_kid)
            else:
                # Generate new key pair
                priv, pub, kid = self._generate_key_pair()
                self._save_key_pair(priv, pub, kid, "current")
                self._current_private = priv
                self._current_public = pub
                self._key_id = kid
                self._loaded_at = time.time()
                self._generation += 1
                logger.info("Ed25519 key pair generated (kid=%s)", kid)

    def rotate(self) -> str:
        """Rotate key pair: current → previous, generate new current.
        Returns the new key ID."""
        with self._lock:
            if self._current_private is None:
                raise RuntimeError("Cannot rotate: no current key loaded")

            # Move current → previous
            self._save_key_pair(
                self._current_private,
                self._current_public,
                self._key_id,
                "previous",
            )
            self._previous_public = self._current_public
            self._previous_key_id = self._key_id

            # Generate new current
            priv, pub, kid = self._generate_key_pair()
            self._save_key_pair(priv, pub, kid, "current")
            self._current_private = priv
            self._current_public = pub
            self._key_id = kid
            self._loaded_at = time.time()
            self._generation += 1

            logger.info(
                "Key rotated: new=%s, previous=%s (grace=%ds)",
                kid,
                self._previous_key_id,
                _ROTATION_GRACE_SECONDS,
            )
            return kid

    def get_signing_key(self) -> Ed25519PrivateKey:
        """Get the current private key for JWT signing."""
        if self._current_private is None:
            self.initialize()
        with self._lock:
            if self._current_private is None:
                raise RuntimeError("FATAL: No signing key available")
            return self._current_private

    def get_verification_keys(self) -> list[tuple[Ed25519PublicKey, str]]:
        """Get all valid public keys for JWT verification.
        Returns list of (public_key, key_id) — current first, then previous."""
        if self._current_public is None:
            self.initialize()
        with self._lock:
            keys = []
            if self._current_public:
                keys.append((self._current_public, self._key_id))
            if self._previous_public:
                keys.append((self._previous_public, self._previous_key_id))
            return keys

    def get_current_key_id(self) -> str:
        """Get the current key ID (for JWT kid header)."""
        if self._current_private is None:
            self.initialize()
        return self._key_id

    def get_public_key_pem(self) -> str:
        """Get the current public key in PEM format (safe to share)."""
        if self._current_public is None:
            self.initialize()
        with self._lock:
            return self._current_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

    def get_status(self) -> dict:
        """Get key status for health endpoints (no secrets exposed)."""
        with self._lock:
            return {
                "algorithm": _ALG,
                "key_id": self._key_id,
                "previous_key_id": self._previous_key_id or None,
                "loaded_at": int(self._loaded_at) if self._loaded_at else None,
                "generation": self._generation,
                "rotation_grace_seconds": _ROTATION_GRACE_SECONDS,
                "has_previous": self._previous_public is not None,
            }


# ── Module-level singleton ───────────────────────────────────────────────────
_state = _KeyState()


def initialize() -> None:
    """Initialize the key manager. Call once at startup."""
    _state.initialize()


def get_signing_key() -> Ed25519PrivateKey:
    return _state.get_signing_key()


def get_verification_keys() -> list[tuple[Ed25519PublicKey, str]]:
    return _state.get_verification_keys()


def get_current_key_id() -> str:
    return _state.get_current_key_id()


def get_algorithm() -> str:
    return _ALG


def rotate_keys() -> str:
    return _state.rotate()


def get_public_key_pem() -> str:
    return _state.get_public_key_pem()


def get_status() -> dict:
    return _state.get_status()

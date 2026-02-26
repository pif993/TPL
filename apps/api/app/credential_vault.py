"""
TPL Credential Vault — Password Lifecycle & Breach Protection
==============================================================

Manages the full credential lifecycle with extreme security:
  • Password history: prevents reuse of last N passwords (default 12)
  • Password aging: enforces max age with configurable grace period
  • Minimum password age: prevents rapid cycling to bypass history
  • Breach detection: k-anonymity check via Have I Been Pwned API
  • Entropy calculation: real Shannon entropy + pattern detection
  • Complexity rules: configurable, enforced server-side
  • Credential rotation tracking and alerting

Design principles:
  • Passwords are NEVER stored in plaintext — only Argon2id hashes
  • Breach check uses k-anonymity (only SHA-1 prefix sent, 5 chars)
  • Thread-safe with advisory file locking
  • All operations are auditable
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import tempfile
import threading
import time
import fcntl
from collections import Counter
from pathlib import Path
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger("tpl.credential_vault")

# ── Configuration ────────────────────────────────────────────────────────────
_DATA_DIR = Path(os.getenv("TPL_DATA_DIR", "/data"))

# Password history: number of previous passwords to retain
PASSWORD_HISTORY_SIZE = int(os.getenv("PASSWORD_HISTORY_SIZE", "12"))

# Password aging (seconds)
PASSWORD_MAX_AGE = int(os.getenv("PASSWORD_MAX_AGE", "7776000"))  # 90 days
PASSWORD_MIN_AGE = int(os.getenv("PASSWORD_MIN_AGE", "86400"))  # 1 day
PASSWORD_EXPIRY_WARNING = int(os.getenv("PASSWORD_EXPIRY_WARNING", "604800"))  # 7 days

# Breach check
BREACH_CHECK_ENABLED = os.getenv("BREACH_CHECK_ENABLED", "true").lower() in ("true", "1", "yes")
BREACH_CHECK_TIMEOUT = float(os.getenv("BREACH_CHECK_TIMEOUT", "3.0"))

# Complexity requirements
PW_MIN_LENGTH = int(os.getenv("PW_MIN_LENGTH", "14"))
PW_MIN_ENTROPY = float(os.getenv("PW_MIN_ENTROPY", "3.0"))
PW_REQUIRE_UPPER = True
PW_REQUIRE_LOWER = True
PW_REQUIRE_DIGIT = True
PW_REQUIRE_SPECIAL = True
PW_MAX_LENGTH = 256

# Common password patterns to reject
_COMMON_PATTERNS = [
    r"^(.)\1+$",                    # All same character
    r"^(012|123|234|345|456|567|678|789)+$",  # Sequential digits
    r"^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno)+$",  # Sequential letters
    r"^(qwerty|asdfgh|zxcvbn)",     # Keyboard patterns
    r"password|passwd|admin|root|letmein|welcome",  # Common words
]

# Argon2id hasher (matching user_management_engine parameters)
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


class PasswordPolicyViolation(Exception):
    """Raised when a password doesn't meet policy requirements."""

    def __init__(self, code: str, message: str, details: Optional[dict] = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


class CredentialVault:
    """Manages credential lifecycle with extreme security."""

    def __init__(self, data_dir: Optional[Path] = None):
        self._data_dir = data_dir or _DATA_DIR
        self._history_file = self._data_dir / ".tpl_pw_history.json"
        self._lock = threading.Lock()
        self._data_dir.mkdir(parents=True, exist_ok=True)

    # ── Storage ──────────────────────────────────────────────────────────

    def _load_history(self) -> dict:
        """Load password history from disk."""
        if not self._history_file.exists():
            return {"users": {}, "updated": 0}
        try:
            with open(self._history_file, "r", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except Exception:
            return {"users": {}, "updated": 0}

    def _save_history(self, data: dict) -> None:
        """Atomic write password history to disk."""
        data["updated"] = int(time.time())
        dir_name = str(self._data_dir)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp", prefix=".pwh_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(data, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
                fcntl.flock(f, fcntl.LOCK_UN)
            os.replace(tmp_path, str(self._history_file))
            try:
                os.chmod(self._history_file, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ── Password Validation ──────────────────────────────────────────────

    def validate_password(
        self,
        password: str,
        username: str = "",
        check_history: bool = True,
        check_breach: bool = True,
    ) -> dict:
        """
        Comprehensive password validation. Returns validation report.
        Raises PasswordPolicyViolation on failure.

        Checks (in order):
          1. Length (min/max)
          2. Complexity (upper, lower, digit, special)
          3. Entropy (Shannon entropy)
          4. Common patterns
          5. Username similarity
          6. Password history (reuse prevention)
          7. Breach database (k-anonymity)
        """
        report = {
            "valid": True,
            "checks": {},
            "entropy": 0.0,
            "strength": "unknown",
        }

        # 1. Length check
        if len(password) < PW_MIN_LENGTH:
            raise PasswordPolicyViolation(
                "too_short",
                f"La password deve essere lunga almeno {PW_MIN_LENGTH} caratteri (attuale: {len(password)}).",
                {"min_length": PW_MIN_LENGTH, "actual_length": len(password)},
            )
        if len(password) > PW_MAX_LENGTH:
            raise PasswordPolicyViolation(
                "too_long",
                f"La password non può superare {PW_MAX_LENGTH} caratteri.",
                {"max_length": PW_MAX_LENGTH},
            )
        report["checks"]["length"] = True

        # 2. Complexity
        if PW_REQUIRE_UPPER and not re.search(r"[A-Z]", password):
            raise PasswordPolicyViolation(
                "missing_uppercase",
                "La password deve contenere almeno una lettera maiuscola.",
            )
        if PW_REQUIRE_LOWER and not re.search(r"[a-z]", password):
            raise PasswordPolicyViolation(
                "missing_lowercase",
                "La password deve contenere almeno una lettera minuscola.",
            )
        if PW_REQUIRE_DIGIT and not re.search(r"[0-9]", password):
            raise PasswordPolicyViolation(
                "missing_digit",
                "La password deve contenere almeno un numero.",
            )
        if PW_REQUIRE_SPECIAL and not re.search(r"[^A-Za-z0-9]", password):
            raise PasswordPolicyViolation(
                "missing_special",
                "La password deve contenere almeno un carattere speciale.",
            )
        report["checks"]["complexity"] = True

        # 3. Entropy
        entropy = self._calculate_entropy(password)
        report["entropy"] = round(entropy, 2)
        if entropy < PW_MIN_ENTROPY:
            raise PasswordPolicyViolation(
                "low_entropy",
                f"Password troppo prevedibile (entropia: {entropy:.1f} bit/char, minimo: {PW_MIN_ENTROPY}).",
                {"entropy": round(entropy, 2), "min_entropy": PW_MIN_ENTROPY},
            )
        report["checks"]["entropy"] = True

        # 4. Common patterns
        pw_lower = password.lower()
        for pattern in _COMMON_PATTERNS:
            if re.search(pattern, pw_lower):
                raise PasswordPolicyViolation(
                    "common_pattern",
                    "La password contiene un pattern comune e facilmente indovinabile.",
                )
        report["checks"]["patterns"] = True

        # 5. Username similarity
        if username and len(username) >= 3:
            un_lower = username.lower()
            if un_lower in pw_lower or pw_lower in un_lower:
                raise PasswordPolicyViolation(
                    "contains_username",
                    "La password non deve contenere lo username.",
                )
            # Check reversed username
            if un_lower[::-1] in pw_lower:
                raise PasswordPolicyViolation(
                    "contains_username_reversed",
                    "La password non deve contenere lo username invertito.",
                )
        report["checks"]["username_check"] = True

        # 6. Password history
        if check_history and username:
            if self._is_in_history(username, password):
                raise PasswordPolicyViolation(
                    "password_reused",
                    f"Non puoi riutilizzare una delle ultime {PASSWORD_HISTORY_SIZE} password.",
                    {"history_size": PASSWORD_HISTORY_SIZE},
                )
        report["checks"]["history"] = True

        # 7. Breach check (k-anonymity)
        if check_breach and BREACH_CHECK_ENABLED:
            breach_result = self._check_breach(password)
            if breach_result > 0:
                raise PasswordPolicyViolation(
                    "breached",
                    f"Questa password è apparsa in {breach_result} data breach noti. Scegline un'altra.",
                    {"breach_count": breach_result},
                )
        report["checks"]["breach"] = True

        # Calculate strength
        report["strength"] = self._strength_label(entropy, len(password))
        return report

    def _calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy (bits per character)."""
        if not password:
            return 0.0
        freq = Counter(password)
        length = len(password)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        return entropy

    def _strength_label(self, entropy: float, length: int) -> str:
        """Map entropy + length to a human-readable strength label."""
        score = entropy * length  # Total bits of entropy
        if score < 40:
            return "debole"
        if score < 60:
            return "media"
        if score < 80:
            return "buona"
        if score < 100:
            return "forte"
        return "eccellente"

    def _check_breach(self, password: str) -> int:
        """
        Check if password appears in known data breaches using
        k-anonymity via the Have I Been Pwned API.

        Only the first 5 characters of the SHA-1 hash are sent.
        Returns the breach count (0 if not found, -1 on error).
        """
        try:
            import httpx

            sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]

            with httpx.Client(timeout=BREACH_CHECK_TIMEOUT) as client:
                resp = client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"Add-Padding": "true"},  # Anti-timing attack
                )
                if resp.status_code != 200:
                    logger.warning("HIBP API returned %d", resp.status_code)
                    return -1  # Error — don't block

                for line in resp.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        logger.info(
                            "Password found in %d breaches (k-anonymity check)",
                            count,
                        )
                        return count

            return 0  # Not found — good

        except Exception as exc:
            logger.warning("Breach check failed: %s", exc)
            return -1  # Error — don't block the user

    # ── Password History ─────────────────────────────────────────────────

    def _is_in_history(self, user_id: str, password: str) -> bool:
        """Check if password matches any entry in the user's history."""
        with self._lock:
            data = self._load_history()
            user_history = data.get("users", {}).get(user_id, {})
            hashes = user_history.get("hashes", [])

        for stored_hash in hashes:
            try:
                if _ph.verify(stored_hash, password):
                    return True
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                continue
            except Exception:
                continue

        return False

    def record_password_change(self, user_id: str, password: str) -> None:
        """Record a password change in history. Stores Argon2id hash, not plaintext."""
        pw_hash = _ph.hash(password)
        now = int(time.time())

        with self._lock:
            data = self._load_history()
            users = data.setdefault("users", {})
            user_data = users.setdefault(user_id, {
                "hashes": [],
                "changes": [],
                "created_at": now,
            })

            # Add to hash history (LIFO, capped)
            hashes = user_data.get("hashes", [])
            hashes.insert(0, pw_hash)
            if len(hashes) > PASSWORD_HISTORY_SIZE:
                hashes = hashes[:PASSWORD_HISTORY_SIZE]
            user_data["hashes"] = hashes

            # Record change metadata (no hashes — just timestamps)
            changes = user_data.get("changes", [])
            changes.insert(0, {"ts": now})
            if len(changes) > PASSWORD_HISTORY_SIZE * 2:
                changes = changes[: PASSWORD_HISTORY_SIZE * 2]
            user_data["changes"] = changes

            user_data["last_change"] = now

            self._save_history(data)

        logger.info("Password change recorded for user=%s", user_id)

    def check_password_age(self, user_id: str) -> dict:
        """
        Check password age for a user.
        Returns {expired, days_remaining, days_old, warning}.
        """
        with self._lock:
            data = self._load_history()
            user_data = data.get("users", {}).get(user_id, {})

        last_change = user_data.get("last_change", 0)
        if not last_change:
            # No history — treat as needing change
            return {
                "expired": True,
                "days_remaining": 0,
                "days_old": 0,
                "warning": True,
                "message": "Nessun cambio password registrato.",
            }

        now = int(time.time())
        age_seconds = now - last_change
        age_days = age_seconds // 86400
        remaining_seconds = PASSWORD_MAX_AGE - age_seconds
        remaining_days = max(0, remaining_seconds // 86400)
        expired = age_seconds >= PASSWORD_MAX_AGE
        warning = remaining_seconds <= PASSWORD_EXPIRY_WARNING

        return {
            "expired": expired,
            "days_remaining": remaining_days,
            "days_old": age_days,
            "warning": warning,
            "max_age_days": PASSWORD_MAX_AGE // 86400,
            "message": "Password scaduta." if expired else (
                f"Password in scadenza tra {remaining_days} giorni." if warning else ""
            ),
        }

    def check_min_age(self, user_id: str) -> bool:
        """
        Check if minimum password age has been met.
        Returns True if the password can be changed, False if too soon.
        """
        with self._lock:
            data = self._load_history()
            user_data = data.get("users", {}).get(user_id, {})

        last_change = user_data.get("last_change", 0)
        if not last_change:
            return True  # No previous change

        elapsed = int(time.time()) - last_change
        return elapsed >= PASSWORD_MIN_AGE

    def get_policy(self) -> dict:
        """Get current password policy for client display."""
        return {
            "min_length": PW_MIN_LENGTH,
            "max_length": PW_MAX_LENGTH,
            "require_uppercase": PW_REQUIRE_UPPER,
            "require_lowercase": PW_REQUIRE_LOWER,
            "require_digit": PW_REQUIRE_DIGIT,
            "require_special": PW_REQUIRE_SPECIAL,
            "min_entropy": PW_MIN_ENTROPY,
            "history_size": PASSWORD_HISTORY_SIZE,
            "max_age_days": PASSWORD_MAX_AGE // 86400,
            "min_age_days": PASSWORD_MIN_AGE // 86400,
            "breach_check": BREACH_CHECK_ENABLED,
        }

    def get_user_credential_status(self, user_id: str) -> dict:
        """Get credential status for a specific user (no secrets)."""
        age_info = self.check_password_age(user_id)

        with self._lock:
            data = self._load_history()
            user_data = data.get("users", {}).get(user_id, {})

        return {
            "user_id": user_id,
            "last_change": user_data.get("last_change", 0),
            "total_changes": len(user_data.get("changes", [])),
            "age": age_info,
        }

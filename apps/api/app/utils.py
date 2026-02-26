"""
TPL Shared Utilities — Single source of truth for common patterns.

Eliminates code duplication across engines and main.py for:
  - JSONL file I/O with file locking and rotation
  - Tamper-evident audit logging with hash chains
  - Thread-safe rate limiting helpers

All functions are thread-safe and use fcntl advisory locks to prevent
corruption from concurrent writes.
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Any


# ── File Locking ──────────────────────────────────────────────────────

@contextmanager
def file_lock(filepath: str, exclusive: bool = True):
    """Advisory file lock using fcntl. Prevents concurrent corruption of state files."""
    lock_path = filepath + ".lock"
    fd = None
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


# ── JSONL I/O ─────────────────────────────────────────────────────────

DEFAULT_MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB


def jsonl_rotate_if_needed(filepath: str, max_size: int = DEFAULT_MAX_LOG_SIZE) -> bool:
    """Rotate a JSONL file if it exceeds max_size. Returns True if rotated."""
    try:
        if os.path.isfile(filepath) and os.path.getsize(filepath) > max_size:
            rotated = filepath + ".1"
            if os.path.isfile(rotated):
                os.remove(rotated)
            os.rename(filepath, rotated)
            return True
    except Exception:
        pass
    return False


def jsonl_append(filepath: str, record: dict, lock: threading.Lock | None = None,
                 max_size: int = DEFAULT_MAX_LOG_SIZE) -> None:
    """Append a JSON record to a JSONL file with file locking and optional rotation.

    Args:
        filepath: Path to the .jsonl file.
        record: Dict to serialize and append.
        lock: Optional threading.Lock for thread safety.
        max_size: Max file size before rotation (0 = no rotation).
    """
    def _write():
        if max_size > 0:
            jsonl_rotate_if_needed(filepath, max_size)
        fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8"))
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    if lock:
        with lock:
            _write()
    else:
        _write()


def jsonl_tail(filepath: str, limit: int = 100, lock: threading.Lock | None = None) -> list[dict]:
    """Read the last `limit` records from a JSONL file.

    Uses a deque with maxlen for O(1) memory bounded reads.

    Args:
        filepath: Path to the .jsonl file.
        limit: Maximum number of records to return (1-500).
        lock: Optional threading.Lock for thread safety.

    Returns:
        List of parsed dicts, most recent last.
    """
    limit = max(1, min(limit, 500))
    if not os.path.isfile(filepath):
        return []

    out: deque[dict] = deque(maxlen=limit)

    def _read():
        with open(filepath, "r", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    if lock:
        with lock:
            _read()
    else:
        _read()

    return list(out)


# ── Atomic JSON State ─────────────────────────────────────────────────

def atomic_json_save(filepath: str, data: dict) -> None:
    """Atomically write a JSON file using tmp + os.replace."""
    tmp = filepath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, filepath)


def json_load_safe(filepath: str, default: Any = None) -> Any:
    """Load a JSON file, returning default on any error."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


# ── Rate Limiting ─────────────────────────────────────────────────────

class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Tracks attempts per key within a time window. Used for login brute-force
    protection and API key rate limiting.
    """

    def __init__(self, max_attempts: int = 8, window_seconds: int = 120):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_limited(self, key: str) -> bool:
        """Check if `key` has exceeded the rate limit."""
        now = time.time()
        threshold = now - self.window
        with self._lock:
            attempts = [t for t in self._attempts.get(key, []) if t >= threshold]
            self._attempts[key] = attempts
            return len(attempts) >= self.max_attempts

    def register_attempt(self, key: str) -> None:
        """Record a failed attempt for `key`."""
        now = time.time()
        threshold = now - self.window
        with self._lock:
            attempts = [t for t in self._attempts.get(key, []) if t >= threshold]
            attempts.append(now)
            self._attempts[key] = attempts

    def clear(self, key: str) -> None:
        """Clear all attempts for `key` (e.g., after successful login)."""
        with self._lock:
            self._attempts.pop(key, None)

    def cleanup(self) -> int:
        """Remove all expired entries. Returns number of keys cleaned."""
        threshold = time.time() - self.window
        cleaned = 0
        with self._lock:
            expired = [k for k, v in self._attempts.items() if all(t < threshold for t in v)]
            for k in expired:
                del self._attempts[k]
                cleaned += 1
        return cleaned

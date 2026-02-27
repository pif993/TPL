"""
Unit Tests — RateLimiter (brute-force protection)

Tests the sliding-window rate limiter used for login and API key protection.
"""
import time
import threading
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../apps/api"))

from app.utils import RateLimiter


class TestRateLimiterBasic:
    """Test basic rate limiting behavior."""

    def test_not_limited_initially(self):
        rl = RateLimiter(max_attempts=3, window_seconds=60)
        assert rl.is_limited("user1") is False

    def test_limited_after_max_attempts(self):
        rl = RateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            rl.register_attempt("user1")
        assert rl.is_limited("user1") is True

    def test_not_limited_below_max(self):
        rl = RateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(2):
            rl.register_attempt("user1")
        assert rl.is_limited("user1") is False

    def test_different_keys_independent(self):
        rl = RateLimiter(max_attempts=2, window_seconds=60)
        rl.register_attempt("user1")
        rl.register_attempt("user1")
        assert rl.is_limited("user1") is True
        assert rl.is_limited("user2") is False

    def test_clear_resets_attempts(self):
        rl = RateLimiter(max_attempts=2, window_seconds=60)
        rl.register_attempt("user1")
        rl.register_attempt("user1")
        assert rl.is_limited("user1") is True
        rl.clear("user1")
        assert rl.is_limited("user1") is False


class TestRateLimiterWindow:
    """Test sliding window expiration."""

    def test_attempts_expire_after_window(self):
        rl = RateLimiter(max_attempts=2, window_seconds=1)
        rl.register_attempt("user1")
        rl.register_attempt("user1")
        assert rl.is_limited("user1") is True
        time.sleep(1.1)  # wait for window to expire
        assert rl.is_limited("user1") is False

    def test_cleanup_removes_expired(self):
        rl = RateLimiter(max_attempts=2, window_seconds=1)
        rl.register_attempt("user1")
        rl.register_attempt("user2")
        time.sleep(1.1)
        cleaned = rl.cleanup()
        assert cleaned == 2


class TestRateLimiterThreadSafety:
    """Test thread safety of the rate limiter."""

    def test_concurrent_registrations(self):
        rl = RateLimiter(max_attempts=100, window_seconds=60)
        errors = []

        def register_many():
            try:
                for _ in range(50):
                    rl.register_attempt("shared_key")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Should have accumulated ~200 attempts
        assert rl.is_limited("shared_key") is True

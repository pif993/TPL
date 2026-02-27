"""
Unit Tests — HMAC Communication Signature Verification

Tests the HMAC-SHA256 canonical form signature generation and verification
used in the communication engine.
"""
import hashlib
import hmac
import json
import time
import pytest


def _canonical(sender, recipient, msg_type, payload, nonce, ts):
    """Reproduce the canonical form used by the communication engine."""
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"{sender}|{recipient}|{msg_type}|{payload_str}|{nonce}|{ts}"


def _sign(canonical_str, secret):
    """Sign a canonical string with HMAC-SHA256."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class TestHMACSignature:
    """Test HMAC canonical form and signature mechanics."""

    def test_canonical_form_is_deterministic(self):
        """Same inputs must always produce the same canonical string."""
        c1 = _canonical("a", "b", "ping", {"k": "v"}, "nonce1", 1700000000)
        c2 = _canonical("a", "b", "ping", {"k": "v"}, "nonce1", 1700000000)
        assert c1 == c2

    def test_canonical_form_payload_sorting(self):
        """Payload keys must be sorted for canonical form."""
        c1 = _canonical("a", "b", "t", {"z": 1, "a": 2}, "n", 1)
        c2 = _canonical("a", "b", "t", {"a": 2, "z": 1}, "n", 1)
        assert c1 == c2  # same because json.dumps sorts keys

    def test_signature_matches(self):
        """A correctly signed message must verify."""
        secret = "test-comm-shared-secret-hmac-key-1234567890abcdef"
        canon = _canonical("sender", "receiver", "ping", {"data": "hello"}, "nonce123", 1700000000)
        sig = _sign(canon, secret)
        # Verify
        expected = hmac.new(secret.encode(), canon.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(sig, expected)

    def test_wrong_secret_fails(self):
        """A signature with the wrong secret must not match."""
        canon = _canonical("a", "b", "t", {}, "n", 1)
        sig_good = _sign(canon, "correct-secret-abcdefghijklmno")
        sig_bad = _sign(canon, "wrong-secret-abcdefghijklmnop")
        assert not hmac.compare_digest(sig_good, sig_bad)

    def test_tampered_message_fails(self):
        """Modifying any field should invalidate the signature."""
        secret = "test-secret-for-tamper-detection-12345"
        canon_orig = _canonical("a", "b", "ping", {"x": 1}, "nonce1", 1700000000)
        sig_orig = _sign(canon_orig, secret)

        # Tamper: change sender
        canon_tampered = _canonical("ATTACKER", "b", "ping", {"x": 1}, "nonce1", 1700000000)
        assert not hmac.compare_digest(sig_orig, _sign(canon_tampered, secret))

        # Tamper: change payload
        canon_tampered2 = _canonical("a", "b", "ping", {"x": 2}, "nonce1", 1700000000)
        assert not hmac.compare_digest(sig_orig, _sign(canon_tampered2, secret))

        # Tamper: change timestamp
        canon_tampered3 = _canonical("a", "b", "ping", {"x": 1}, "nonce1", 9999999999)
        assert not hmac.compare_digest(sig_orig, _sign(canon_tampered3, secret))

    def test_timing_safe_comparison(self):
        """hmac.compare_digest should be used (not ==) to prevent timing attacks."""
        secret = "test-secret-for-timing-safety-12345"
        canon = _canonical("a", "b", "t", {}, "n", 1)
        sig = _sign(canon, secret)
        # This is really a code review check — the communication engine
        # should use hmac.compare_digest. At unit test level, verify it works.
        assert hmac.compare_digest(sig, sig)
        assert not hmac.compare_digest(sig, sig[:-1] + "0" if sig[-1] != "0" else sig[:-1] + "1")

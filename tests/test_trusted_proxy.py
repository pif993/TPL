"""
Unit Tests — Trusted Proxy Parsing

Tests the client IP extraction logic that parses X-Forwarded-For
headers only from trusted proxy CIDRs.
"""
import os
import sys
import ipaddress
import pytest


class TestTrustedProxyParsing:
    """Test trusted proxy CIDR matching and XFF chain parsing."""

    def test_private_ips_are_trusted(self):
        """Docker-internal and private IPs should be trusted."""
        from app.main import _ip_is_trusted
        trusted_ips = [
            "172.16.0.1",
            "172.31.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "192.168.1.1",
            "127.0.0.1",
        ]
        for ip in trusted_ips:
            assert _ip_is_trusted(ip), f"{ip} should be trusted"

    def test_public_ips_are_not_trusted(self):
        """Public internet IPs should NOT be trusted."""
        from app.main import _ip_is_trusted
        untrusted_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.1",
            "100.100.100.100",
        ]
        for ip in untrusted_ips:
            assert not _ip_is_trusted(ip), f"{ip} should not be trusted"

    def test_invalid_ip_not_trusted(self):
        """Invalid IP strings should not be trusted (and not crash)."""
        from app.main import _ip_is_trusted
        assert _ip_is_trusted("not-an-ip") is False
        assert _ip_is_trusted("") is False


class TestClientIPExtraction:
    """Test the _client_ip function for correct XFF chain parsing."""

    def test_direct_connection_uses_peer_ip(self):
        """Without XFF header, peer IP should be returned."""
        from app.main import _client_ip
        from unittest.mock import MagicMock

        request = MagicMock()
        request.client.host = "203.0.113.50"
        request.headers = {}

        ip = _client_ip(request)
        assert ip == "203.0.113.50"

    def test_xff_from_trusted_proxy(self):
        """When peer is trusted, rightmost non-trusted XFF IP is used."""
        from app.main import _client_ip
        from unittest.mock import MagicMock

        request = MagicMock()
        request.client.host = "172.16.0.2"  # trusted proxy
        # XFF chain: client → trusted proxy. Walk right-to-left, skip trusted.
        request.headers = {"X-Forwarded-For": "203.0.113.50, 10.0.0.1"}

        ip = _client_ip(request)
        # Should pick the rightmost non-trusted IP (203.0.113.50)
        assert ip == "203.0.113.50"

    def test_xff_all_trusted_returns_leftmost(self):
        """When all XFF IPs are trusted, leftmost is returned."""
        from app.main import _client_ip
        from unittest.mock import MagicMock

        request = MagicMock()
        request.client.host = "172.16.0.2"  # trusted
        request.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}

        ip = _client_ip(request)
        assert ip == "10.0.0.1"  # leftmost when all trusted

    def test_xff_from_untrusted_peer_ignored(self):
        """When peer is NOT trusted, XFF is ignored entirely."""
        from app.main import _client_ip
        from unittest.mock import MagicMock

        request = MagicMock()
        request.client.host = "203.0.113.1"  # untrusted peer
        request.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}

        ip = _client_ip(request)
        # Untrusted peer → ignore XFF, use peer IP
        assert ip == "203.0.113.1"

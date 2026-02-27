"""
Unit Tests — secret_loader

Tests the secret loading, validation, weak-secret rejection,
key ring support, and hot-reload logic.
"""
import os
import pytest
from pathlib import Path


def _reset_loader():
    """Force-reset the secret_loader module state between tests."""
    import importlib
    import apps.api.app.secret_loader as sl
    sl._loaded = False
    sl._cache.clear()
    sl._previous_cache.clear()
    sl._metadata.clear()
    sl.SECRETS_DIR = Path(os.environ["TPL_SECRETS_DIR"])
    return sl


class TestSecretLoading:
    """Test secret loading from tmpfs files."""

    def test_load_all_secrets_succeeds(self):
        sl = _reset_loader()
        secrets = sl.load_all_secrets()
        assert "API_SECRET" in secrets
        assert "COMM_SHARED_SECRET" in secrets
        assert "TPL_MASTER_KEY" in secrets

    def test_get_secret_returns_correct_value(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        val = sl.get_secret("API_SECRET")
        assert val == "test-api-secret-for-unit-tests-1234567890"

    def test_get_secret_raises_on_missing_required(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        with pytest.raises(RuntimeError, match="not available"):
            sl.get_secret("NONEXISTENT_SECRET", required=True)

    def test_get_secret_returns_empty_on_missing_optional(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        val = sl.get_secret("NONEXISTENT_SECRET", required=False)
        assert val == ""

    def test_metadata_never_contains_values(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        meta = sl.get_secret_metadata()
        for name, info in meta.items():
            assert "value" not in info, f"Metadata for {name} leaks value"
            assert "secret" not in str(info).lower() or "is_vault" in str(info), \
                f"Metadata for {name} may leak secret info"

    def test_metadata_has_source_and_timing(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        meta = sl.get_secret_metadata()
        for name, info in meta.items():
            assert "source" in info
            assert "loaded_at" in info
            assert info["loaded_at"] > 0


class TestWeakSecretRejection:
    """Test that weak/default secrets are blocked."""

    @pytest.mark.parametrize("weak_value", [
        "change-me-please", "change-me", "changeme", "secret",
        "admin", "password", "", "test", "default", "12345",
    ])
    def test_weak_secret_rejected(self, weak_value, tmp_path):
        sl = _reset_loader()
        secrets_dir = Path(os.environ["TPL_SECRETS_DIR"])
        (secrets_dir / "api_secret").write_text(weak_value)
        with pytest.raises(RuntimeError, match="weak|short"):
            sl.load_all_secrets()

    def test_short_secret_rejected(self, tmp_path):
        sl = _reset_loader()
        secrets_dir = Path(os.environ["TPL_SECRETS_DIR"])
        (secrets_dir / "api_secret").write_text("abc1234")  # 7 chars
        with pytest.raises(RuntimeError, match="too short"):
            sl.load_all_secrets()


class TestKeyRing:
    """Test key ring (current + previous) for zero-downtime rotation."""

    def test_key_ring_without_previous(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        current, previous = sl.get_key_ring("API_SECRET")
        assert len(current) > 0
        assert previous is None

    def test_key_ring_with_previous(self):
        sl = _reset_loader()
        secrets_dir = Path(os.environ["TPL_SECRETS_DIR"])
        (secrets_dir / "api_secret_previous").write_text("old-api-secret-for-rotation-test")
        sl.load_all_secrets()
        current, previous = sl.get_key_ring("API_SECRET")
        assert current == "test-api-secret-for-unit-tests-1234567890"
        assert previous == "old-api-secret-for-rotation-test"


class TestReloadSecrets:
    """Test hot-reload detects changes."""

    def test_reload_detects_length_change(self):
        sl = _reset_loader()
        sl.load_all_secrets()

        # Change secret value
        secrets_dir = Path(os.environ["TPL_SECRETS_DIR"])
        (secrets_dir / "api_secret").write_text("a-completely-different-secret-value-for-testing-reload")
        changes = sl.reload_secrets()
        assert changes["API_SECRET"]["changed"] is True

    def test_reload_no_change_detected(self):
        sl = _reset_loader()
        sl.load_all_secrets()
        changes = sl.reload_secrets()
        # No actual change → changed should be False for all
        for name, info in changes.items():
            assert info["changed"] is False

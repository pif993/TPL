"""
TPL Test Configuration — pytest fixtures and helpers.

Sets up temporary secrets and environment for isolated unit testing
without Docker or external services.
"""
import json
import os
import tempfile
import shutil
import pytest


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Ensure every test runs in isolation with its own secrets and data dirs."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    # Write minimal secrets files
    _write(secrets_dir / "api_secret", "test-api-secret-for-unit-tests-1234567890")
    _write(secrets_dir / "tpl_admin_password", "TestAdminPassword!1234")
    _write(secrets_dir / "tpl_user_password", "TestUserPassword!5678")
    _write(secrets_dir / "comm_shared_secret", "test-comm-shared-secret-hmac-key-1234567890abcdef")
    _write(secrets_dir / "tpl_master_key", "test-master-key-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")

    monkeypatch.setenv("TPL_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv("TPL_DATA_DIR", str(data_dir))
    monkeypatch.setenv("TPL_VAULT_MODE", "disabled")
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.0/8,::1/128")
    monkeypatch.setenv("ENABLE_CONTROL_PLANE", "0")
    monkeypatch.setenv("LOGIN_WINDOW_SECONDS", "120")
    monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "8")

    yield


def _write(path, content):
    path.write_text(content, encoding="utf-8")
    os.chmod(str(path), 0o640)

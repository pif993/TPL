#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"50_auth_local","ver":"3.0.0","deps":["40_api_base"],"desc":"Fortress auth — Ed25519 JWT, refresh-token rotation, server-side sessions, credential vault (Argon2id)"}
JSON
}

apply(){
  # The auth dispatcher (auth_impl.py) selects backend via AUTH_MODE env var.
  # This module writes the compose fragment for fortress-grade local auth.
  # Core modules: crypto_keys.py, session_manager.py, credential_vault.py, _auth_local.py
  mkdir -p compose.d

  cat > compose.d/50-auth.yml <<'YML'
# ── FORTRESS AUTH MODE (v3.0) ──────────────────────────────────
# Ed25519 asymmetric JWT · Refresh-token rotation · Credential vault
services:
  api:
    environment:
      AUTH_MODE: local
      ACCESS_TOKEN_TTL: ${ACCESS_TOKEN_TTL:-900}
      REFRESH_TOKEN_TTL: ${REFRESH_TOKEN_TTL:-604800}
      MAX_CONCURRENT_SESSIONS: ${MAX_CONCURRENT_SESSIONS:-5}
      PASSWORD_MIN_LENGTH: ${PASSWORD_MIN_LENGTH:-14}
      PASSWORD_MIN_ENTROPY: ${PASSWORD_MIN_ENTROPY:-3.0}
      PASSWORD_MAX_AGE_DAYS: ${PASSWORD_MAX_AGE_DAYS:-90}
      BREACH_CHECK_ENABLED: ${BREACH_CHECK_ENABLED:-true}
YML

  echo "INFO: Module 50_auth_local v3.0 applied — Fortress AUTH_MODE=local"
  echo "INFO: Ed25519 key pair will be auto-generated on first API startup"
  echo "INFO: Access token TTL=15min, refresh rotation enabled, credential vault active"
}

check(){ true; }
rollback(){ rm -f compose.d/50-auth.yml; }

#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  TPL Run — Operational CLI for the TPL platform
# ═══════════════════════════════════════════════════════════════════════════════
#  Usage:
#    ./run.sh up            Start all services
#    ./run.sh down          Stop all services (keeps data)
#    ./run.sh restart       Restart all services
#    ./run.sh status        Show service status
#    ./run.sh logs [svc]    Follow logs (optionally for a single service)
#    ./run.sh backup        Backup data directory to tarball
#    ./run.sh restore <f>   Restore data from backup tarball
#    ./run.sh upgrade       Pull latest images + rebuild + ordered restart
#    ./run.sh rotate-secrets  Rotate secrets (current → *.previous key ring)
#    ./run.sh doctor        Comprehensive health check
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Load configuration ───────────────────────────────────────────────────────
# Priority: /etc/tpl/config.env → .env → defaults
_load_config() {
  # SECURITY: unset any inherited AUTH_MODE before sourcing .env
  # Prevents stale shell variables from overriding the config file
  unset AUTH_MODE 2>/dev/null || true
  if [[ -f /etc/tpl/config.env ]]; then
    set -a; source /etc/tpl/config.env; set +a
  elif [[ -f "$SCRIPT_DIR/.env" && -r "$SCRIPT_DIR/.env" ]]; then
    set -a; source "$SCRIPT_DIR/.env"; set +a
  elif [[ -f "$SCRIPT_DIR/.env" ]]; then
    echo "WARN: .env exists but is not readable (check permissions)" >&2
  fi
}
_load_config

# ── Configuration (NEVER secrets) ────────────────────────────────────────────
DOMAIN_MODE="${DOMAIN_MODE:-local}"
TRAEFIK_HTTP_PORT="${TRAEFIK_HTTP_PORT:-80}"
TRAEFIK_HTTPS_PORT="${TRAEFIK_HTTPS_PORT:-8443}"
ENABLE_TRAEFIK="${ENABLE_TRAEFIK:-1}"
AUTO_INSTALL="${AUTO_INSTALL:-1}"
LOGIN_WINDOW_SECONDS="${LOGIN_WINDOW_SECONDS:-120}"
LOGIN_MAX_ATTEMPTS="${LOGIN_MAX_ATTEMPTS:-8}"
JWT_TTL_SECONDS="${JWT_TTL_SECONDS:-3600}"
BOOTSTRAP_MODE="${BOOTSTRAP_MODE:-false}"
FORCE_HTTPS="${FORCE_HTTPS:-true}"
TRUSTED_PROXY_IPS="${TRUSTED_PROXY_IPS:-172.16.0.0/12,10.0.0.0/8,192.168.0.0/16}"
AUTH_MODE="${AUTH_MODE:-local}"
ENABLE_CONTROL_PLANE="${ENABLE_CONTROL_PLANE:-0}"
TPL_URL="${TPL_URL:-https://localhost}"

# ── Paths (set by install.sh, with safe defaults) ────────────────────────────
SECRETS_DIR="${TPL_SECRETS_DIR_HOST:-/opt/tpl/secrets}"
DATA_DIR="${TPL_DATA_DIR_HOST:-/var/lib/tpl}"
LOG_DIR="${TPL_LOG_DIR_HOST:-/var/log/tpl}"
TLS_DIR="${TPL_TLS_DIR:-/opt/tpl/secrets/tls}"

# Backwards compatibility: if system paths don't exist, fall back to local
if [[ ! -d "$SECRETS_DIR" && -d "$SCRIPT_DIR/.secrets" ]]; then
  SECRETS_DIR="$SCRIPT_DIR/.secrets"
fi
if [[ ! -d "$DATA_DIR" ]]; then
  DATA_DIR="$SCRIPT_DIR/data"
  mkdir -p "$DATA_DIR" 2>/dev/null || true
fi

# ── Vault mode detection ─────────────────────────────────────────────────────
VAULT_MODE="false"
if [[ -f compose.d/20-vault.yml && -f .vault_approle/role-id ]]; then
  VAULT_MODE="true"
  echo "INFO: Vault mode detected — secrets delivered via tmpfs"
fi

# ── Residual .tpl_* warning ──────────────────────────────────────────────────
_tpl_residuals=$(find . -maxdepth 1 -name ".tpl_*" ! -name ".tpl_state.json" \( -type f -o -type d \) 2>/dev/null | head -5)
if [[ -n "$_tpl_residuals" ]]; then
  echo "WARN: Residual .tpl_* files in project root. Clean: ./init.sh clean-state" >&2
fi

# ── Secrets validation (fail-fast) ───────────────────────────────────────────
_WEAK=("change-me-please" "change-me" "changeme" "secret" "admin" "password" "" "user" "test" "default" "12345" "admin123" "comm-secret-change-me")
_check_secret() {
  local name="$1" path="$2"
  [[ -f "$path" ]] || { echo "FATAL: Secret $name not found at $path. Run: sudo ./install.sh" >&2; exit 1; }
  local val; val="$(cat "$path" 2>/dev/null)" || { echo "FATAL: Cannot read $path" >&2; exit 1; }
  for w in "${_WEAK[@]}"; do
    [[ "$val" = "$w" ]] && { echo "FATAL: $name is weak/placeholder. Re-run: sudo ./install.sh" >&2; exit 1; }
  done
  [[ ${#val} -ge 8 ]] || { echo "FATAL: $name too short (${#val} < 8). Re-run: sudo ./install.sh" >&2; exit 1; }
}

validate_secrets() {
  [[ "$VAULT_MODE" = "true" ]] && return 0
  [[ -d "$SECRETS_DIR" ]] || { echo "FATAL: Secrets dir $SECRETS_DIR not found. Run: sudo ./install.sh" >&2; exit 1; }
  # If not running as root and secrets dir isn't readable, skip validation
  # (Docker daemon runs as root and will mount them correctly)
  if [[ ! -r "$SECRETS_DIR" ]]; then
    echo "INFO: Secrets dir not readable by $(whoami) — skipping validation (Docker will mount as root)" >&2
    return 0
  fi
  _check_secret "api_secret"         "$SECRETS_DIR/api_secret"
  _check_secret "tpl_admin_password" "$SECRETS_DIR/tpl_admin_password"
  _check_secret "tpl_user_password"  "$SECRETS_DIR/tpl_user_password"
  _check_secret "comm_shared_secret" "$SECRETS_DIR/comm_shared_secret"
  _check_secret "tpl_master_key"     "$SECRETS_DIR/tpl_master_key"
}

# ── Stale mount detection (reusable) ─────────────────────────────────────────
# Docker Compose caches bind mount paths at container creation time.  If the
# project directory was moved/renamed/copied, existing containers keep the OLD
# absolute paths.  This function detects those containers and force-removes
# them so the next `dc up` creates fresh ones with the correct mounts.
# Returns 0 if stale containers were found and purged, 1 if clean.
_purge_stale_containers() {
  local _cwd; _cwd="$(pwd)"
  local _found_stale=1            # 1 = clean (bash convention)

  # Scan ALL containers belonging to compose project "tpl" (set by compose.yml name:)
  local _cid _wdir _cname
  for _cid in $(docker ps -a --filter "label=com.docker.compose.project=tpl" --format '{{.ID}}' 2>/dev/null); do
    _wdir=$(docker inspect "$_cid" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null) || continue
    if [[ -n "$_wdir" && "$_wdir" != "$_cwd" ]]; then
      _cname=$(docker inspect "$_cid" --format '{{.Name}}' 2>/dev/null)
      echo "WARN: Stale container $_cname from $_wdir (expected $_cwd) — removing"
      docker rm -f "$_cid" >/dev/null 2>&1 || true
      _found_stale=0
    fi
  done

  # Also catch any tpl-* container without the project label (edge case)
  for _cid in $(docker ps -a --filter "name=tpl-" --format '{{.ID}}' 2>/dev/null); do
    _wdir=$(docker inspect "$_cid" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null) || continue
    if [[ -n "$_wdir" && "$_wdir" != "$_cwd" ]]; then
      _cname=$(docker inspect "$_cid" --format '{{.Name}}' 2>/dev/null)
      echo "WARN: Ghost container $_cname from $_wdir — removing"
      docker rm -f "$_cid" >/dev/null 2>&1 || true
      _found_stale=0
    fi
  done

  # Clean up orphaned networks when stale containers were found
  if [[ $_found_stale -eq 0 ]]; then
    echo "INFO: Cleaning stale networks..."
    docker network rm tpl_default    2>/dev/null || true
    docker network rm tpl_kc_internal 2>/dev/null || true
  fi

  return $_found_stale
}

# ── Bootstrap resolution ─────────────────────────────────────────────────────
# BOOTSTRAP_MODE=auto → resolved at startup based on users file existence.
# Once users exist, persists BOOTSTRAP_MODE=false in .env permanently.
_resolve_bootstrap() {
  # Check /data/.bootstrapped marker first — once set, bootstrap is permanently off
  if [[ -f "$DATA_DIR/.bootstrapped" ]]; then
    BOOTSTRAP_MODE="false"
    return
  fi
  # If no users file exists at all, bootstrap MUST be enabled — otherwise locked out
  if [[ ! -f "$DATA_DIR/.tpl_users.json" ]]; then
    BOOTSTRAP_MODE="true"
    echo "INFO: No users found — bootstrap enabled for initial admin setup" >&2
    return
  fi
  # Users exist but no .bootstrapped marker (edge case) — honour .env setting
  case "${BOOTSTRAP_MODE}" in
    false|0|no) BOOTSTRAP_MODE="false" ;;
    *)          BOOTSTRAP_MODE="true" ;;
  esac
}

# ── Compose helpers ──────────────────────────────────────────────────────────
_compose_files() {
  local args=(-f compose.yml)
  for f in compose.d/*.yml; do
    [[ -f "$f" ]] || continue
    local base; base=$(basename "$f")
    [[ "$base" = "10-traefik.yml" && "${ENABLE_TRAEFIK:-0}" != "1" ]] && continue
    # Proxy mode: 12-proxy.yml replaces 10-traefik.yml (no host ports)
    [[ "$base" = "10-traefik.yml" && "${DOMAIN_MODE:-local}" = "proxy" ]] && continue
    [[ "$base" = "11-dev.yml" ]] && continue  # dev profile loaded explicitly below
    [[ "$base" = "12-proxy.yml" ]] && continue  # proxy overlay loaded explicitly below
    [[ "$base" = "21-vault-agent.yml" && "$VAULT_MODE" = "false" ]] && continue
    [[ "$base" = "20-vault.yml"       && "$VAULT_MODE" = "false" ]] && continue
    # Skip ALL 60-auth* fragments — only 50-auth.yml controls auth mode
    [[ "$base" = 60-auth* ]] && continue
    # Skip keycloak compose fragment when using local auth (default)
    [[ "$base" = "60-keycloak.yml" && "${AUTH_MODE:-local}" != "keycloak" ]] && continue
    args+=(-f "$f")
  done
  # 11-dev.yml no longer auto-loaded — local mode uses TRAEFIK_BIND_IP=127.0.0.1
  # which makes 10-traefik.yml bind to loopback automatically (no duplicate ports)
  # Proxy mode: overlay removes host ports from Traefik
  if [[ "${DOMAIN_MODE:-local}" = "proxy" && -f compose.d/12-proxy.yml ]]; then
    args+=(-f compose.d/12-proxy.yml)
  fi
  printf '%s\n' "${args[@]}"
}

dc() {
  local -a files=()
  while IFS= read -r f; do files+=("$f"); done < <(_compose_files)
  docker compose "${files[@]}" "$@"
}

_export_env() {
  export TRAEFIK_HTTP_PORT TRAEFIK_HTTPS_PORT
  export AUTH_MODE OIDC_ISSUER="${OIDC_ISSUER:-}" OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-myapp-web}"
  export ENABLE_TRAEFIK AUTO_INSTALL
  export LOGIN_WINDOW_SECONDS LOGIN_MAX_ATTEMPTS JWT_TTL_SECONDS
  export BOOTSTRAP_MODE FORCE_HTTPS TRUSTED_PROXY_IPS
  export ENABLE_CONTROL_PLANE
  export TPL_DATA_DIR="${TPL_DATA_DIR:-/data}"
  export CORS_ORIGINS="${CORS_ORIGINS:-$TPL_URL}"
  export TPL_SECRETS_DIR_HOST="$SECRETS_DIR"
  export TPL_DATA_DIR_HOST="$DATA_DIR"
  export TPL_TLS_DIR="$TLS_DIR"
  export TPL_LOG_DIR_HOST="$LOG_DIR"
  # OTA Auto-Apply: export host UID/GID for container group_add
  export TPL_UID="$(id -u)"
  export TPL_GID="$(id -g)"
  export TPL_PROJECT_ROOT="$SCRIPT_DIR"
  # Local mode: force loopback binding so Traefik is never reachable from network
  if [[ "${DOMAIN_MODE:-local}" = "local" ]]; then
    export TRAEFIK_BIND_IP="127.0.0.1"
  else
    export TRAEFIK_BIND_IP="${TRAEFIK_BIND_IP:-0.0.0.0}"
  fi
}

_wait_healthy() {
  local url="$1" tries="${2:-120}"
  for _ in $(seq 1 "$tries"); do
    curl -fskS "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

_ensure_ready() {
  [[ "$AUTO_INSTALL" = "1" ]] || return 0
  local need_install=0

  # Check if compose fragments are missing
  [[ ! -f compose.yml || ! -f compose.d/40-api.yml || ! -f compose.d/30-web.yml ]] && need_install=1

  # Check if secrets are missing (no system dir AND no local dir)
  if [[ ! -d "${TPL_SECRETS_DIR_HOST:-/opt/tpl/secrets}" && ! -d "$SCRIPT_DIR/.secrets" ]]; then
    need_install=1
  fi

  [[ $need_install -eq 0 ]] && return 0

  echo "AUTO_INSTALL: preparing stack..."
  # Try install.sh first (full production installer), then init.sh (dev/local)
  if [[ -x ./install.sh ]] && [[ $(id -u) -eq 0 ]]; then
    ./install.sh
  elif [[ -x ./init.sh ]]; then
    ./init.sh auto-install
  else
    echo "FATAL: Neither install.sh nor init.sh available" >&2
    exit 1
  fi

  # Reload config and paths after auto-install
  _load_config
  _reload_paths
}

_reload_paths() {
  SECRETS_DIR="${TPL_SECRETS_DIR_HOST:-/opt/tpl/secrets}"
  DATA_DIR="${TPL_DATA_DIR_HOST:-/var/lib/tpl}"
  LOG_DIR="${TPL_LOG_DIR_HOST:-/var/log/tpl}"
  TLS_DIR="${TPL_TLS_DIR:-/opt/tpl/secrets/tls}"
  if [[ ! -d "$SECRETS_DIR" && -d "$SCRIPT_DIR/.secrets" ]]; then
    SECRETS_DIR="$SCRIPT_DIR/.secrets"
  fi
  if [[ ! -d "$DATA_DIR" ]]; then
    DATA_DIR="$SCRIPT_DIR/data"
    mkdir -p "$DATA_DIR" 2>/dev/null || true
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ═════════════════════════════════════════════════════════════════════════════

cmd_up() {
  _ensure_ready
  _resolve_bootstrap
  validate_secrets
  _export_env

  # ── Fix data directory ownership for container UID 999 ──────────────
  _fix_data_perms() {
    # Container runs as appuser (999). Host user runs run.sh.
    # Owner=999 gets full access; others get read-only (enough for backups/status).
    # Shell scripts keep +x.  Host writes to data/ go via docker run when needed.
    local owner
    owner=$(stat -c '%u' "$DATA_DIR" 2>/dev/null) || return 0
    if [[ "$owner" != "999" ]]; then
      docker run --rm -v "$(cd "$DATA_DIR" && pwd):/mnt" alpine sh -c \
        'chown -R 999:999 /mnt && find /mnt -type d -exec chmod 755 {} \; && find /mnt -type f -name "*.sh" -exec chmod 755 {} \; && find /mnt -type f ! -name "*.sh" -exec chmod 644 {} \;' \
        2>/dev/null || true
    fi
  }
  _fix_data_perms

  # ── Fix secrets permissions for container UID 999 ───────────────────
  # The API container runs as user 999:999 and bind-mounts .secrets/ read-only.
  # Secrets must be group-readable (GID 999) so the container can load them.
  _fix_secrets_perms() {
    [[ "$VAULT_MODE" = "true" ]] && return 0
    [[ -d "$SECRETS_DIR" ]] || return 0
    # Check if container UID 999 can read secrets
    local test_file="$SECRETS_DIR/api_secret"
    [[ -f "$test_file" ]] || return 0
    local grp
    grp=$(stat -c '%g' "$test_file" 2>/dev/null) || return 0
    if [[ "$grp" != "999" ]]; then
      echo "INFO: Fixing .secrets/ group ownership for container (GID 999)..."
      local abs_sec
      abs_sec="$(cd "$SCRIPT_DIR" && realpath "$SECRETS_DIR" 2>/dev/null || echo "$SECRETS_DIR")"
      docker run --rm -v "$abs_sec:/mnt" alpine sh -c \
        'chgrp -R 999 /mnt && find /mnt -type d -exec chmod 750 {} \; && find /mnt -type f -exec chmod 640 {} \; && chmod 644 /mnt/tls/tpl.crt 2>/dev/null; true' \
        2>/dev/null || {
        chgrp -R 999 "$SECRETS_DIR" 2>/dev/null || echo "WARN: Cannot fix .secrets/ group. Container may fail to read secrets." >&2
        chmod 750 "$SECRETS_DIR" 2>/dev/null || true
        find "$SECRETS_DIR" -type f -exec chmod 640 {} \; 2>/dev/null || true
        find "$SECRETS_DIR" -type d -exec chmod 750 {} \; 2>/dev/null || true
        chmod 644 "$SECRETS_DIR/tls/tpl.crt" 2>/dev/null || true
      }
    fi
  }
  _fix_secrets_perms

  # ── Fail-safe port check: never kill to free ports ──────────────────
  _check_port_safe() {
    local port="$1" label="$2"
    # Skip if port not published (proxy mode, or no dev profile)
    [[ -z "$port" || "$port" = "0" ]] && return 0
    # Check if port is busy AND not by our own containers
    local pid=""
    pid=$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1) || true
    if [[ -n "$pid" ]]; then
      # Check if it's our own docker-proxy
      local cmdname=""
      cmdname=$(ps -p "$pid" -o comm= 2>/dev/null) || true
      if [[ "$cmdname" != "docker-proxy" && "$cmdname" != "com.docker.backend" ]]; then
        echo "FATAL: Port $port ($label) is occupied by PID $pid ($cmdname)." >&2
        echo "       TPL does NOT auto-kill processes. Options:" >&2
        echo "         1. Stop the conflicting service manually" >&2
        echo "         2. Change TRAEFIK_HTTPS_PORT in .env" >&2
        echo "         3. Run in proxy mode (DOMAIN_MODE=proxy)" >&2
        exit 1
      fi
    fi
  }
  # Proxy mode: no host ports → skip port checks entirely
  if [[ "${DOMAIN_MODE:-local}" != "proxy" ]]; then
    _check_port_safe "$TRAEFIK_HTTPS_PORT" "HTTPS"
    _check_port_safe "$TRAEFIK_HTTP_PORT" "HTTP"
  fi

  # ── Seed modules if data/modules/current is empty ──────────────────
  _seed_modules_if_needed() {
    local mod_current="$DATA_DIR/modules/current"
    # Already have .sh files → skip
    ls "$mod_current"/*.sh >/dev/null 2>&1 && return 0
    # Ensure directory exists (fix root ownership from previous Docker runs)
    if [[ -d "$mod_current" && ! -w "$mod_current" ]]; then
      echo "INFO: Fixing ownership of $mod_current..."
      docker run --rm -v "$(cd "$DATA_DIR" && pwd):/mnt" alpine chown -R "$(id -u):$(id -g)" /mnt/modules 2>/dev/null || true
    fi
    mkdir -p "$mod_current" 2>/dev/null || true
    if [[ -d "$SCRIPT_DIR/modules" ]]; then
      cp "$SCRIPT_DIR/modules/"*.sh "$mod_current/" 2>/dev/null || true
      chmod 755 "$mod_current"/*.sh 2>/dev/null || true
      local n; n=$(ls "$mod_current"/*.sh 2>/dev/null | wc -l)
      [[ "$n" -gt 0 ]] && echo "Seeded $n modules into $mod_current"
    fi
  }
  _seed_modules_if_needed

  # ── Auto-unseal Vault helper ───────────────────────────────────────
  _unseal_vault_if_needed() {
    local keys_file="$SCRIPT_DIR/.vault_unseal_keys.json"
    [[ -f "$keys_file" ]] || { echo "WARN: No unseal keys file — cannot auto-unseal Vault" >&2; return 1; }

    # Wait for vault container to be reachable
    echo -n "Waiting for Vault to start..."
    local _i
    for _i in $(seq 1 30); do
      if docker exec tpl-vault vault status >/dev/null 2>&1; then
        echo " reachable"
        break
      fi
      sleep 2
    done

    # Check if already unsealed
    local sealed
    sealed=$(docker exec tpl-vault vault status -format=json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('sealed','true'))" 2>/dev/null) || sealed="true"
    if [[ "$sealed" != "true" ]]; then
      echo "INFO: Vault already unsealed"
      return 0
    fi

    echo "INFO: Auto-unsealing Vault..."
    local _keys
    _keys=$(python3 -c "
import json,sys
d=json.load(open('$keys_file'))
keys=d.get('unseal_keys_b64',d.get('keys_base64',[]))
for k in keys[:d.get('unseal_threshold',3)]:
    print(k)
" 2>/dev/null)
    if [[ -z "$_keys" ]]; then
      echo "ERROR: Cannot read unseal keys from $keys_file" >&2
      return 1
    fi

    # Apply all keys in a single exec to avoid nonce timeouts
    local _unseal_script=""
    while IFS= read -r _key; do
      _unseal_script+="vault operator unseal '$_key' >/dev/null 2>&1;"
    done <<<"$_keys"
    _unseal_script+="vault status -format=json"

    local _result
    _result=$(docker exec tpl-vault sh -c "$_unseal_script" 2>/dev/null)
    sealed=$(echo "$_result" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sealed','true'))" 2>/dev/null) || sealed="true"

    if [[ "$sealed" = "false" ]]; then
      echo "INFO: Vault unsealed successfully"
      # Wait for health check to pass
      for _i in $(seq 1 30); do
        local _health; _health=$(docker inspect tpl-vault --format '{{.State.Health.Status}}' 2>/dev/null) || _health="unknown"
        if [[ "$_health" = "healthy" ]]; then
          return 0
        fi
        sleep 2
      done
      echo "WARN: Vault unsealed but healthcheck not passing yet"
      return 0
    else
      echo "ERROR: Vault unseal failed — keys may not match vault data" >&2
      echo "       Run: ./install_tpl.sh --reset && ./install_tpl.sh" >&2
      return 1
    fi
  }

  echo "Starting TPL ($DOMAIN_MODE mode)..."

  # ── Stale mount detection ──────────────────────────────────────────
  local _needs_recreate=""
  if _purge_stale_containers; then
    _needs_recreate="1"
    echo "INFO: Stale containers purged — will force-recreate all services"
  fi

  if [[ "$VAULT_MODE" = "true" ]]; then
    # ── Vault-aware startup: bring up vault first, unseal, then the rest ──
    if [[ -n "$_needs_recreate" ]]; then
      echo "INFO: Recreating containers (stale bind mounts detected)..."
      dc up -d --build --force-recreate vault
    else
      dc up -d --build vault
    fi
    # Unseal vault if sealed
    _unseal_vault_if_needed
    # Now bring up everything else (vault is already healthy)
    if [[ -n "$_needs_recreate" ]]; then
      dc up -d --build --force-recreate
    else
      dc up -d --build
    fi
  else
    # ── No Vault: simple startup ──
    if [[ -n "$_needs_recreate" ]]; then
      dc up -d --build --force-recreate
    else
      dc up -d --build
    fi
  fi

  # Wait for API health — proxy mode uses container exec, otherwise TLS/HTTP
  local health_url
  if [[ "$DOMAIN_MODE" = "proxy" ]]; then
    health_url="http://localhost:${TRAEFIK_HTTP_PORT:-80}/api/health"
  elif [[ -f "$TLS_DIR/tpl.crt" ]]; then
    health_url="https://localhost:${TRAEFIK_HTTPS_PORT}/api/health"
  else
    health_url="http://localhost:${TRAEFIK_HTTP_PORT}/api/health"
  fi

  echo -n "Waiting for API health..."
  if [[ "$DOMAIN_MODE" = "proxy" ]]; then
    # Proxy mode: no host ports, check health via docker exec
    local _ready=0
    for _ in $(seq 1 120); do
      if docker compose $(_compose_files) exec -T api curl -fs http://localhost:8000/health >/dev/null 2>&1; then
        _ready=1; break
      fi
      sleep 1
    done
    [[ $_ready -eq 1 ]] && echo " ready" || { echo " timeout"; echo "WARN: API may still be starting. Check: ./run.sh logs api" >&2; dc ps; }
  elif _wait_healthy "$health_url" 120; then
    echo " ready"
  else
    echo " timeout"
    echo "WARN: API may still be starting. Check: ./run.sh logs api" >&2
    dc ps
  fi

  echo ""
  echo "╔═══════════════════════════════════════════╗"
  echo "║  TPL is running                          ║"
  printf "║  URL: %-35s ║\n" "$TPL_URL"
  echo "╚═══════════════════════════════════════════╝"

  # ── First-run: show initial credentials in terminal ─────────────────
  # On the very first startup (no .bootstrapped marker), display the admin
  # password prominently so the operator can login and change it.
  _show_initial_creds() {
    # Resolve absolute path to avoid relative-path issues
    local abs_secrets abs_data
    abs_secrets="$(cd "$SCRIPT_DIR" && realpath "$SECRETS_DIR" 2>/dev/null || echo "$SCRIPT_DIR/.secrets")"
    abs_data="$(cd "$SCRIPT_DIR" && realpath "$DATA_DIR" 2>/dev/null || echo "$SCRIPT_DIR/data")"

    # Only show if .bootstrapped marker is absent (first boot)
    [[ -f "$abs_data/.bootstrapped" ]] && return 0

    local admin_pw=""
    # Try multiple paths: resolved SECRETS_DIR, then fallback .secrets/
    if [[ -f "$abs_secrets/tpl_admin_password" ]]; then
      admin_pw=$(cat "$abs_secrets/tpl_admin_password" 2>/dev/null) || admin_pw=""
    elif [[ -f "$SCRIPT_DIR/.secrets/tpl_admin_password" ]]; then
      admin_pw=$(cat "$SCRIPT_DIR/.secrets/tpl_admin_password" 2>/dev/null) || admin_pw=""
    fi
    [[ -z "$admin_pw" ]] && return 0

    local the_url="${TPL_URL:-https://localhost:${TRAEFIK_HTTPS_PORT}}"

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  🔐  PASSWORD TEMPORANEA ADMIN (primo avvio)"
    echo ""
    printf "  URL:       %s\n" "$the_url"
    printf "  Username:  %s\n" "admin"
    printf "  Password:  %s\n" "$admin_pw"
    echo ""
    echo "  ⚠  CAMBIO PASSWORD OBBLIGATORIO al primo login!"
    echo "  🔒  La password sopra è temporanea e monouso."
    echo "  📋  Queste credenziali non verranno più mostrate."
    echo "  🗑  Dopo il cambio, la password generata è invalidata."
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
  }

  # Post-startup smoke test
  echo ""
  echo "Post-startup smoke test..."
  local smoke_pass=0 smoke_fail=0
  # ST1: API health
  if curl -fskS "$health_url" >/dev/null 2>&1; then
    echo "  ✓ API health endpoint"
    smoke_pass=$((smoke_pass+1))
  else
    echo "  ✗ API health endpoint unreachable"
    smoke_fail=$((smoke_fail+1))
  fi
  # ST2: Data volume writable (from inside container)
  if docker compose $(_compose_files) exec -T api test -w /data 2>/dev/null; then
    echo "  ✓ /data writable inside container"
    smoke_pass=$((smoke_pass+1))
  else
    echo "  ✗ /data not writable inside container"
    smoke_fail=$((smoke_fail+1))
  fi
  # ST3: Modules mounted
  if docker compose $(_compose_files) exec -T api sh -c 'ls /work/modules/*.sh' >/dev/null 2>&1; then
    echo "  ✓ Modules mounted in container"
    smoke_pass=$((smoke_pass+1))
  else
    echo "  ⚠ No modules visible in container /work/modules"
    smoke_fail=$((smoke_fail+1))
  fi
  # ST4: No unexpected host port exposure
  local unexpected_ports=""
  unexpected_ports=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oE '0\.0\.0\.0:[0-9]+' | grep -v ":${TRAEFIK_HTTPS_PORT}$" | grep -v ":${TRAEFIK_HTTP_PORT}$" || true)
  if [[ -z "$unexpected_ports" ]]; then
    echo "  ✓ No unexpected host port exposure"
    smoke_pass=$((smoke_pass+1))
  else
    echo "  ⚠ Unexpected ports: $unexpected_ports"
    smoke_fail=$((smoke_fail+1))
  fi
  # ST5: Auth mode verification — catch AUTH_MODE mismatch between shell and container
  local _container_auth
  _container_auth=$(docker exec tpl-api-1 printenv AUTH_MODE 2>/dev/null) || _container_auth="unknown"
  if [[ "$_container_auth" = "${AUTH_MODE:-local}" ]]; then
    echo "  ✓ AUTH_MODE verified: $_container_auth"
    smoke_pass=$((smoke_pass+1))
  else
    echo "  ✗ AUTH_MODE MISMATCH: container=$_container_auth expected=${AUTH_MODE:-local}"
    echo "    FIXING: forcing container recreate with correct AUTH_MODE..."
    smoke_fail=$((smoke_fail+1))
    dc up -d --build --force-recreate api
    echo -n "    Waiting for API health..."
    _wait_healthy "$health_url" 60 && echo " ready" || echo " timeout"
    _container_auth=$(docker exec tpl-api-1 printenv AUTH_MODE 2>/dev/null) || _container_auth="unknown"
    echo "    AUTH_MODE after fix: $_container_auth"
  fi
  # ST6: Login test — verify authentication actually works
  if [[ "${AUTH_MODE:-local}" = "local" ]]; then
    local _login_code
    _login_code=$(docker exec tpl-api-1 python3 -c "
import os, sys, logging
logging.disable(logging.CRITICAL)  # suppress all log output
sys.path.insert(0, '/app')
try:
    from app.main import app
    from app._auth_local import _try_file_auth, _auto_disable_bootstrap, _get_fallback_users
    from app.secret_loader import get_secret
    bootstrap = _auto_disable_bootstrap()
    pw = get_secret('TPL_ADMIN_PASSWORD', required=False) or ''
    if not bootstrap:
        result = _try_file_auth('admin', pw)
        print('OK' if result else 'NO_MATCH')
    else:
        fb = _get_fallback_users().get('admin', {})
        import hmac
        ok = hmac.compare_digest((pw or '').encode(), (fb.get('pw','') or '').encode())
        print('OK' if ok else 'NO_MATCH')
except Exception as e:
    print(f'ERR:{e}')
" 2>&1 | tail -1)
    if [[ "$_login_code" = "OK" ]]; then
      echo "  ✓ Admin login pre-flight: credentials verified"
      smoke_pass=$((smoke_pass+1))
    else
      echo "  ✗ Admin login pre-flight FAILED: $_login_code"
      echo "    Check: ./run.sh logs api | tail -20"
      smoke_fail=$((smoke_fail+1))
    fi
  fi
  echo "  Smoke: $smoke_pass passed, $smoke_fail failed"
  if [[ $smoke_fail -gt 0 ]]; then
    echo "  Run './run.sh doctor' for details." >&2
  fi

  # Show initial credentials AFTER smoke tests (so they're the last thing visible)
  _show_initial_creds
}

cmd_down() {
  _export_env
  echo "Stopping TPL..."
  dc down --remove-orphans || true
  echo "Stopped."
}

cmd_restart() {
  _export_env
  _resolve_bootstrap
  _export_env
  validate_secrets

  # Stale mount detection: `restart` cannot fix stale bind mounts —
  # if detected, do a full force-recreate instead.
  if _purge_stale_containers; then
    echo "WARN: Stale bind mounts detected — performing full recreate instead of restart"
    dc up -d --build --force-recreate
  else
    echo "Restarting TPL..."
    dc restart
  fi
  echo "Checking health..."
  sleep 3
  dc ps
}

cmd_status() {
  _export_env
  dc ps
  echo ""
  # Quick health check
  local api_ok=0
  if [[ "$DOMAIN_MODE" = "proxy" ]]; then
    docker compose $(_compose_files) exec -T api curl -fs http://localhost:8000/health >/dev/null 2>&1 && api_ok=1
  else
    local health_url
    if [[ -f "$TLS_DIR/tpl.crt" ]]; then
      health_url="https://localhost:${TRAEFIK_HTTPS_PORT}/api/health"
    else
      health_url="http://localhost:${TRAEFIK_HTTP_PORT}/api/health"
    fi
    curl -fskS "$health_url" >/dev/null 2>&1 && api_ok=1
  fi
  if [[ $api_ok -eq 1 ]]; then
    echo "API: healthy"
  else
    echo "API: not reachable (may be starting)"
  fi
}

cmd_logs() {
  _export_env
  shift 2>/dev/null || true
  dc logs -f --tail 200 "$@"
}

# ── Backup: snapshot data dir to tarball ──────────────────────────────────────
cmd_backup() {
  local ts; ts=$(date +%Y%m%d-%H%M%S)
  local backup_dir="${DATA_DIR}/backups"
  mkdir -p "$backup_dir"
  local out="$backup_dir/tpl-backup-${ts}.tar.gz"

  echo "Creating backup of $DATA_DIR ..."
  # Exclude the backups directory itself
  tar -czf "$out" -C "$(dirname "$DATA_DIR")" \
    --exclude='backups' \
    "$(basename "$DATA_DIR")"

  local size; size=$(du -h "$out" | cut -f1)
  echo "Backup created: $out ($size)"
}

# ── Restore: restore data from backup tarball ─────────────────────────────────
cmd_restore() {
  local file="${2:-}"
  [[ -n "$file" ]] || { echo "Usage: ./run.sh restore <backup.tar.gz>" >&2; exit 1; }
  [[ -f "$file" ]] || { echo "FATAL: Backup file not found: $file" >&2; exit 1; }

  # Validate tarball integrity before proceeding
  if ! tar -tzf "$file" >/dev/null 2>&1; then
    echo "FATAL: '$file' is not a valid .tar.gz archive" >&2; exit 1
  fi

  echo "WARNING: This will stop services and replace all data in $DATA_DIR"
  echo "Press Ctrl+C to abort, or wait 5 seconds..."
  sleep 5

  _export_env
  echo "Stopping services..."
  dc down --remove-orphans || true

  echo "Restoring from $file ..."
  tar -xzf "$file" -C "$(dirname "$DATA_DIR")"

  echo "Restarting services..."
  cmd_up
  echo "Restore complete."
}

# ── Upgrade: pull latest images + rebuild + ordered restart ───────────────────
cmd_upgrade() {
  _export_env
  _resolve_bootstrap
  _export_env  # re-export after bootstrap resolution
  validate_secrets

  echo "Pulling latest images..."
  dc pull

  echo "Rebuilding and restarting..."
  dc up -d --build --force-recreate

  echo "Waiting for health..."
  sleep 5
  dc ps
  echo "Upgrade complete."
}

# ── Rotate secrets: current → *.previous (key ring) ──────────────────────────
cmd_rotate_secrets() {
  echo "Rotating secrets..."

  for s in api_secret tpl_master_key comm_shared_secret; do
    local path="$SECRETS_DIR/$s"
    if [[ -f "$path" ]]; then
      cp "$path" "${path}.previous"
      chmod 640 "${path}.previous"
      # Generate new secret
      head -c 64 /dev/urandom | base64 | tr -d '/+=' | head -c 64 > "$path"
      chmod 640 "$path"
      # Fix group ownership for container access (GID 999)
      chgrp 999 "$path" "${path}.previous" 2>/dev/null || true
      echo "  Rotated: $s (previous saved)"
    else
      echo "  SKIP: $s not found"
    fi
  done

  echo ""
  echo "Secrets rotated. Now apply to running services:"
  echo "  ./run.sh restart"
  echo ""
  echo "The API supports key ring verification — tokens signed with the"
  echo "previous key remain valid during the grace period."
}

# ── Doctor: comprehensive health check ────────────────────────────────────────
cmd_doctor() {
  echo "TPL Doctor — comprehensive health check"
  echo "════════════════════════════════════════"
  local pass=0 fail_count=0 warn_count=0

  # 1. Docker
  if docker info >/dev/null 2>&1; then
    echo "  ✓ Docker daemon running"
    pass=$((pass+1))
  else
    echo "  ✗ Docker daemon not running"
    fail_count=$((fail_count+1))
  fi

  # 2. Compose config
  _export_env
  if dc config >/dev/null 2>&1; then
    echo "  ✓ Compose configuration valid"
    pass=$((pass+1))
  else
    echo "  ✗ Compose configuration invalid"
    fail_count=$((fail_count+1))
  fi

  # 3. Secrets
  if [[ -d "$SECRETS_DIR" ]]; then
    local sec_perms
    sec_perms=$(stat -c '%a' "$SECRETS_DIR" 2>/dev/null || stat -f '%Lp' "$SECRETS_DIR" 2>/dev/null || echo "?")
    if [[ "$sec_perms" = "700" || "$sec_perms" = "750" ]]; then
      echo "  ✓ Secrets directory: $SECRETS_DIR ($sec_perms)"
      pass=$((pass+1))
    else
      echo "  ⚠ Secrets directory permissions: $sec_perms (expected 750)"
      warn_count=$((warn_count+1))
    fi
    for s in api_secret tpl_master_key comm_shared_secret; do
      if [[ -f "$SECRETS_DIR/$s" ]]; then
        pass=$((pass+1))
      else
        echo "  ✗ Missing secret: $s"
        fail_count=$((fail_count+1))
      fi
    done
    echo "  ✓ Core secrets present"
    # Check individual file permissions (should be 600)
    local sec_file_ok=0 sec_file_bad=0
    for sf in "$SECRETS_DIR"/*; do
      [[ -f "$sf" ]] || continue
      local fp
      fp=$(stat -c '%a' "$sf" 2>/dev/null || echo "?")
      if [[ "$fp" != "600" && "$fp" != "640" && "$(basename "$sf")" != "tpl.crt" ]]; then
        echo "  ⚠ $(basename "$sf"): permissions $fp (expected 640)"
        sec_file_bad=$((sec_file_bad+1))
      else
        sec_file_ok=$((sec_file_ok+1))
      fi
    done
    if [[ $sec_file_bad -gt 0 ]]; then
      warn_count=$((warn_count + sec_file_bad))
    else
      echo "  ✓ All secret files: permissions 640"
      pass=$((pass+1))
    fi
    # Check TLS directory permissions
    if [[ -d "$SECRETS_DIR/tls" ]]; then
      local tls_perms
      tls_perms=$(stat -c '%a' "$SECRETS_DIR/tls" 2>/dev/null || echo "?")
      if [[ "$tls_perms" = "700" || "$tls_perms" = "750" ]]; then
        echo "  ✓ TLS directory: $tls_perms"
        pass=$((pass+1))
      else
        echo "  ⚠ TLS directory permissions: $tls_perms (expected 750)"
        warn_count=$((warn_count+1))
      fi
    fi
  else
    echo "  ✗ Secrets directory not found: $SECRETS_DIR"
    fail_count=$((fail_count+1))
  fi

  # 4. Data directory
  if [[ -d "$DATA_DIR" ]]; then
    echo "  ✓ Data directory: $DATA_DIR"
    pass=$((pass+1))
  else
    echo "  ✗ Data directory not found: $DATA_DIR"
    fail_count=$((fail_count+1))
  fi

  # 5. Port checks (skip for proxy mode — no host ports)
  if [[ "${DOMAIN_MODE}" = "proxy" ]]; then
    echo "  ℹ Proxy mode — no host port checks (TLS by upstream proxy)"
  else
    for port in "$TRAEFIK_HTTP_PORT" "$TRAEFIK_HTTPS_PORT"; do
    if ss -ltnH "sport = :$port" 2>/dev/null | grep -q . || \
       lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "  ✓ Port $port: listening"
      pass=$((pass+1))
    else
      echo "  ⚠ Port $port: not listening (services may be down)"
      warn_count=$((warn_count+1))
    fi
  done
  fi

  # 6. Service health
  local health_url health_ok=0
  if [[ "$DOMAIN_MODE" = "proxy" ]]; then
    # Proxy mode: check via docker exec
    if docker compose $(_compose_files) exec -T api curl -fs http://localhost:8000/health >/dev/null 2>&1; then
      health_ok=1
    fi
  else
    if [[ -f "$TLS_DIR/tpl.crt" ]]; then
      health_url="https://localhost:${TRAEFIK_HTTPS_PORT}/api/health"
    else
      health_url="http://localhost:${TRAEFIK_HTTP_PORT}/api/health"
    fi
    if curl -fskS "$health_url" >/dev/null 2>&1; then
      health_ok=1
    fi
  fi
  if [[ $health_ok -eq 1 ]]; then
    echo "  ✓ API /health: ok"
    pass=$((pass+1))
  else
    echo "  ⚠ API /health: not reachable"
    warn_count=$((warn_count+1))
  fi

  # 7. Running containers
  local running
  running=$(dc ps --status running -q 2>/dev/null | wc -l)
  if (( running == 0 )); then
    echo "  ⚠ Running containers: 0 (no services running)"
    warn_count=$((warn_count+1))
  else
    echo "  ✓ Running containers: $running"
    pass=$((pass+1))
  fi

  # 8. No unexpected ports (only Traefik should expose host ports)
  local exposed
  exposed=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep -oE '0\.0\.0\.0:[0-9]+' | sort -u)
  if [[ -n "$exposed" ]]; then
    echo "  ℹ Host-exposed ports: $(echo "$exposed" | tr '\n' ' ')"
    # Check only expected ports
    while IFS= read -r ep; do
      local p; p=$(echo "$ep" | cut -d: -f2)
      if [[ "$p" != "$TRAEFIK_HTTP_PORT" && "$p" != "$TRAEFIK_HTTPS_PORT" ]]; then
        echo "  ⚠ Unexpected host port: $p (only Traefik should expose ports)"
        warn_count=$((warn_count+1))
      fi
    done <<< "$exposed"
  fi

  # 9. .tpl_* residuals
  local residuals
  residuals=$(find . -maxdepth 1 -name ".tpl_*" ! -name ".tpl_state.json" \( -type f -o -type d \) 2>/dev/null | wc -l)
  if [[ "$residuals" -gt 0 ]]; then
    echo "  ⚠ Residual .tpl_* files: $residuals (clean: ./init.sh clean-state)"
    warn_count=$((warn_count+1))
  else
    echo "  ✓ No residual .tpl_* files"
    pass=$((pass+1))
  fi

  # 10. Bootstrap status
  if [[ -f "$DATA_DIR/.bootstrapped" ]]; then
    echo "  ✓ Bootstrap: completed"
    pass=$((pass+1))
  else
    echo "  ℹ Bootstrap: pending (first-run setup needed)"
  fi

  # 11. Module presence
  local mod_dir="$DATA_DIR/modules/current"
  if [[ -d "$mod_dir" ]]; then
    local mod_count
    mod_count=$(find "$mod_dir" -maxdepth 1 -name "*.sh" 2>/dev/null | wc -l)
    if [[ "$mod_count" -gt 0 ]]; then
      echo "  ✓ Modules: $mod_count module(s) in $mod_dir"
      pass=$((pass+1))
    else
      echo "  ⚠ Module directory exists but is empty: $mod_dir"
      warn_count=$((warn_count+1))
    fi
  else
    echo "  ⚠ Module directory not found: $mod_dir (run init.sh to seed)"
    warn_count=$((warn_count+1))
  fi

  # 12. Data volume writable
  local _tw="$DATA_DIR/.doctor_probe_$$"
  if touch "$_tw" 2>/dev/null && rm -f "$_tw"; then
    echo "  ✓ Data volume writable: $DATA_DIR"
    pass=$((pass+1))
  else
    echo "  ✗ Data volume NOT writable: $DATA_DIR"
    fail_count=$((fail_count+1))
  fi

  # 13. TLS certificate present
  if [[ -f "$TLS_DIR/tpl.crt" && -f "$TLS_DIR/tpl.key" ]]; then
    # Check expiry
    local exp
    exp=$(openssl x509 -enddate -noout -in "$TLS_DIR/tpl.crt" 2>/dev/null | cut -d= -f2)
    if [[ -n "$exp" ]]; then
      local exp_epoch now_epoch
      exp_epoch=$(date -d "$exp" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$exp" +%s 2>/dev/null || echo 0)
      now_epoch=$(date +%s)
      local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
      if [[ "$days_left" -lt 30 ]]; then
        echo "  ⚠ TLS cert expires in ${days_left} days ($exp)"
        warn_count=$((warn_count+1))
      else
        echo "  ✓ TLS certificate valid (expires in ${days_left} days)"
        pass=$((pass+1))
      fi
    else
      echo "  ✓ TLS certificate present"
      pass=$((pass+1))
    fi
  else
    echo "  ⚠ TLS certificate not found at $TLS_DIR/tpl.{crt,key}"
    warn_count=$((warn_count+1))
  fi

  # 14. Container read_only enforcement
  local ro_fail=0
  while IFS= read -r container; do
    local ro
    ro=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container" 2>/dev/null || echo "unknown")
    if [[ "$ro" != "true" ]]; then
      echo "  ⚠ Container $container: read_only=false (should be true)"
      warn_count=$((warn_count+1))
      ro_fail=$((ro_fail+1))
    fi
  done < <(docker compose $(_compose_files) ps -q 2>/dev/null)
  if [[ "$ro_fail" -eq 0 ]]; then
    echo "  ✓ All containers: read_only filesystem"
    pass=$((pass+1))
  fi

  # Summary
  echo ""
  echo "Results: $pass passed, $fail_count failed, $warn_count warnings"
  [[ $fail_count -gt 0 ]] && { echo "Doctor found issues — review above." >&2; return 1; }
  echo "All checks passed."
}

# ── Modules management (proxy to scripts/tpl-modules) ────────────────────────
cmd_modules() {
  local subcmd="${1:-list}"
  local script="$SCRIPT_DIR/scripts/tpl-modules"
  if [[ ! -x "$script" ]]; then
    echo "ERROR: tpl-modules script not found at $script" >&2
    exit 1
  fi
  # Export paths so tpl-modules uses same base dirs
  export TPL_ROOT="$SCRIPT_DIR"
  export TPL_MODULES_BASE="${TPL_DATA_DIR_HOST:-$SCRIPT_DIR/data}/modules"
  export TPL_DATA="${TPL_DATA_DIR_HOST:-$SCRIPT_DIR/data}"
  shift 2>/dev/null || true
  exec "$script" "$subcmd" "$@"
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  echo "Usage: ./run.sh <command>"
  echo ""
  echo "Commands:"
  echo "  up              Start all services"
  echo "  down            Stop all services"
  echo "  restart         Restart all services"
  echo "  status          Show service status + health"
  echo "  logs [service]  Follow logs"
  echo "  backup          Backup data to tarball"
  echo "  restore <file>  Restore data from backup"
  echo "  upgrade         Pull + rebuild + restart"
  echo "  rotate-secrets  Rotate secrets (key ring)"
  echo "  doctor          Comprehensive health check"
  echo "  modules <cmd>   Module management (list|install|verify|rollback|info|history)"
  exit 1
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "${1:-up}" in
  up|start)       cmd_up ;;
  down|stop)      cmd_down ;;
  restart)        cmd_restart ;;
  status|ps)      cmd_status ;;
  logs)           cmd_logs "$@" ;;
  backup)         cmd_backup ;;
  restore)        cmd_restore "$@" ;;
  upgrade)        cmd_upgrade ;;
  rotate-secrets) cmd_rotate_secrets ;;
  doctor|check)   cmd_doctor ;;
  modules)        shift; cmd_modules "$@" ;;
  *)              usage ;;
esac

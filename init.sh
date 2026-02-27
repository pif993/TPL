#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
MODDIR="$ROOT/modules"
STATE="$ROOT/data/.tpl_state.json"
CDIR="$ROOT/compose.d"
die(){ echo "ERR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing: $1"; }

# Validate critical dependencies early
need python3

# state helpers
sload(){ mkdir -p "$(dirname "$STATE")"; [ -f "$STATE" ] || echo '{"installed":{},"updated":0}' >"$STATE"; }
sset(){ sload; python3 - "$STATE" "$1" "$2" <<'PY'
import sys,json,time,os,tempfile
path,mid,ver=sys.argv[1],sys.argv[2],sys.argv[3]
o=json.load(open(path))
o.setdefault('installed',{})[mid]={'ver':ver,'ts':int(time.time())}
o['updated']=int(time.time())
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path))
with os.fdopen(fd,'w') as f: json.dump(o,f,separators=(',',':'))
os.replace(tmp,path)
PY
}
sunset(){ sload; python3 - "$STATE" "$1" <<'PY'
import sys,json,time,os,tempfile
path,mid=sys.argv[1],sys.argv[2]
o=json.load(open(path))
o.setdefault('installed',{}).pop(mid,None)
o['updated']=int(time.time())
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(path))
with os.fdopen(fd,'w') as f: json.dump(o,f,separators=(',',':'))
os.replace(tmp,path)
PY
}
is_installed(){ sload; python3 - "$STATE" "$1" <<'PY'
import sys,json
path,mid=sys.argv[1],sys.argv[2]
o=json.load(open(path))
print('1' if mid in o.get('installed',{}) else '0')
PY
}

# robust meta extraction: prefer static here-doc inside module, else execute meta() in isolated subshell
meta_of_file(){ local f="$1"
  python3 - "$f" <<'PY'
import sys,re,subprocess,shlex
p=sys.argv[1]
s=open(p,'r',encoding='utf-8').read()
m=re.search(r"meta\s*\(\)\s*\{[\s\S]*?cat\s+<<[\'\"]JSON[\'\"]\s*\n([\s\S]*?)\nJSON",s)
if m:
    print(m.group(1))
    sys.exit(0)
try:
    out=subprocess.run(['bash','-c',f'set -euo pipefail; source {shlex.quote(p)}; meta'],capture_output=True,text=True,timeout=5)
    mm=re.search(r'\{[\s\S]*\}',out.stdout)
    if mm:
        print(mm.group(0))
except Exception:
    pass
sys.exit(0)
PY
}

have_fn(){ ( cd "$ROOT" && source "$1" && declare -F "$2" >/dev/null ) 2>/dev/null || return 1; }
call_fn(){ ( cd "$ROOT" && source "$1" && "$2" ) || return 1; }

# ── Cached module listing (built once, reused) ───────────────────────────────
_MOD_CACHE=""
_mod_list_build(){
  [ -d "$MODDIR" ] || { echo ""; return; }
  for f in "$MODDIR"/*.sh; do [ -f "$f" ] || continue
    mj="$(meta_of_file "$f")"
    local fields
    fields=$(printf '%s' "$mj" | python3 -c '
import sys,re,json
r=sys.stdin.read()
m=re.search(r"\{[\s\S]*\}",r)
if not m: sys.exit(1)
o=json.loads(m.group(0))
print(o.get("id",""))
print(o.get("ver",""))
print(",".join(o.get("deps",[])))
print(o.get("desc",""))
') || continue
    local id ver deps desc
    { read -r id; read -r ver; read -r deps; read -r desc; } <<< "$fields"
    [ -z "$id" ] && { echo "WARN: bad meta in $f" >&2; continue; }
    echo "$id|$ver|$deps|$desc|$f"
  done | sort
}

mod_list(){
  if [ -z "$_MOD_CACHE" ]; then
    _MOD_CACHE="$(_mod_list_build)"
  fi
  echo "$_MOD_CACHE"
}

mod_by_id(){ local id="$1"; while IFS= read -r line; do [ -z "$line" ] && continue; local mid="${line%%|*}"; if [ "$mid" = "$id" ]; then echo "${line##*|}"; return 0; fi; done < <(mod_list); return 1; }

# Extract ver and deps from cache line (avoids re-invoking meta_of_file + python3)
_meta_from_cache(){ local id="$1" field="$2"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local mid="${line%%|*}"
    if [ "$mid" = "$id" ]; then
      local rest="${line#*|}"  # ver|deps|desc|file
      case "$field" in
        ver)  echo "${rest%%|*}" ;;
        deps) rest="${rest#*|}"; echo "${rest%%|*}" ;;
      esac
      return 0
    fi
  done < <(mod_list)
  return 1
}

# Dependency resolution with cycle detection
_DEP_STACK=""
_mod_apply_inner(){ local id="$1"
  # Cycle detection
  if echo "$_DEP_STACK" | grep -qw "$id"; then
    die "Circular dependency detected: $_DEP_STACK -> $id"
  fi
  _DEP_STACK="$_DEP_STACK $id"

  # Early exit: already installed → skip without resolving deps
  local already; already="$(is_installed "$id")"
  if [ "$already" = "1" ]; then echo "SKIP $id"; _DEP_STACK="${_DEP_STACK% $id}"; return 0; fi

  local f
  f="$(mod_by_id "$id")" || die "Module not found: $id"

  # Use cached meta instead of re-running python3
  local ver deps
  ver="$(_meta_from_cache "$id" ver)" || ver=""
  deps="$(_meta_from_cache "$id" deps)" || deps=""

  IFS=',' read -r -a depa <<<"${deps:-}"
  for d in "${depa[@]}"; do [ -n "${d:-}" ] && _mod_apply_inner "$d"; done

  have_fn "$f" apply || die "Module $id missing apply()"
  echo "APPLY $id@${ver:-?}"
  call_fn "$f" apply || { have_fn "$f" rollback && { echo "ROLLBACK $id"; call_fn "$f" rollback || true; }; die "Apply failed: $id"; }
  have_fn "$f" check && { call_fn "$f" check || die "Check failed: $id"; }
  sset "$id" "${ver:-0}"
  _DEP_STACK="${_DEP_STACK% $id}"
}

mod_apply(){ for id in "$@"; do _mod_apply_inner "$id"; done; }

mod_reset(){ local id="$1"; local f; f="$(mod_by_id "$id")" || die "Module not found: $id"; have_fn "$f" rollback && { echo "ROLLBACK $id"; call_fn "$f" rollback || true; }; sunset "$id"; }

ensure_base(){
  mkdir -p "$MODDIR" "$CDIR" infra apps apps/api infra/web infra/traefik infra/traefik/dynamic infra/vault/policies
  # Module distribution directories (appliance-grade paths)
  local mod_base="${TPL_MODULES_BASE:-/var/lib/tpl/modules}"
  mkdir -p "$mod_base/releases" 2>/dev/null || true
  mkdir -p "$ROOT/data" 2>/dev/null || true
  [ -f "$ROOT/compose.yml" ] || cat > "$ROOT/compose.yml" <<'YML'
name: tpl
networks:
  default:
    name: tpl_default
volumes:
  pg:
    name: tpl_pg
YML

  # If install.sh has already configured system paths, skip .env/.secrets generation
  if [[ -n "${TPL_SECRETS_DIR_HOST:-}" ]]; then
    sload
    echo "INFO: install.sh environment detected — using system paths"
    return 0
  fi
  # Also check if install.sh wrote /etc/tpl/config.env (standalone init.sh after install.sh)
  if [[ -f /etc/tpl/config.env ]]; then
    set -a; source /etc/tpl/config.env; set +a
    sload
    echo "INFO: install.sh config detected (/etc/tpl/config.env) — using system paths"
    return 0
  fi

  # ── Generate .env (config only — NO SECRETS) ─────────────────────────
  # Migrate stale .env if it has old PORT= but no TPL_SECRETS_DIR_HOST
  if [ -f "$ROOT/.env" ] && grep -q '^PORT=' "$ROOT/.env" 2>/dev/null && ! grep -q 'TPL_SECRETS_DIR_HOST' "$ROOT/.env" 2>/dev/null; then
    echo "INFO: Migrating stale .env (old format) → backup .env.bak.$(date +%s)"
    cp "$ROOT/.env" "$ROOT/.env.bak.$(date +%s)"
    rm -f "$ROOT/.env"
  fi
  if [ ! -f "$ROOT/.env" ]; then
    cat > "$ROOT/.env" <<ENV
# ─────────────────────────────────────────────────────────────────────────────
# TPL Environment Configuration — AUTO-GENERATED $(date -Iseconds)
# ─────────────────────────────────────────────────────────────────────────────
# This file contains ONLY non-sensitive configuration.
# Secrets are in .secrets/ directory (never here).
# NEVER commit this file to version control (.gitignore protects it).
# ─────────────────────────────────────────────────────────────────────────────
DOMAIN_MODE=local
TPL_URL=https://localhost:8443
TPL_SECRETS_DIR_HOST=./.secrets
TPL_DATA_DIR_HOST=./data
TPL_LOG_DIR_HOST=./logs
TPL_TLS_DIR=./.secrets/tls
TRAEFIK_HTTP_PORT=18080
TRAEFIK_HTTPS_PORT=8443
CORS_ORIGINS=https://localhost:8443
AUTH_MODE=keycloak
OIDC_ISSUER=http://keycloak:8080/auth/realms/myapp
OIDC_CLIENT_ID=myapp-web
ENABLE_TRAEFIK=1
AUTO_INSTALL=1
# ENABLE_CONTROL_PLANE=0  # ⚠ NEVER enable in production (RCE risk)
# BOOTSTRAP_MODE: resolved at runtime by run.sh
#   First boot (no /data/.bootstrapped marker) → auto-enabled
#   After first user creation → auto-disabled permanently
#   Override: set BOOTSTRAP_MODE=false in .env to force-disable
# TRAEFIK_BIND_IP=0.0.0.0  # Set to VPN/LAN IP to restrict access
FORCE_HTTPS=true
TRUSTED_PROXY_IPS=172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
LOGIN_WINDOW_SECONDS=120
LOGIN_MAX_ATTEMPTS=8
JWT_TTL_SECONDS=3600
ENV
    chmod 600 "$ROOT/.env"
  fi

  # ── Ensure data directory exists with correct permissions ──
  local DATA_DIR="$ROOT/data"
  if [ ! -d "$DATA_DIR" ]; then
    mkdir -p "$DATA_DIR"
  fi
  # Container UID 999 needs write access to data/.
  # If data/ is owned by container UID (999) from a previous run, use Docker
  # to reclaim it — avoids requiring sudo.
  local _data_owner
  _data_owner=$(stat -c '%u' "$DATA_DIR" 2>/dev/null) || _data_owner="$(id -u)"
  if [ "$_data_owner" != "$(id -u)" ] && [ "$(id -u)" != "0" ]; then
    echo "INFO: Fixing data/ ownership (currently UID $_data_owner) via Docker..."
    docker run --rm -v "$(cd "$DATA_DIR" && pwd):/mnt" alpine sh -c \
      "chown -R $(id -u):$(id -g) /mnt" 2>/dev/null || {
      echo "WARN: Cannot reclaim data/ ownership. Try: sudo chown -R $(id -u) $DATA_DIR" >&2
    }
  fi
  chmod 770 "$DATA_DIR" 2>/dev/null || true
  chown -R "$(id -u):999" "$DATA_DIR" 2>/dev/null || true

  # ── Seed modules into data volume if not already present ──────────
  # Modules live as artifacts in data/modules/current — NOT bind-mounted
  # from the repo. The repo ./modules/ is the source of truth for seeding.
  local MOD_CURRENT="$DATA_DIR/modules/current"
  mkdir -p "$MOD_CURRENT" 2>/dev/null || true
  if ! ls "$MOD_CURRENT"/*.sh >/dev/null 2>&1; then
    echo "INFO: Seeding modules into $MOD_CURRENT from repo..."
    if [ -d "$ROOT/modules" ]; then
      cp -a "$ROOT/modules/"*.sh "$MOD_CURRENT/" 2>/dev/null || true
      local count; count=$(ls "$MOD_CURRENT"/*.sh 2>/dev/null | wc -l)
      echo "INFO: Seeded $count modules"
    fi
    chmod -R 755 "$MOD_CURRENT" 2>/dev/null || true
  fi

  # ── Generate secrets into .secrets/ directory (one file per secret) ──
  local SECRETS_DIR="$ROOT/.secrets"
  if [ ! -d "$SECRETS_DIR" ]; then
    echo "INFO: Generating cryptographic secrets into .secrets/ directory." >&2
    # Defence-in-depth: restrict default permissions for all generated files
    umask 077
    mkdir -p "$SECRETS_DIR"

    _GEN_SECRET(){ head -c $(( $1 * 2 )) /dev/urandom | base64 | tr -d '/+=\n' | head -c "$2"; }

    # Write each secret to its own file (chmod 640 — owner+group read)
    _WRITE_SECRET(){ printf '%s' "$2" > "$SECRETS_DIR/$1"; chmod 640 "$SECRETS_DIR/$1"; }

    _WRITE_SECRET "api_secret"         "$(_GEN_SECRET 48 48)"
    _WRITE_SECRET "tpl_admin_password"  "$(_GEN_SECRET 32 24)"
    _WRITE_SECRET "tpl_user_password"   "$(_GEN_SECRET 32 24)"
    _WRITE_SECRET "comm_shared_secret"  "$(_GEN_SECRET 48 48)"
    _WRITE_SECRET "tpl_master_key"      "$(_GEN_SECRET 64 64)"

    # ── Generate self-signed TLS certificate for dev HTTPS ──────────────
    local TLS_DIR="$SECRETS_DIR/tls"
    mkdir -p "$TLS_DIR"
    if command -v openssl >/dev/null 2>&1; then
      openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$TLS_DIR/tpl.key" -out "$TLS_DIR/tpl.crt" \
        -subj "/CN=localhost/O=TPL Dev" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
      chmod 640 "$TLS_DIR/tpl.key"
      chmod 644 "$TLS_DIR/tpl.crt"
    fi

    # ── Fix ownership so container UID 999 can read secrets ─────────────
    # The API container runs as user 999:999 and mounts .secrets/ read-only.
    # Without this, secrets created by any user would be unreadable inside
    # the container. Use Docker to chgrp (non-root can't chgrp to foreign GID).
    # Permissions: dir 750, files 640, group=999 → container can read.
    echo "INFO: Setting secrets group ownership for container (GID 999)..."
    docker run --rm -v "$SECRETS_DIR:/mnt" alpine sh -c \
      'chgrp -R 999 /mnt && find /mnt -type d -exec chmod 750 {} \; && find /mnt -type f -exec chmod 640 {} \; && chmod 644 /mnt/tls/tpl.crt 2>/dev/null; true' \
      2>/dev/null || {
      # Fallback: try native chgrp (works if running as root or user is in GID 999)
      chgrp -R 999 "$SECRETS_DIR" 2>/dev/null || true
      chmod 750 "$SECRETS_DIR" 2>/dev/null || true
      find "$SECRETS_DIR" -type f -exec chmod 640 {} \; 2>/dev/null || true
      find "$SECRETS_DIR" -type d -exec chmod 750 {} \; 2>/dev/null || true
      chmod 644 "$SECRETS_DIR/tls/tpl.crt" 2>/dev/null || true
    }

    # Read generated password for display
    local _admin_pw _user_pw
    _admin_pw=$(cat "$SECRETS_DIR/tpl_admin_password" 2>/dev/null) || _admin_pw="(errore lettura)"
    _user_pw=$(cat "$SECRETS_DIR/tpl_user_password" 2>/dev/null) || _user_pw="(errore lettura)"

    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  PRIMO AVVIO — Secrets e credenziali generate               ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo "║  Secrets:  .secrets/ (files chmod 640)                      ║"
    echo "║  TLS cert: .secrets/tls/ (self-signed, dev-only)            ║"
    echo "║                                                             ║"
    printf "║  👤 Admin:  admin / %-38s ║\n" "$_admin_pw"
    printf "║  👤 User:   user  / %-38s ║\n" "$_user_pw"
    echo "║                                                             ║"
    echo "║  ⚠  CAMBIO PASSWORD OBBLIGATORIO al primo login!            ║"
    echo "║  🔒  Le password sopra sono temporanee e monouso.           ║"
    echo "║                                                             ║"
    echo "║  HTTPS: https://localhost:8443 (self-signed)                ║"
    echo "║                                                             ║"
    echo "║  NON condividere o committare .secrets/ (.gitignore).       ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
  fi

  # ── Generate TLS routes for Traefik (if cert exists) ────────────────
  if [[ -f "$ROOT/.secrets/tls/tpl.crt" && ! -f "$ROOT/infra/traefik/dynamic/routes-tls.yml" ]]; then
    cat > "$ROOT/infra/traefik/dynamic/routes-tls.yml" <<'YML'
# Auto-generated by init.sh — HTTPS routes (requires TLS cert in .secrets/tls/)
http:
  routers:
    web-tls:
      rule: "PathPrefix(`/`)"
      service: web
      priority: 1
      entryPoints: [websecure]
      tls: {}
    api-tls:
      rule: "PathPrefix(`/api`)"
      service: api
      middlewares: [sa]
      priority: 9
      entryPoints: [websecure]
      tls: {}
tls:
  certificates:
    - certFile: /etc/traefik/tls/tpl.crt
      keyFile: /etc/traefik/tls/tpl.key
YML
  fi

  sload
}

apply_all(){
  ensure_base
  # ── Maximum security by default ──────────────────────────────────────────
  # Vault (20_vault) manages all secrets: encrypted at rest, AppRole auth,
  # per-service policies, tmpfs delivery, audit log, rotation.
  # Keycloak (60_auth_keycloak) provides enterprise OIDC authentication:
  # realm roles, password policies, brute force protection, SSO.
  #
  # For lightweight/dev-only deployments without Vault/Keycloak:
  #   ./init.sh dev-install
  mod_apply 10_traefik 20_vault 30_web_gui 35_ux_linear 40_api_base 45_api_engine_host 60_auth_keycloak 80_language_engine 90_log_engine 95_communication_engine 96_security_hardening 97_encryption 100_ai_log_analysis 101_system_monitoring_ai 102_user_management 103_router_manager 104_template_manager 105_version_manager 106_resilience 107_self_diagnosis 108_ota_update
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  INSTALLAZIONE COMPLETA — MASSIMA SICUREZZA                ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  Vault:    secrets cifrati, AppRole, audit, rotation       ║"
  echo "║  Keycloak: OIDC enterprise, realm roles, password policy   ║"
  echo "║  Auth:     AUTH_MODE=keycloak (default)                    ║"
  echo "║                                                            ║"
  echo "║  Per modalità dev (senza Vault/Keycloak):                  ║"
  echo "║    ./init.sh dev-install                                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "OK: maximum security modules applied (Vault + Keycloak)"
}

apply_lite(){
  ensure_base
  # ── Development / standalone mode ────────────────────────────────────────
  # Uses local auth (Argon2id + file-based users) without Vault or Keycloak.
  # Suitable for development, testing, or air-gapped environments.
  # ⚠  NOT recommended for production — use apply_all() instead.
  mod_apply 10_traefik 30_web_gui 35_ux_linear 40_api_base 45_api_engine_host 50_auth_local 80_language_engine 90_log_engine 95_communication_engine 96_security_hardening 97_encryption 100_ai_log_analysis 101_system_monitoring_ai 102_user_management 103_router_manager 104_template_manager 105_version_manager 106_resilience 107_self_diagnosis 108_ota_update
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  DEV-INSTALL — Modalità locale (sicurezza ridotta)         ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  Auth:     AUTH_MODE=local (Argon2id + file users)         ║"
  echo "║  Secrets:  .secrets/ directory (file-based, no Vault)      ║"
  echo "║  Keycloak: NON installato                                  ║"
  echo "║                                                            ║"
  echo "║  ⚠  Per massima sicurezza in produzione:                   ║"
  echo "║    ./init.sh auto-install                                  ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "OK: development modules applied (local auth, no Vault/Keycloak)"
}

doctor(){
  need bash; need python3
  need docker
  ensure_base

  local pass_count=0 fail_count=0 warn_count=0
  _doc_pass(){ echo "  ✓ $*"; pass_count=$((pass_count+1)); }
  _doc_fail(){ echo "  ✗ $*"; fail_count=$((fail_count+1)); }
  _doc_warn(){ echo "  ⚠ $*"; warn_count=$((warn_count+1)); }

  echo "TPL Doctor (init.sh) — single-source-of-truth audit"
  echo "════════════════════════════════════════════════════════"

  # ── 1. Compose config valid ─────────────────────────────────────────
  echo ""
  echo "── 1. Compose configuration ──"
  local args=(-f "$ROOT/compose.yml")
  local f
  for f in "$CDIR"/*.yml; do [ -f "$f" ] && args+=(-f "$f"); done
  if docker compose "${args[@]}" config >/dev/null 2>&1; then
    _doc_pass "Compose configuration valid"
  else
    _doc_fail "Compose configuration invalid"
  fi

  # ── 2. compose.d ↔ registered modules coherence ────────────────────
  echo ""
  echo "── 2. compose.d ↔ module state coherence ──"
  sload
  local installed_modules
  installed_modules=$(python3 - "$STATE" <<'PY'
import sys, json
s = json.load(open(sys.argv[1]))
for m in sorted(s.get("installed", {}).keys()):
    print(m)
PY
  )

  # Map: module_id → expected compose fragment filename
  # Modules that produce compose fragments follow naming convention:
  #   10_traefik → compose.d/10-traefik.yml
  local orphan_fragments=0 missing_fragments=0
  # Check each compose.d fragment has a matching installed module
  for frag in "$CDIR"/*.yml; do
    [ -f "$frag" ] || continue
    local base; base="$(basename "$frag" .yml)"
    # Convert fragment name (e.g. 40-api) to module pattern (e.g. 40_api*)
    local mod_pattern; mod_pattern=$(echo "$base" | sed 's/-/_/g')
    if echo "$installed_modules" | grep -q "^${mod_pattern}"; then
      : # matched
    else
      # Some fragments are hand-managed (e.g. 11-dev, 12-proxy)
      if [[ "$base" =~ ^(11-dev|12-proxy)$ ]]; then
        : # known non-module fragment, skip
      else
        _doc_warn "Orphan compose fragment: $base.yml (no matching module in state)"
        orphan_fragments=$((orphan_fragments+1))
      fi
    fi
  done
  # Check each module that should produce a compose fragment
  while IFS= read -r mid; do
    [ -z "$mid" ] && continue
    # Only check modules that typically produce compose fragments (by prefix convention)
    local prefix; prefix="${mid%%_*}"
    case "$prefix" in
      10|20|30|40|50|60) # core infrastructure modules produce compose fragments
        local expected_frag; expected_frag=$(echo "$mid" | sed 's/_/-/g; s/\(.*\)/\1.yml/')
        # Try exact match, then prefix match
        if [ -f "$CDIR/$expected_frag" ] || ls "$CDIR"/"${prefix}-"*.yml >/dev/null 2>&1; then
          : # found
        else
          _doc_warn "Module $mid installed but no compose.d fragment found"
          missing_fragments=$((missing_fragments+1))
        fi
        ;;
    esac
  done <<< "$installed_modules"
  if [ "$orphan_fragments" -eq 0 ] && [ "$missing_fragments" -eq 0 ]; then
    _doc_pass "compose.d fragments match registered modules"
  fi

  # ── 3. Generated file checksum / drift detection ───────────────────
  echo ""
  echo "── 3. Generated file drift detection ──"
  # Files generated by modules — check against known checksums in state
  local checksum_file="$ROOT/data/.tpl_checksums.json"
  if [ -f "$checksum_file" ]; then
    local drift_count=0 checked_count=0
    while IFS='|' read -r fpath expected_hash; do
      [ -z "$fpath" ] && continue
      if [ ! -f "$ROOT/$fpath" ]; then
        _doc_warn "Generated file missing: $fpath"
        drift_count=$((drift_count+1))
        continue
      fi
      local actual_hash; actual_hash=$(sha256sum "$ROOT/$fpath" 2>/dev/null | awk '{print $1}')
      if [ "$actual_hash" != "$expected_hash" ]; then
        _doc_warn "DRIFT: $fpath (expected ${expected_hash:0:12}… got ${actual_hash:0:12}…)"
        drift_count=$((drift_count+1))
      fi
      checked_count=$((checked_count+1))
    done < <(python3 - "$checksum_file" <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    for path, info in d.get("files", {}).items():
        print(f"{path}|{info.get('sha256', '')}")
except Exception:
    pass
PY
    )
    if [ "$drift_count" -eq 0 ] && [ "$checked_count" -gt 0 ]; then
      _doc_pass "All $checked_count generated files match checksums (no drift)"
    elif [ "$checked_count" -eq 0 ]; then
      _doc_warn "Checksum file exists but has no entries"
    fi
  else
    _doc_warn "No checksum registry (data/.tpl_checksums.json). Run: ./init.sh snapshot-checksums"
  fi

  # ── 4. Module file integrity (modules in data/modules/current) ─────
  echo ""
  echo "── 4. Module file integrity ──"
  local mod_current="$ROOT/data/modules/current"
  if [ -d "$mod_current" ]; then
    local mod_ok=0 mod_bad=0
    for mf in "$mod_current"/*.sh; do
      [ -f "$mf" ] || continue
      # Check module has a valid meta() function
      if grep -q 'meta()' "$mf" 2>/dev/null; then
        mod_ok=$((mod_ok+1))
      else
        _doc_warn "Module missing meta(): $(basename "$mf")"
        mod_bad=$((mod_bad+1))
      fi
    done
    if [ "$mod_bad" -eq 0 ] && [ "$mod_ok" -gt 0 ]; then
      _doc_pass "$mod_ok modules have valid meta() functions"
    fi
  else
    _doc_warn "Module directory not found: $mod_current"
  fi

  # ── 5. State file integrity ────────────────────────────────────────
  echo ""
  echo "── 5. State file integrity ──"
  if [ -f "$STATE" ]; then
    if python3 -c "import json; json.load(open('$STATE'))" 2>/dev/null; then
      local installed_count
      installed_count=$(python3 -c "import json; print(len(json.load(open('$STATE')).get('installed',{})))")
      _doc_pass "State file valid: $installed_count modules registered"
    else
      _doc_fail "State file corrupted: $STATE"
    fi
  else
    _doc_warn "State file missing (first run?): $STATE"
  fi

  # ── Summary ────────────────────────────────────────────────────────
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "Results: $pass_count passed, $fail_count failed, $warn_count warnings"
  [ "$fail_count" -gt 0 ] && { echo "Doctor found critical issues — review above." >&2; return 1; }
  [ "$warn_count" -gt 0 ] && echo "Some warnings — review above."
  [ "$fail_count" -eq 0 ] && [ "$warn_count" -eq 0 ] && echo "All checks passed."
  return 0
}

# ── Snapshot checksums of generated files (called after module apply) ──
snapshot_checksums(){
  local checksum_file="$ROOT/data/.tpl_checksums.json"
  local generated_files=(
    "compose.yml"
    "infra/traefik/traefik.yml"
    "infra/traefik/dynamic/routes.yml"
    "infra/traefik/dynamic/routes-tls.yml"
    "infra/web/nginx.conf"
    "apps/api/app/main.py"
    "apps/api/requirements.txt"
    "apps/api/Dockerfile"
  )
  # Also add compose.d fragments
  for frag in "$CDIR"/*.yml; do
    [ -f "$frag" ] && generated_files+=("compose.d/$(basename "$frag")")
  done

  python3 - "$checksum_file" "$ROOT" "${generated_files[@]}" <<'PY'
import sys, json, hashlib, time, os

checksum_file = sys.argv[1]
root = sys.argv[2]
files = sys.argv[3:]

result = {"ts": int(time.time()), "files": {}}
for rel_path in files:
    full = os.path.join(root, rel_path)
    if os.path.isfile(full):
        h = hashlib.sha256(open(full, "rb").read()).hexdigest()
        result["files"][rel_path] = {
            "sha256": h,
            "size": os.path.getsize(full),
            "mtime": int(os.path.getmtime(full)),
        }

with open(checksum_file, "w") as f:
    json.dump(result, f, indent=2)
print(f"OK: {len(result['files'])} file checksums saved to {checksum_file}")
PY
}

# commands
cmd="${1:-list}"; shift || true
case "$cmd" in
  init) ensure_base; echo "OK: base ready" ;;
  auto-install) apply_all ;;
  apply-all) apply_all ;;
  dev-install) apply_lite ;;
  doctor) doctor ;;
  snapshot-checksums) ensure_base; snapshot_checksums ;;
  bootstrap)
    # Convenience: enable BOOTSTRAP_MODE temporarily for first-run setup.
    # Auto-disables once users are created via the UI.
    ensure_base
    if [ ! -f "$ROOT/.env" ]; then
      die ".env not found — run: ./init.sh auto-install first"
    fi
    if grep -q '^BOOTSTRAP_MODE=' "$ROOT/.env" 2>/dev/null; then
      sed -i 's/^BOOTSTRAP_MODE=.*/BOOTSTRAP_MODE=true/' "$ROOT/.env"
      echo "OK: BOOTSTRAP_MODE=true set in .env (temporary)"
    else
      echo 'BOOTSTRAP_MODE=true' >> "$ROOT/.env"
      echo "OK: BOOTSTRAP_MODE=true appended to .env (temporary)"
    fi
    echo ""
    echo "  Next steps:"
    echo "    1. ./run.sh up"
    echo "    2. Login: admin / \$(cat .secrets/tpl_admin_password)"
    echo "    3. Create real users via User Management UI"
    echo "    4. BOOTSTRAP_MODE auto-disables when users file exists"
    echo "    5. To force-disable: sed -i 's/BOOTSTRAP_MODE=true/BOOTSTRAP_MODE=false/' .env"
    echo ""
    ;;
  clean-state)
    # Remove residual .tpl_* state files from project root.
    # These are Docker-created leftovers; state now lives in /data volume.
    echo "Removing .tpl_* state files from project root..."
    found=0
    for f in "$ROOT"/.tpl_audit.jsonl "$ROOT"/.tpl_comm.jsonl "$ROOT"/.tpl_events.jsonl \
             "$ROOT"/.tpl_security.jsonl "$ROOT"/.tpl_users.json "$ROOT"/.tpl_config_baseline.json \
             "$ROOT"/.tpl_resilience_metrics.json "$ROOT"/.tpl_changelog.jsonl \
             "$ROOT"/.tpl_diagnosis.jsonl; do
      [ -f "$f" ] && { rm -f "$f" 2>/dev/null || echo "WARN: Cannot remove $f (try: sudo rm -f $f)"; found=$((found+1)); }
    done
    [ -d "$ROOT/.tpl_backups" ] && { rm -rf "$ROOT/.tpl_backups" 2>/dev/null || echo "WARN: Cannot remove .tpl_backups/ (try: sudo rm -rf .tpl_backups/)"; found=$((found+1)); }
    echo "OK: cleaned $found residual state file(s). State lives in Docker /data volume."
    ;;
  auto)
    apply_all
    if command -v docker >/dev/null 2>&1; then
      ENABLE_TRAEFIK="${ENABLE_TRAEFIK:-1}" "$ROOT/run.sh" up
    else
      echo "WARN: docker not available, install completed but run skipped"
    fi
    ;;
  list) mod_list | cut -d'|' -f1-4 ;;
  apply) [ "${1:-}" ] || die "Usage: ./init.sh apply <module_id> [module_id...]"; mod_apply "$@" ;;
  reset-module) [ "${1:-}" ] || die "Usage: ./init.sh reset-module <module_id>"; mod_reset "$1" ;;
  *) echo "Usage: ./init.sh [init|auto-install|dev-install|apply-all|doctor|snapshot-checksums|auto|bootstrap|clean-state|list|apply|reset-module]"; exit 1 ;;
esac

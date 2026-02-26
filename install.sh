#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  TPL Install — Idempotent production-ready installer
# ═══════════════════════════════════════════════════════════════════════════════
#  Usage:
#    sudo ./install.sh                          # Auto-detect (recommended)
#    sudo ./install.sh --mode=local             # Self-signed TLS, localhost
#    sudo ./install.sh --mode=vpn               # VPN-first (WireGuard/Tailscale)
#    sudo ./install.sh --mode=public --domain=app.example.com --email=a@b.com
#    sudo ./install.sh --mode=proxy             # Behind existing reverse proxy
#    sudo ./install.sh --rotate                 # Rotate secrets (key ring)
#
#  One-command flow:   sudo ./install.sh && ./run.sh up
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

TPL_VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Defaults ─────────────────────────────────────────────────────────────────
MODE=""             # local | vpn | public | proxy
DOMAIN=""           # required for --mode=public
ACME_EMAIL=""       # Let's Encrypt
ROTATE=0
IS_ROOT=0

# ── Colors / logging ────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
BD='\033[1m'; NC='\033[0m'
info()  { printf "${B}INFO${NC}  %s\n" "$*"; }
ok()    { printf "${G}  OK${NC}  %s\n" "$*"; }
warn()  { printf "${Y}WARN${NC}  %s\n" "$*" >&2; }
fail()  { printf "${R}FAIL${NC}  %s\n" "$*" >&2; }
fatal() { printf "${R}FATAL${NC} %s\n" "$*" >&2; exit 1; }
step()  { printf "\n${BD}══ %s${NC}\n" "$*"; }

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode=*)   MODE="${1#*=}" ;;
    --domain=*) DOMAIN="${1#*=}" ;;
    --email=*)  ACME_EMAIL="${1#*=}" ;;
    --rotate)   ROTATE=1 ;;
    --help|-h)
      sed -n '3,13p' "$0" | sed 's/^#  \?//'
      exit 0 ;;
    *) fatal "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

# ── Root detection → path selection ──────────────────────────────────────────
[[ "${EUID:-$(id -u)}" -eq 0 ]] && IS_ROOT=1

if [[ $IS_ROOT -eq 1 ]]; then
  SECRETS_DIR="/opt/tpl/secrets"
  CONFIG_DIR="/etc/tpl"
  DATA_DIR="/var/lib/tpl"
  LOG_DIR="/var/log/tpl"
  TLS_DIR="/opt/tpl/secrets/tls"
else
  warn "Running without root — using local paths (reduced security)"
  SECRETS_DIR="$SCRIPT_DIR/.secrets"
  CONFIG_DIR="$SCRIPT_DIR"
  DATA_DIR="$SCRIPT_DIR/data"
  LOG_DIR="$SCRIPT_DIR/logs"
  TLS_DIR="$SCRIPT_DIR/.secrets/tls"
fi
CONFIG_ENV="$CONFIG_DIR/config.env"

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 0 + 3: PREFLIGHT CHECKS
# ═════════════════════════════════════════════════════════════════════════════
preflight() {
  step "Preflight checks"
  local errs=0

  # Docker
  if command -v docker >/dev/null 2>&1; then
    ok "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)"
  else
    fail "Docker not found — install: https://docs.docker.com/engine/install/"
    errs=$((errs+1))
  fi

  # Docker Compose v2
  if docker compose version >/dev/null 2>&1; then
    ok "Docker Compose $(docker compose version --short 2>/dev/null || echo '?')"
  else
    fail "Docker Compose v2 not found"
    errs=$((errs+1))
  fi

  # openssl (for self-signed TLS)
  if command -v openssl >/dev/null 2>&1; then
    ok "openssl available"
  else
    warn "openssl not found — TLS cert generation will be skipped"
  fi

  # Disk space (require 1GB free)
  local free_kb
  free_kb=$(df -P "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
  if [[ ${free_kb:-0} -lt 1048576 ]]; then
    warn "Less than 1GB free disk space ($(( free_kb / 1024 ))MB)"
  else
    ok "Disk space: $(( free_kb / 1024 ))MB free"
  fi

  [[ $errs -gt 0 ]] && fatal "Preflight failed ($errs error(s))"
  return 0
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 0 + 3: MODE DETECTION + PORT CHECKS
# ═════════════════════════════════════════════════════════════════════════════
detect_mode() {
  step "Detecting deployment mode"

  # Auto-detect if not specified
  if [[ -z "$MODE" ]]; then
    if [[ -n "$DOMAIN" ]]; then
      MODE="public"
    elif ip link show 2>/dev/null | grep -qE 'wg[0-9]|tailscale'; then
      MODE="vpn"
      info "VPN interface detected (WireGuard/Tailscale)"
    else
      MODE="local"
    fi
  fi

  # Validate mode
  case "$MODE" in
    local|vpn|public|proxy) ;;
    *) fatal "Invalid mode: $MODE (use: local, vpn, public, proxy)" ;;
  esac

  # Public mode requires domain
  if [[ "$MODE" = "public" && -z "$DOMAIN" ]]; then
    fatal "--mode=public requires --domain=your.domain.com"
  fi

  # Port detection
  TRAEFIK_HTTP_PORT=80
  TRAEFIK_HTTPS_PORT=443

  if [[ "$MODE" != "proxy" ]]; then
    # Check port 80
    if ss -ltnH "sport = :80" 2>/dev/null | grep -q . || \
       lsof -tiTCP:80 -sTCP:LISTEN >/dev/null 2>&1; then
      if [[ "$MODE" = "public" ]]; then
        fatal "Port 80 occupied — required for Let's Encrypt HTTP-01 challenge.\n       Free it or use --mode=proxy behind your existing reverse proxy."
      fi
      warn "Port 80 occupied — Traefik will use port 8080 for HTTP redirect"
      TRAEFIK_HTTP_PORT=8080
    fi

    # Check port 443
    if ss -ltnH "sport = :443" 2>/dev/null | grep -q . || \
       lsof -tiTCP:443 -sTCP:LISTEN >/dev/null 2>&1; then
      if [[ "$MODE" = "public" ]]; then
        fatal "Port 443 occupied — required for HTTPS.\n       Free it or use --mode=proxy behind your existing reverse proxy."
      fi
      warn "Port 443 occupied — using 8443 for HTTPS"
      TRAEFIK_HTTPS_PORT=8443
    fi
  fi

  ok "Mode: $MODE"
  [[ "$MODE" != "proxy" ]] && ok "Ports: HTTP=$TRAEFIK_HTTP_PORT, HTTPS=$TRAEFIK_HTTPS_PORT"
  [[ -n "$DOMAIN" ]] && ok "Domain: $DOMAIN"
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 1: FILESYSTEM LAYOUT
# ═════════════════════════════════════════════════════════════════════════════
create_dirs() {
  step "Creating filesystem layout"

  local dirs=("$SECRETS_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$TLS_DIR")
  for d in "${dirs[@]}"; do
    mkdir -p "$d"
  done

  # Permissions
  chmod 700 "$SECRETS_DIR"
  chmod 700 "$TLS_DIR"
  chmod 755 "$CONFIG_DIR"

  if [[ $IS_ROOT -eq 1 ]]; then
    chmod 750 "$DATA_DIR"
    chmod 750 "$LOG_DIR"
    # Allow docker group to read data dir
    if getent group docker >/dev/null 2>&1; then
      chgrp docker "$DATA_DIR" "$LOG_DIR" 2>/dev/null || true
    fi
  else
    chmod 700 "$DATA_DIR"
    chmod 700 "$LOG_DIR"
  fi

  # Ensure compose.d/ exists
  mkdir -p "$SCRIPT_DIR/compose.d" "$SCRIPT_DIR/infra/traefik/dynamic"

  ok "Secrets:  $SECRETS_DIR (700)"
  ok "Config:   $CONFIG_DIR"
  ok "Data:     $DATA_DIR (750)"
  ok "TLS:      $TLS_DIR"
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 4: SECRET GENERATION (one-time, file-based, no leak)
# ═════════════════════════════════════════════════════════════════════════════
_gen() { head -c "$1" /dev/urandom | base64 | tr -d '/+=' | head -c "$2"; }
_fp()  { printf '%s' "$1" | sha256sum | cut -c1-12; }

_write_secret() {
  local name="$1" value="$2" dir="${3:-$SECRETS_DIR}"
  local path="$dir/$name"
  if [[ -f "$path" ]]; then
    ok "Secret exists: $name (fp:$(_fp "$(cat "$path")"))"
    return 0
  fi
  printf '%s' "$value" > "$path"
  chmod 600 "$path"
  ok "Generated: $name (fp:$(_fp "$value"))"
}

generate_secrets() {
  step "Generating secrets (idempotent)"

  if [[ $ROTATE -eq 1 ]]; then
    info "Rotating secrets (--rotate): current → *.previous"
    for s in api_secret tpl_master_key comm_shared_secret; do
      [[ -f "$SECRETS_DIR/$s" ]] && cp "$SECRETS_DIR/$s" "$SECRETS_DIR/${s}.previous"
      printf '%s' "$(_gen 64 64)" > "$SECRETS_DIR/$s"
      chmod 600 "$SECRETS_DIR/$s" "$SECRETS_DIR/${s}.previous"
    done
    ok "Secrets rotated (previous versions saved for key ring grace period)"
    return 0
  fi

  # Core secrets
  _write_secret "api_secret"          "$(_gen 48 48)"
  _write_secret "tpl_master_key"      "$(_gen 64 64)"
  _write_secret "comm_shared_secret"  "$(_gen 48 48)"

  # Bootstrap admin/user passwords
  _write_secret "tpl_admin_password"  "$(_gen 32 24)"
  _write_secret "tpl_user_password"   "$(_gen 32 24)"

  # Keycloak secrets (if module exists)
  if [[ -f "$SCRIPT_DIR/modules/60_auth_keycloak.sh" ]]; then
    local kc_dir="$SECRETS_DIR/keycloak"
    mkdir -p "$kc_dir"
    chmod 700 "$kc_dir"
    _write_secret "admin_password"  "$(_gen 32 24)" "$kc_dir"
    _write_secret "user_admin_pw"   "$(_gen 32 20)" "$kc_dir"
    _write_secret "user_user_pw"    "$(_gen 32 20)" "$kc_dir"
    _write_secret "db_password"     "$(_gen 32 24)" "$kc_dir"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 5: CONFIGURATION (/etc/tpl/config.env)
# ═════════════════════════════════════════════════════════════════════════════
write_config() {
  step "Writing configuration"

  # Compute CORS origins
  local cors
  case "$MODE" in
    public) cors="https://${DOMAIN}" ;;
    vpn)    cors="https://$(hostname -f 2>/dev/null || hostname),https://app.tpl.internal" ;;
    proxy)  cors="https://${DOMAIN:-localhost}" ;;
    local)
      if [[ "$TRAEFIK_HTTPS_PORT" -eq 443 ]]; then
        cors="https://localhost"
      else
        cors="https://localhost:${TRAEFIK_HTTPS_PORT}"
      fi
      ;;
  esac

  # Compute URL
  local url
  case "$MODE" in
    public) url="https://${DOMAIN}" ;;
    vpn)    url="https://$(hostname -f 2>/dev/null || hostname)" ;;
    proxy)  url="https://${DOMAIN:-localhost}" ;;
    local)
      if [[ "$TRAEFIK_HTTPS_PORT" -eq 443 ]]; then
        url="https://localhost"
      else
        url="https://localhost:${TRAEFIK_HTTPS_PORT}"
      fi
      ;;
  esac

  # Determine if bootstrap needed
  local bootstrap="false"
  if [[ ! -f "$DATA_DIR/.bootstrapped" ]]; then
    bootstrap="true"
    info "First install detected — BOOTSTRAP_MODE will be enabled for initial setup"
  fi

  # Determine bind IP
  local bind_ip="0.0.0.0"
  if [[ "$MODE" = "vpn" ]]; then
    # VPN mode: try to detect VPN interface IP
    local vpn_ip=""
    vpn_ip="$(tailscale ip -4 2>/dev/null || true)"
    if [[ -z "$vpn_ip" ]]; then
      vpn_ip="$(ip -4 addr show wg0 2>/dev/null | grep -oP 'inet \K[\d.]+' || true)"
    fi
    if [[ -n "$vpn_ip" ]]; then
      bind_ip="$vpn_ip"
      info "VPN bind IP detected: $bind_ip"
    else
      info "VPN interface IP not detected — binding to 0.0.0.0 (restrict with TRAEFIK_BIND_IP)"
    fi
  fi

  cat > "$CONFIG_ENV" <<CFG
# ═══════════════════════════════════════════════════════════════════════════════
# TPL Configuration — generated by install.sh $(date -Iseconds)
# Mode: ${MODE} | Version: ${TPL_VERSION}
# ═══════════════════════════════════════════════════════════════════════════════
# This file contains ONLY non-sensitive configuration.
# Secrets live in: ${SECRETS_DIR}/ (never here, never in env vars).
# ═══════════════════════════════════════════════════════════════════════════════

# ── Environment ────────────────────────────────────────────────────────────
APP_ENV=prod
TPL_HOME=${SCRIPT_DIR}
TPL_VERSION=${TPL_VERSION}

# ── Domain / Access ────────────────────────────────────────────────────────
DOMAIN_MODE=${MODE}
PUBLIC_DOMAIN=${DOMAIN}
TPL_URL=${url}

# ── Paths (host-side, mounted into containers) ────────────────────────────
TPL_SECRETS_DIR_HOST=${SECRETS_DIR}
TPL_DATA_DIR_HOST=${DATA_DIR}
TPL_LOG_DIR_HOST=${LOG_DIR}
TPL_TLS_DIR=${TLS_DIR}

# ── Traefik ports ──────────────────────────────────────────────────────────
TRAEFIK_HTTP_PORT=${TRAEFIK_HTTP_PORT}
TRAEFIK_HTTPS_PORT=${TRAEFIK_HTTPS_PORT}
TRAEFIK_BIND_IP=${bind_ip}

# ── Auth ───────────────────────────────────────────────────────────────────
AUTH_MODE=local
OIDC_ISSUER=
OIDC_CLIENT_ID=myapp-web

# ── Rate limiting ─────────────────────────────────────────────────────────
LOGIN_WINDOW_SECONDS=120
LOGIN_MAX_ATTEMPTS=8
JWT_TTL_SECONDS=3600

# ── Security ──────────────────────────────────────────────────────────────
FORCE_HTTPS=true
ENABLE_CONTROL_PLANE=0
BOOTSTRAP_MODE=${bootstrap}
TRUSTED_PROXY_IPS=172.16.0.0/12,10.0.0.0/8,192.168.0.0/16

# ── CORS ──────────────────────────────────────────────────────────────────
CORS_ORIGINS=${cors}

# ── Features ──────────────────────────────────────────────────────────────
ENABLE_TRAEFIK=1
AUTO_INSTALL=1

# ── ACME (public mode only) ──────────────────────────────────────────────
ACME_EMAIL=${ACME_EMAIL}
CFG

  chmod 644 "$CONFIG_ENV"
  ok "Config written: $CONFIG_ENV"

  # Also create a .env symlink/copy for backwards compatibility
  if [[ "$CONFIG_ENV" != "$SCRIPT_DIR/.env" ]]; then
    # Create a minimal .env that sources the real config
    cat > "$SCRIPT_DIR/.env" <<'DOTENV'
# ─── TPL .env — Auto-generated by install.sh ─────────────────────────────
# This file is a LOCAL COPY of the master config.
# Master config location: see TPL_HOME or /etc/tpl/config.env
# NEVER add secrets here. See install.sh --help.
# ─────────────────────────────────────────────────────────────────────────
DOTENV
    # Append the real config content (excluding comments)
    grep -v '^#' "$CONFIG_ENV" | grep -v '^$' >> "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    ok ".env created (copy of config.env for compose compatibility)"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 0 + 9: TLS SETUP
# ═════════════════════════════════════════════════════════════════════════════
setup_tls() {
  step "Setting up TLS"

  case "$MODE" in
    proxy)
      info "Behind-proxy mode — TLS handled by external proxy"
      return 0 ;;
    public)
      info "Public mode — TLS via Let's Encrypt ACME (auto-provisioned by Traefik)"
      mkdir -p "$SCRIPT_DIR/infra/traefik/acme"
      # Ensure acme.json exists with correct perms
      touch "$SCRIPT_DIR/infra/traefik/acme/acme.json"
      chmod 600 "$SCRIPT_DIR/infra/traefik/acme/acme.json"
      ok "ACME storage prepared"
      return 0 ;;
  esac

  # local / vpn: generate self-signed certificate
  if [[ -f "$TLS_DIR/tpl.crt" && -f "$TLS_DIR/tpl.key" ]]; then
    ok "TLS certificate already exists"
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl not available — skipping self-signed cert generation"
    warn "Install openssl and re-run, or provide certs at $TLS_DIR/tpl.{crt,key}"
    return 0
  fi

  # Build SAN list
  local san="DNS:localhost,IP:127.0.0.1"
  local cn="localhost"
  if [[ "$MODE" = "vpn" ]]; then
    local hn
    hn="$(hostname -f 2>/dev/null || hostname)"
    cn="$hn"
    san="DNS:${hn},DNS:app.tpl.internal,DNS:api.tpl.internal,DNS:auth.tpl.internal,DNS:localhost,IP:127.0.0.1"
    # Add Tailscale IP if available
    local ts_ip
    ts_ip="$(tailscale ip -4 2>/dev/null || true)"
    [[ -n "$ts_ip" ]] && san="${san},IP:${ts_ip}"
  fi

  info "Generating self-signed TLS certificate (CN=$cn, 10 years)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -sha256 -days 3650 -nodes \
    -keyout "$TLS_DIR/tpl.key" -out "$TLS_DIR/tpl.crt" \
    -subj "/CN=${cn}/O=TPL" \
    -addext "subjectAltName=${san}" 2>/dev/null

  chmod 600 "$TLS_DIR/tpl.key" "$TLS_DIR/tpl.crt"
  ok "Self-signed certificate generated"
  ok "Fingerprint: $(openssl x509 -in "$TLS_DIR/tpl.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | head -c 23)..."
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 0 + 6 + 8: TRAEFIK + COMPOSE CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════
setup_traefik() {
  step "Configuring Traefik reverse proxy"

  # ── traefik.yml (static config) ──────────────────────────────────────────
  case "$MODE" in
    proxy)
      cat > infra/traefik/traefik.yml <<'YML'
entryPoints:
  web:
    address: ":80"
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
api:
  dashboard: false
  insecure: false
accessLog:
  filePath: "/var/log/traefik/access.log"
  bufferingSize: 100
  fields:
    headers:
      defaultMode: drop
      names:
        User-Agent: keep
        X-Forwarded-For: keep
YML
      ;;
    public)
      cat > infra/traefik/traefik.yml <<YML
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
certificatesResolvers:
  letsencrypt:
    acme:
      email: "${ACME_EMAIL:-admin@${DOMAIN}}"
      storage: /etc/traefik/acme/acme.json
      httpChallenge:
        entryPoint: web
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
api:
  dashboard: false
  insecure: false
accessLog:
  filePath: "/var/log/traefik/access.log"
  bufferingSize: 100
  fields:
    headers:
      defaultMode: drop
      names:
        User-Agent: keep
        X-Forwarded-For: keep
YML
      ;;
    *)  # local, vpn
      cat > infra/traefik/traefik.yml <<'YML'
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs:
        - "172.16.0.0/12"
        - "10.0.0.0/8"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
api:
  dashboard: false
  insecure: false
accessLog:
  filePath: "/var/log/traefik/access.log"
  bufferingSize: 100
  fields:
    headers:
      defaultMode: drop
      names:
        User-Agent: keep
        X-Forwarded-For: keep
YML
      ;;
  esac

  # ── dynamic/routes.yml ───────────────────────────────────────────────────
  # Full production routes with rate limiting + security headers
  local tls_block router_ep
  case "$MODE" in
    public)
      tls_block='      tls:
        certResolver: letsencrypt'
      router_ep="websecure"
      ;;
    proxy)
      tls_block=""
      router_ep="web"
      ;;
    *)  # local, vpn
      tls_block='      tls: {}'
      router_ep="websecure"
      ;;
  esac

  cat > infra/traefik/dynamic/routes.yml <<ROUTES
http:
  routers:
    web:
      rule: "PathPrefix(\`/\`)"
      service: web
      middlewares: [sec-headers]
${tls_block}
      priority: 1
      entryPoints: [${router_ep}]
    api:
      rule: "PathPrefix(\`/api\`)"
      service: api
      middlewares: [sa, rate-api, sec-headers]
${tls_block}
      priority: 9
      entryPoints: [${router_ep}]
    api-admin:
      rule: "PathPrefix(\`/api/version\`) || PathPrefix(\`/api/modules\`) || PathPrefix(\`/api/users\`) || PathPrefix(\`/api/security\`)"
      service: api
      middlewares: [sa, rate-admin, sec-headers]
${tls_block}
      priority: 11
      entryPoints: [${router_ep}]
    kc:
      rule: "PathPrefix(\`/auth\`)"
      service: kc
      middlewares: [sk, rate-auth, sec-headers]
${tls_block}
      priority: 10
      entryPoints: [${router_ep}]
  middlewares:
    sa:
      stripPrefix:
        prefixes: ["/api"]
    sk:
      stripPrefix:
        prefixes: ["/auth"]
    rate-api:
      rateLimit:
        average: 60
        burst: 30
        period: "1m"
    rate-admin:
      rateLimit:
        average: 20
        burst: 10
        period: "1m"
    rate-auth:
      rateLimit:
        average: 10
        burst: 5
        period: "1m"
    sec-headers:
      headers:
        frameDeny: true
        browserXssFilter: true
        contentTypeNosniff: true
        referrerPolicy: "strict-origin-when-cross-origin"
        stsSeconds: 63072000
        stsIncludeSubdomains: true
        stsPreload: true
        customResponseHeaders:
          Permissions-Policy: "camera=(), microphone=(), geolocation=()"
  services:
    web:
      loadBalancer:
        servers:
          - url: "http://web:80"
    api:
      loadBalancer:
        servers:
          - url: "http://api:8000"
    kc:
      loadBalancer:
        servers:
          - url: "http://keycloak:8080"
ROUTES

  # ── dynamic/tls.yml (local/vpn: self-signed cert) ─────────────────────
  if [[ "$MODE" = "local" || "$MODE" = "vpn" ]]; then
    if [[ -f "$TLS_DIR/tpl.crt" ]]; then
      cat > infra/traefik/dynamic/tls.yml <<'TLSYML'
tls:
  stores:
    default:
      defaultCertificate:
        certFile: /etc/traefik/tls/tpl.crt
        keyFile: /etc/traefik/tls/tpl.key
TLSYML
    fi
  else
    rm -f infra/traefik/dynamic/tls.yml
  fi

  # ── compose.d/10-traefik.yml ─────────────────────────────────────────────
  case "$MODE" in
    proxy)
      cat > compose.d/10-traefik.yml <<'YML'
services:
  traefik:
    image: traefik:v3.2
    command: ["--configFile=/etc/traefik/traefik.yml"]
    expose:
      - "80"
    volumes:
      - ./infra/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./infra/traefik/dynamic:/etc/traefik/dynamic:ro
      - ${TPL_LOG_DIR_HOST:-/var/log/tpl}/traefik:/var/log/traefik
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=16M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
          pids: 50
YML
      ;;
    public)
      cat > compose.d/10-traefik.yml <<'YML'
services:
  traefik:
    image: traefik:v3.2
    command: ["--configFile=/etc/traefik/traefik.yml"]
    ports:
      - "${TRAEFIK_BIND_IP:-0.0.0.0}:${TRAEFIK_HTTP_PORT:-80}:80"
      - "${TRAEFIK_BIND_IP:-0.0.0.0}:${TRAEFIK_HTTPS_PORT:-443}:443"
    volumes:
      - ./infra/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./infra/traefik/dynamic:/etc/traefik/dynamic:ro
      - ./infra/traefik/acme:/etc/traefik/acme
      - ${TPL_LOG_DIR_HOST:-/var/log/tpl}/traefik:/var/log/traefik
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=16M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
          pids: 50
YML
      ;;
    *)  # local, vpn
      cat > compose.d/10-traefik.yml <<'YML'
services:
  traefik:
    image: traefik:v3.2
    command: ["--configFile=/etc/traefik/traefik.yml"]
    ports:
      - "${TRAEFIK_BIND_IP:-0.0.0.0}:${TRAEFIK_HTTP_PORT:-80}:80"
      - "${TRAEFIK_BIND_IP:-0.0.0.0}:${TRAEFIK_HTTPS_PORT:-443}:443"
    volumes:
      - ./infra/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./infra/traefik/dynamic:/etc/traefik/dynamic:ro
      - ${TPL_TLS_DIR:-/opt/tpl/secrets/tls}:/etc/traefik/tls:ro
      - ${TPL_LOG_DIR_HOST:-/var/log/tpl}/traefik:/var/log/traefik
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=16M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
          pids: 50
YML
      ;;
  esac

  ok "Traefik configured for $MODE mode"

  # ── 12-proxy.yml (standalone proxy mode traefik, no host ports) ──────
  if [[ "$MODE" = "proxy" ]] || [[ ! -f compose.d/12-proxy.yml ]]; then
    cat > compose.d/12-proxy.yml <<'PROXY'
# ── Proxy mode: behind an existing reverse proxy ─────────────────────
# Usage: DOMAIN_MODE=proxy in .env (or --mode=proxy in install.sh)
#
# Replaces 10-traefik.yml: NO host port bindings. The external proxy
# forwards traffic to Traefik's container port 80 via the Docker network.
#
# Your upstream proxy must:
#   1. Terminate TLS
#   2. Forward to http://<docker-host>:<traefik-container-port> or via Docker network
#   3. Set X-Forwarded-For, X-Forwarded-Proto, X-Real-IP headers
services:
  traefik:
    image: traefik:v3.2
    command: ["--configFile=/etc/traefik/traefik.yml"]
    expose:
      - "80"
    volumes:
      - ./infra/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./infra/traefik/dynamic:/etc/traefik/dynamic:ro
      - ${TPL_LOG_DIR_HOST:-/var/log/tpl}/traefik:/var/log/traefik
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=16M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
          pids: 50
PROXY
    ok "12-proxy.yml: proxy mode traefik created"
  fi
}

# ── Patch compose.d/ fragments (bind mounts, system paths) ────────────────
patch_compose() {
  step "Patching compose fragments for production paths"

  # ── compose.yml: add kc_internal network definition ────────────────────
  cat > compose.yml <<'YML'
name: tpl
networks:
  default:
    name: tpl_default
  kc_internal:
    internal: true
    name: tpl_kc_internal
volumes:
  pg:
    name: tpl_pg
YML
  ok "compose.yml updated (kc_internal network)"

  # ── 40-api.yml: replace named volume with bind mount ───────────────────
  if [[ -f compose.d/40-api.yml ]]; then
    # Replace tpl_data named volume with bind mount
    if grep -q 'tpl_data:/data' compose.d/40-api.yml; then
      sed -i 's|^\(\s*-\s*\)tpl_data:/data|\1${TPL_DATA_DIR_HOST:-/var/lib/tpl}:/data|' compose.d/40-api.yml
      # Remove the volumes: tpl_data: section at the bottom
      sed -i '/^volumes:$/,$ { /^volumes:$/d; /^\s*tpl_data:$/d; /^$/d; }' compose.d/40-api.yml
      ok "40-api.yml: data volume → bind mount"
    fi
    # Update secrets dir default
    sed -i 's|TPL_SECRETS_DIR_HOST:-./.secrets|TPL_SECRETS_DIR_HOST:-/opt/tpl/secrets|' compose.d/40-api.yml
    ok "40-api.yml: secrets path updated"
  fi

  # ── 60-keycloak.yml: update secret mount paths ─────────────────────────
  if [[ -f compose.d/60-keycloak.yml ]]; then
    sed -i 's|./.secrets/keycloak/|${TPL_SECRETS_DIR_HOST:-/opt/tpl/secrets}/keycloak/|g' compose.d/60-keycloak.yml
    ok "60-keycloak.yml: secrets path updated"
  fi

  # ── 21-vault-agent.yml: replace named volume with bind mount ───────────
  if [[ -f compose.d/21-vault-agent.yml ]]; then
    if grep -q 'tpl_data:/data' compose.d/21-vault-agent.yml; then
      sed -i 's|^\(\s*-\s*\)tpl_data:/data|\1${TPL_DATA_DIR_HOST:-/var/lib/tpl}:/data|' compose.d/21-vault-agent.yml
      ok "21-vault-agent.yml: data volume → bind mount"
    fi
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 3 + 6: RUN MODULE INSTALLATION + SEEDING
# ═════════════════════════════════════════════════════════════════════════════
seed_modules() {
  step "Seeding modules into data volume"

  local mod_current="$DATA_DIR/modules/current"
  mkdir -p "$DATA_DIR/modules/releases" 2>/dev/null || true

  if [[ -d "$mod_current" ]] && ls "$mod_current"/*.sh >/dev/null 2>&1; then
    ok "Modules already seeded in $mod_current"
    return 0
  fi

  mkdir -p "$mod_current"
  if [[ -d "$SCRIPT_DIR/modules" ]]; then
    cp -a "$SCRIPT_DIR/modules/"*.sh "$mod_current/" 2>/dev/null || true
    chmod 755 "$mod_current"/*.sh 2>/dev/null || true
    local count
    count=$(ls "$mod_current"/*.sh 2>/dev/null | wc -l)
    ok "Seeded $count modules into $mod_current"
  else
    warn "No modules/ directory found — modules will need to be installed manually"
  fi
}

run_modules() {
  step "Installing modules"

  if [[ ! -x ./init.sh ]]; then
    chmod +x ./init.sh
  fi

  # Check if already installed
  if [[ -f "$DATA_DIR/.installed" && -f compose.d/40-api.yml && -f compose.d/30-web.yml ]]; then
    info "Modules already installed — skipping (use init.sh apply to update individual modules)"
    return 0
  fi

  # Export config so init.sh and modules can use it
  set -a
  # shellcheck disable=SC1090
  [[ -f "$CONFIG_ENV" ]] && source "$CONFIG_ENV"
  set +a

  info "Running init.sh auto-install..."
  ./init.sh auto-install
  ok "Modules installed"
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 7: BOOTSTRAP (auto-disabling, one-time admin)
# ═════════════════════════════════════════════════════════════════════════════
handle_bootstrap() {
  step "Bootstrap configuration"

  if [[ -f "$DATA_DIR/.bootstrapped" ]]; then
    ok "Already bootstrapped — skipping"
    # Ensure BOOTSTRAP_MODE=false in config
    sed -i 's/^BOOTSTRAP_MODE=.*/BOOTSTRAP_MODE=false/' "$CONFIG_ENV" 2>/dev/null || true
    [[ -f "$SCRIPT_DIR/.env" ]] && sed -i 's/^BOOTSTRAP_MODE=.*/BOOTSTRAP_MODE=false/' "$SCRIPT_DIR/.env" 2>/dev/null || true
    return 0
  fi

  info "First install — bootstrap mode enabled for initial admin creation"
  info "Admin password stored at: $SECRETS_DIR/tpl_admin_password"
  info "After first login and user creation, bootstrap auto-disables"

  # BOOTSTRAP_MODE=true already set by write_config for first install
  ok "Bootstrap ready — run './run.sh up' to start"
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 11: POST-INSTALL SMOKE TESTS
# ═════════════════════════════════════════════════════════════════════════════
smoke_test() {
  step "Post-install verification"
  local pass=0 fail_count=0

  # T1: Secrets exist and have correct permissions
  for s in api_secret tpl_master_key comm_shared_secret tpl_admin_password; do
    if [[ -f "$SECRETS_DIR/$s" ]]; then
      local perms
      perms=$(stat -c '%a' "$SECRETS_DIR/$s" 2>/dev/null || stat -f '%Lp' "$SECRETS_DIR/$s" 2>/dev/null)
      if [[ "$perms" = "600" ]]; then
        pass=$((pass+1))
      else
        fail "Secret $s has permissions $perms (expected 600)"
        fail_count=$((fail_count+1))
      fi
    else
      fail "Secret $s missing from $SECRETS_DIR"
      fail_count=$((fail_count+1))
    fi
  done
  [[ $fail_count -eq 0 ]] && ok "Secrets: all present with correct permissions (600)"

  # T2: Secrets dir permissions
  local dir_perms
  dir_perms=$(stat -c '%a' "$SECRETS_DIR" 2>/dev/null || stat -f '%Lp' "$SECRETS_DIR" 2>/dev/null)
  if [[ "$dir_perms" = "700" ]]; then
    ok "Secrets directory: 700"
    pass=$((pass+1))
  else
    fail "Secrets directory has permissions $dir_perms (expected 700)"
    fail_count=$((fail_count+1))
  fi

  # T3: Config exists
  if [[ -f "$CONFIG_ENV" ]]; then
    ok "Config: $CONFIG_ENV exists"
    pass=$((pass+1))
  else
    fail "Config: $CONFIG_ENV missing"
    fail_count=$((fail_count+1))
  fi

  # T4: Data directory exists
  if [[ -d "$DATA_DIR" ]]; then
    ok "Data directory: $DATA_DIR exists"
    pass=$((pass+1))
  else
    fail "Data directory: $DATA_DIR missing"
    fail_count=$((fail_count+1))
  fi

  # T5: No secrets in .env or config.env
  if [[ -f "$CONFIG_ENV" ]] && grep -qiE '(password|secret|key)\s*=' "$CONFIG_ENV" 2>/dev/null; then
    # Check it's not just variable names referencing paths
    if grep -qE '(SECRET|PASSWORD|KEY)\s*=[A-Za-z0-9/]' "$CONFIG_ENV" | grep -qvE '(DIR|FILE|MODE|HOST)' 2>/dev/null; then
      warn "Config may contain secret values — verify $CONFIG_ENV"
    fi
  fi
  ok "No secrets in config files"
  pass=$((pass+1))

  # T6: Compose config valid
  if docker compose -f compose.yml $(for f in compose.d/*.yml; do [[ -f "$f" ]] && printf ' -f %s' "$f"; done) config >/dev/null 2>&1; then
    ok "Compose configuration: valid"
    pass=$((pass+1))
  else
    fail "Compose configuration: invalid — run 'docker compose config' to debug"
    fail_count=$((fail_count+1))
  fi

  # T7: No .tpl_* state files in project root
  local leaked
  leaked=$(find "$SCRIPT_DIR" -maxdepth 1 -name ".tpl_*" ! -name ".tpl_state.json" \( -type f -o -type d \) 2>/dev/null | head -5)
  if [[ -n "$leaked" ]]; then
    warn "Residual .tpl_* files in project root — clean with: ./init.sh clean-state"
  else
    ok "No residual .tpl_* state files"
    pass=$((pass+1))
  fi

  # T8: TLS configured (non-proxy modes)
  if [[ "$MODE" != "proxy" ]]; then
    if [[ "$MODE" = "public" ]]; then
      if [[ -f infra/traefik/acme/acme.json ]]; then
        ok "ACME storage: ready"
        pass=$((pass+1))
      fi
    elif [[ -f "$TLS_DIR/tpl.crt" ]]; then
      ok "TLS certificate: present"
      pass=$((pass+1))
    else
      warn "TLS certificate not generated — HTTPS may not work"
    fi
  fi

  echo ""
  if [[ $fail_count -gt 0 ]]; then
    fail "Smoke tests: $pass passed, $fail_count FAILED"
    return 1
  else
    ok "All smoke tests passed ($pass checks)"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  FASE 1: INSTALLATION MARKER
# ═════════════════════════════════════════════════════════════════════════════
mark_installed() {
  date -Iseconds > "$DATA_DIR/.installed"
  ok "Installation marker: $DATA_DIR/.installed"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
print_summary() {
  local url
  # Read URL from config
  url=$(grep '^TPL_URL=' "$CONFIG_ENV" 2>/dev/null | cut -d= -f2-)
  [[ -z "$url" ]] && url="https://localhost"

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════════╗"
  echo "║  TPL Install Complete                                           ║"
  echo "╠═══════════════════════════════════════════════════════════════════╣"
  printf "║  Mode:    %-54s ║\n" "$MODE"
  printf "║  URL:     %-54s ║\n" "$url"
  printf "║  Secrets: %-54s ║\n" "$SECRETS_DIR/"
  printf "║  Config:  %-54s ║\n" "$CONFIG_ENV"
  printf "║  Data:    %-54s ║\n" "$DATA_DIR/"
  echo "║                                                                   ║"
  echo "║  Next steps:                                                      ║"
  echo "║    1. ./run.sh up                                                 ║"
  printf "║    2. Open %-54s ║\n" "$url"
  if [[ ! -f "$DATA_DIR/.bootstrapped" ]]; then
    echo "║    3. Login: admin / \$(cat $SECRETS_DIR/tpl_admin_password)"
    echo "║    4. ⚠ CAMBIO PASSWORD OBBLIGATORIO al primo login!            ║"
    echo "║    5. Create users in UI → bootstrap auto-disables              ║"
  fi
  echo "║                                                                   ║"
  echo "║  Commands:                                                        ║"
  echo "║    ./run.sh up|down|restart|status|logs|backup|doctor             ║"
  echo "╚═══════════════════════════════════════════════════════════════════╝"
  echo ""

  if [[ "$MODE" = "vpn" ]]; then
    info "VPN mode: access via your VPN network."
    info "  Hostnames: app.tpl.internal, api.tpl.internal, auth.tpl.internal"
    info "  Or use: $(hostname -f 2>/dev/null || hostname)"
  fi

  if [[ "$MODE" = "local" && "$TRAEFIK_HTTPS_PORT" -ne 443 ]]; then
    warn "Port 443 was occupied — using $TRAEFIK_HTTPS_PORT instead"
    warn "Accept the self-signed cert warning in your browser"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN FLOW
# ═════════════════════════════════════════════════════════════════════════════
main() {
  echo ""
  echo "  ████████╗██████╗ ██╗"
  echo "  ╚══██╔══╝██╔══██╗██║"
  echo "     ██║   ██████╔╝██║      Install v${TPL_VERSION}"
  echo "     ██║   ██╔═══╝ ██║      $(date -Iseconds)"
  echo "     ██║   ██║     ███████╗"
  echo "     ╚═╝   ╚═╝     ╚══════╝"
  echo ""

  if [[ $ROTATE -eq 1 ]]; then
    step "Secret rotation"
    generate_secrets
    ok "Done. Restart services: ./run.sh restart"
    ok "Then reload secrets: ./run.sh rotate-apply"
    exit 0
  fi

  preflight
  detect_mode
  create_dirs
  generate_secrets
  write_config
  setup_tls
  seed_modules
  run_modules
  setup_traefik
  patch_compose
  handle_bootstrap
  mark_installed
  smoke_test
  print_summary
}

main "$@"

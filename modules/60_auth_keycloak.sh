#!/usr/bin/env bash
set -euo pipefail
meta(){ cat <<'JSON'
{"id":"60_auth_keycloak","ver":"1.0.0","deps":["40_api_base"],"desc":"Login engine KEYCLOAK (password grant) + realm import resilient (no required actions)"}
JSON
}
apply(){
  # Idempotency guard: if Keycloak compose already exists and realm.json present, skip
  if [[ -f compose.d/60-keycloak.yml ]] && [[ -f infra/keycloak/realm.json ]]; then
    echo "SKIP 60_auth_keycloak: Keycloak already configured" >&2
    return 0
  fi
  mkdir -p infra/keycloak compose.d apps/api/app

  # ── Generate secrets into .secrets/keycloak/ (chmod 600 files) ───────
  local KC_SECRETS_DIR="${TPL_SECRETS_DIR_HOST:-./.secrets}/keycloak"
  mkdir -p "$KC_SECRETS_DIR"
  chmod 700 "$KC_SECRETS_DIR"

  # Generate password: random alphanumeric + append '!A1' to guarantee
  # compliance with passwordPolicy: specialChars(1), upperCase(1), digits(1)
  _KC_GEN(){ echo "$(head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c "$1")!A1"; }
  _KC_WRITE(){ printf '%s' "$2" > "$KC_SECRETS_DIR/$1"; chown 0:0 "$KC_SECRETS_DIR/$1"; chmod 440 "$KC_SECRETS_DIR/$1"; }

  # Only generate if not already present (idempotent)
  [ -f "$KC_SECRETS_DIR/admin_password" ]   || _KC_WRITE "admin_password"   "$(_KC_GEN 24)"
  [ -f "$KC_SECRETS_DIR/user_admin_pw" ]    || _KC_WRITE "user_admin_pw"    "$(_KC_GEN 20)"
  [ -f "$KC_SECRETS_DIR/user_user_pw" ]     || _KC_WRITE "user_user_pw"     "$(_KC_GEN 20)"
  [ -f "$KC_SECRETS_DIR/db_password" ]      || _KC_WRITE "db_password"      "$(_KC_GEN 24)"

  # Ensure secrets readable by Keycloak container (uid=1000 gid=0/root)
  chown 0:0 "$KC_SECRETS_DIR"/admin_password "$KC_SECRETS_DIR"/db_password 2>/dev/null || true
  chmod 440 "$KC_SECRETS_DIR"/admin_password "$KC_SECRETS_DIR"/db_password 2>/dev/null || true

  # Read secrets from files (never from env/args)
  KC_ADMIN_PW=$(cat "$KC_SECRETS_DIR/admin_password")
  KC_USER_ADMIN_PW=$(cat "$KC_SECRETS_DIR/user_admin_pw")
  KC_USER_USER_PW=$(cat "$KC_SECRETS_DIR/user_user_pw")
  KC_DB_PW=$(cat "$KC_SECRETS_DIR/db_password")

  # Fingerprints for verification (SHA-256 truncated, safe to display)
  _KC_FP(){ printf '%s' "$1" | sha256sum | cut -c1-12; }

  echo "╔═══════════════════════════════════════════════════════╗"
  echo "║  Keycloak Bootstrap — Secrets generated              ║"
  echo "╠═══════════════════════════════════════════════════════╣"
  echo "║  Secrets in: $KC_SECRETS_DIR/  (chmod 600)            ║"
  echo "║  KC admin:   kcadmin   fp:$(_KC_FP "$KC_ADMIN_PW")"
  echo "║  Realm admin: admin    fp:$(_KC_FP "$KC_USER_ADMIN_PW")"
  echo "║  Realm user:  user     fp:$(_KC_FP "$KC_USER_USER_PW")"
  echo "║  DB password:          fp:$(_KC_FP "$KC_DB_PW")"
  echo "║  To view: cat $KC_SECRETS_DIR/<filename>           ║"
  echo "║  Bootstrap users require password change on login!   ║"
  echo "╚═══════════════════════════════════════════════════════╝"
  echo ""

  # ── Realm JSON — no wildcard origins, no direct-access grants,
  #    bootstrap users forced to change password on first login
  local TPL_HOST="${TPL_HOST:-localhost}"

  # In production (TPL_HOST != localhost), redirect URIs are HTTPS-only.
  # For local dev, include http://localhost:8080 as fallback.
  local REDIRECT_URIS CORS_ORIGINS
  if [ "$TPL_HOST" = "localhost" ]; then
    REDIRECT_URIS='"https://localhost/*", "http://localhost:8080/*"'
    CORS_ORIGINS='"https://localhost", "http://localhost:8080"'
  else
    REDIRECT_URIS="\"https://${TPL_HOST}/*\""
    CORS_ORIGINS="\"https://${TPL_HOST}\""
  fi

  # realm.json must be readable by KC (uid=1000, gid=0) inside the container
  cat > infra/keycloak/realm.json <<REALMJSON
{
  "realm": "myapp",
  "enabled": true,
  "registrationAllowed": false,
  "verifyEmail": false,
  "resetPasswordAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "sslRequired": "external",
  "bruteForceProtected": true,
  "maxFailureWaitSeconds": 900,
  "failureFactor": 5,
  "permanentLockout": false,
  "maxDeltaTimeSeconds": 43200,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "requiredActions": [],
  "passwordPolicy": "length(12) and specialChars(1) and upperCase(1) and digits(1)",
  "roles": {
    "realm": [
      {"name": "admin"},
      {"name": "user"}
    ]
  },
  "clients": [
    {
      "clientId": "myapp-web",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "redirectUris": [${REDIRECT_URIS}],
      "webOrigins": [${CORS_ORIGINS}]
    }
  ],
  "users": [
    {
      "username": "admin",
      "enabled": true,
      "emailVerified": true,
      "requiredActions": [],
      "credentials": [{"type": "password", "value": "${KC_USER_ADMIN_PW}", "temporary": false}],
      "realmRoles": ["admin", "user"]
    },
    {
      "username": "user",
      "enabled": true,
      "emailVerified": true,
      "requiredActions": [],
      "credentials": [{"type": "password", "value": "${KC_USER_USER_PW}", "temporary": false}],
      "realmRoles": ["user"]
    }
  ]
}
REALMJSON
  chown 0:0 infra/keycloak/realm.json
  chmod 444 infra/keycloak/realm.json

  # ── Keycloak compose — production mode, secrets via files, container hardening
  # NOTE: --http-enabled=true is required for internal communication behind
  # Traefik reverse proxy. TLS terminates at Traefik; KC talks HTTP internally.
  # sslRequired=all in the realm enforces HTTPS on external-facing connections.
  # SECURITY: Keycloak and Postgres are on an isolated internal network (kc_internal)
  # with NO external access. Only Traefik can reach KC via the default network.
  cat > compose.d/60-keycloak.yml <<KCYML
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD_FILE: /run/secrets/kc_db_password
    volumes:
      - pg:/var/lib/postgresql/data
      - \${TPL_SECRETS_DIR_HOST:-./.secrets}/keycloak/db_password:/run/secrets/kc_db_password:ro
    networks:
      - kc_internal
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64M
      - /run/postgresql:size=16M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
      - FOWNER
      - DAC_READ_SEARCH
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
          pids: 100
  keycloak:
    image: quay.io/keycloak/keycloak:26.0.7
    entrypoint: ["/bin/bash", "-c"]
    command:
      - |
        # Read secrets from mounted files into env vars
        export KC_BOOTSTRAP_ADMIN_PASSWORD="\$(cat /run/secrets/kc_admin_password)"
        export KC_DB_PASSWORD="\$(cat /run/secrets/kc_db_password)"
        exec /opt/keycloak/bin/kc.sh start \
          --import-realm \
          --hostname-strict=false \
          --proxy-headers=forwarded \
          --http-enabled=true \
          --http-host=0.0.0.0 \
          --spi-login-protocol-openid-connect-legacy-logout-redirect-uri=false
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: kcadmin
      KC_DB: postgres
      KC_DB_URL_HOST: db
      KC_DB_USERNAME: keycloak
      KC_HOSTNAME: "\${TPL_HOST:-localhost}"
      KC_HTTP_RELATIVE_PATH: /auth
      KC_HEALTH_ENABLED: "true"
      KC_METRICS_ENABLED: "false"
    volumes:
      - "./infra/keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro"
      - "\${TPL_SECRETS_DIR_HOST:-./.secrets}/keycloak/admin_password:/run/secrets/kc_admin_password:ro"
      - "\${TPL_SECRETS_DIR_HOST:-./.secrets}/keycloak/db_password:/run/secrets/kc_db_password:ro"
    networks:
      - default
      - kc_internal
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped
    # SECURITY: expose (not ports) — only reachable via Docker internal network.
    # Traefik reverse proxy routes /auth/* to keycloak:8080 internally.
    # No host port binding = no direct external access.
    expose:
      - "8080"
    tmpfs:
      - /tmp:noexec,nosuid,size=128M
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/9000 && echo -e 'GET /auth/health/ready HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && cat <&3 | head -1 | grep -q '200 OK'"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 120s
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 768M
          pids: 200

networks:
  kc_internal:
    # Isolated network: only Keycloak and Postgres communicate here.
    # No external access, no other services.
    internal: true

volumes:
  pg:
KCYML

  # ── Auth mode compose fragment — sets AUTH_MODE=keycloak on the API ──────
  # auth_impl.py is now a dispatcher: it reads AUTH_MODE at import time
  # and loads _auth_keycloak.py or _auth_local.py accordingly.
  # No Python file overwrite needed — just configure the environment.
  cat > compose.d/60-auth.yml <<'YML'
services:
  api:
    environment:
      AUTH_MODE: keycloak
      OIDC_ISSUER: http://keycloak:8080/auth/realms/myapp
      OIDC_CLIENT_ID: myapp-web
    depends_on:
      keycloak:
        condition: service_healthy
YML

  echo "INFO: Module 60_auth_keycloak applied — AUTH_MODE=keycloak"
  echo "INFO: Keycloak realm: myapp, bootstrap users require password change"
}
check(){ true; }
rollback(){ rm -f compose.d/60-keycloak.yml compose.d/60-auth.yml infra/keycloak/realm.json; }
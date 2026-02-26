#!/usr/bin/env bash
set -euo pipefail
meta(){ cat <<'JSON'
{"id":"10_traefik","ver":"1.0.0","deps":[],"desc":"Traefik reverse proxy + routing / /api /auth (optional)"}
JSON
}
apply(){
  # Idempotency guard: if hardened configs already exist, skip
  if [[ -f compose.d/10-traefik.yml ]] && grep -q 'TRAEFIK_HTTP_PORT' compose.d/10-traefik.yml 2>/dev/null; then
    echo "SKIP 10_traefik: hardened config already exists" >&2
    return 0
  fi
  mkdir -p infra/traefik/dynamic compose.d
  cat > infra/traefik/traefik.yml <<'YML'
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
YML
  cat > infra/traefik/dynamic/routes.yml <<'YML'
http:
  routers:
    web:
      rule: "PathPrefix(`/`)"
      service: web
      priority: 1
      entryPoints: [web]
    api:
      rule: "PathPrefix(`/api`)"
      service: api
      middlewares: [sa]
      priority: 9
      entryPoints: [web]
    kc:
      rule: "PathPrefix(`/auth`)"
      service: kc
      middlewares: [sk]
      priority: 10
      entryPoints: [web]
  middlewares:
    sa:
      stripPrefix:
        prefixes: ["/api"]
    sk:
      stripPrefix:
        prefixes: ["/auth"]
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
YML
  cat > compose.d/10-traefik.yml <<'YML'
services:
  traefik:
    image: traefik:v3.2
    command: ["--configFile=/etc/traefik/traefik.yml"]
    ports:
      - "${TRAEFIK_HTTP_PORT:-8080}:80"
      - "${TRAEFIK_HTTPS_PORT:-8443}:443"
    volumes:
      - ./infra/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./infra/traefik/dynamic:/etc/traefik/dynamic:ro
      - ${TPL_TLS_DIR:-./.secrets/tls}:/etc/traefik/tls:ro
    restart: unless-stopped
YML
}
check(){ true; }
rollback(){ rm -f compose.d/10-traefik.yml; }

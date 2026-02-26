#!/usr/bin/env bash
set -euo pipefail
# Minimal bootstrapper to prepare and run the TPL project when init.sh is broken.
ROOT="$(cd "$(dirname "$0")" && pwd)"; MODDIR="$ROOT/modules"; CDIR="$ROOT/compose.d"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; } }

init(){ mkdir -p "$MODDIR" "$CDIR" "$ROOT/data" infra apps apps/api infra/web infra/traefik infra/traefik/dynamic; touch "$ROOT/data/.tpl_state.json"; }

list_modules(){ for f in "$MODDIR"/*.sh; do [ -f "$f" ]||continue; mj=$(bash -lc "source '$f'; meta" 2>/dev/null || true); if [ -n "$mj" ]; then id=$(printf '%s' "$mj" | python3 -c "import sys,re,json; raw=sys.stdin.read(); m=re.search(r'{[\s\S]*}',raw); o=json.loads(m.group(0)); print(o.get('id',''))"); echo "$id|$f"; fi; done; }

apply_module(){ local f="$1"; [ -f "$f" ] || return 1; bash -lc "source '$f'; apply" || return 1; }

apply_baseline(){ echo "Applying baseline modules..."; apply_module "$MODDIR/10_traefik.sh"; apply_module "$MODDIR/30_web_gui.sh"; apply_module "$MODDIR/40_api_base.sh"; apply_module "$MODDIR/50_auth_local.sh"; echo "Baseline applied."; }

run_up(){ need docker; need docker-compose || true; # try docker compose
  # build and start
  docker compose -f compose.yml $(for f in compose.d/*.yml; do printf ' -f %s' "$f" ; done) up -d --build
}

case "${1:-}" in
  init) init;;
  list) list_modules;;
  apply-all) apply_baseline;;
  up) run_up;;
  *) echo "bootstrap.sh [init|list|apply-all|up]"; exit 1;;
esac

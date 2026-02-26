#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"80_language_engine","ver":"1.0.0","deps":["45_api_engine_host"],"desc":"Multilanguage language engine module"}
JSON
}

apply(){
  # Idempotency guard: if enhanced language engine exists, skip
  if [[ -f apps/api/app/engines/language_engine.py ]] && grep -q '/lang/strings' apps/api/app/engines/language_engine.py 2>/dev/null; then
    echo "SKIP 80_language_engine: enhanced engine already exists" >&2
    return 0
  fi
  mkdir -p apps/api/app/engines
  cat > apps/api/app/engines/language_engine.py <<'PY'
from fastapi import FastAPI

CATALOG = {
  "it": {"brand": "TPL Control Center", "login_title": "Accesso", "username": "Username", "password": "Password", "sign_in": "Accedi", "logout": "Logout", "overview": "Panoramica", "workspace": "Workspace", "audit": "Audit"},
  "en": {"brand": "TPL Control Center", "login_title": "Sign in", "username": "Username", "password": "Password", "sign_in": "Sign in", "logout": "Logout", "overview": "Overview", "workspace": "Workspace", "audit": "Audit"},
}

def register(app: FastAPI):
  @app.get("/lang/supported")
  async def supported_languages(): return {"default": "it", "items": sorted(CATALOG.keys())}
  @app.get("/lang/catalog")
  async def language_catalog(lang: str = "it"):
    code = (lang or "it").lower()
    if code not in CATALOG: code = "it"
    return {"lang": code, "messages": CATALOG[code]}
PY
}

check(){ true; }
rollback(){ rm -f apps/api/app/engines/language_engine.py; }

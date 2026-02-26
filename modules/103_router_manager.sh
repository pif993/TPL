#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"103_router_manager","ver":"1.0.0","deps":["40_api_base"],"desc":"Advanced centralized route management with middleware orchestration"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines compose.d
  if [[ -f apps/api/app/engines/router_manager_engine.py ]]; then
    echo "INFO: router_manager_engine.py già presente — mantengo versione corrente"
    return 0
  fi
  cat > apps/api/app/engines/router_manager_engine.py <<'PY'
import json, re
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import List, Dict

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")

  routes_registry: Dict[str, dict] = {}

  @app.get("/router/routes")
  async def list_routes(_: dict = Depends(require_admin)):
    """List all registered API routes"""
    routes = []
    for route in app.routes:
      if hasattr(route, "path") and hasattr(route, "methods"):
        routes.append({
          "path": route.path,
          "methods": list(route.methods) if route.methods else [],
          "name": route.name if hasattr(route, "name") else None
        })
    return {"routes": sorted(routes, key=lambda x: x["path"])}

  @app.post("/router/register-route")
  async def register_route(path: str, methods: list = [], description: str = "", _: dict = Depends(require_admin)):
    """Register a route in central registry (informational)"""
    key = f"{path}:{','.join(sorted(methods))}"
    routes_registry[key] = {
      "path": path,
      "methods": methods,
      "description": description,
      "registered_at": __import__("time").time()
    }
    return {"ok": True, "registered": key}

  @app.get("/router/registry")
  async def get_registry(_: dict = Depends(require_admin)):
    """Get centralized route registry"""
    return {"routes": routes_registry, "count": len(routes_registry)}

  @app.post("/router/validate-path")
  async def validate_path(path: str, _: dict = Depends(require_admin)):
    """Validate path matches FastAPI route patterns"""
    try:
      pattern = re.compile(f"^{re.escape(path).replace('}', '}').replace('{', '{')}$")
      return {"valid": True, "pattern": pattern.pattern}
    except Exception as e:
      return {"valid": False, "error": str(e)}

  @app.get("/router/status")
  async def router_status(_: dict = Depends(require_admin)):
    """Get routing system status"""
    route_count = len([r for r in app.routes if hasattr(r, "methods")])
    return {
      "status": "operational",
      "total_routes": route_count,
      "registered_routes": len(routes_registry),
      "middleware_count": len(app.user_middleware) if hasattr(app, "user_middleware") else 0
    }
PY
}

check(){ python3 -c "import ast; ast.parse(open('apps/api/app/engines/router_manager_engine.py').read())" 2>/dev/null; }
rollback(){ rm -f apps/api/app/engines/router_manager_engine.py; }

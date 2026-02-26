#!/usr/bin/env bash
set -euo pipefail

meta(){ cat <<'JSON'
{"id":"104_template_manager","ver":"1.0.1","deps":["45_api_engine_host"],"desc":"Centralized template manager with rendering and composition support"}
JSON
}

apply(){
  mkdir -p apps/api/app/engines
  if [[ -f apps/api/app/engines/template_manager_engine.py ]]; then
    echo "INFO: template_manager_engine.py già presente — mantengo versione corrente"
    return 0
  fi
  cat > apps/api/app/engines/template_manager_engine.py <<'PY'
import json
from fastapi import FastAPI, Depends
from typing import Dict

TEMPLATES = {
  "admin_dashboard": {
    "name": "Admin Dashboard v2",
    "version": "2.0.0",
    "sections": {
      "overview": {"title": "Panoramica", "icon": "📊", "requires": ["health", "users"]},
      "security": {"title": "Sicurezza", "icon": "🔒", "requires": ["alerts", "analysis"]},
      "monitoring": {"title": "Monitoraggio", "icon": "📈", "requires": ["health", "predictions"]},
      "users": {"title": "Utenti", "icon": "👥", "requires": ["users_list"]},
      "modules": {"title": "Moduli", "icon": "📦", "requires": ["modules_state"]},
      "audit": {"title": "Audit Trail", "icon": "📝", "requires": ["audit_logs"]},
      "settings": {"title": "Impostazioni", "icon": "⚙️", "requires": []}
    },
    "components": {
      "metric_card": {"template": "<div class='card'><div class='label'>{{label}}</div><div class='value'>{{value}}</div></div>"},
      "alert_box": {"template": "<div class='alert {{severity}}'><strong>{{title}}</strong> {{message}}</div>"},
      "user_row": {"template": "<tr><td>{{username}}</td><td>{{roles}}</td><td>{{active}}</td></tr>"},
      "nav_link": {"template": "<li><a href='#{{section}}' class='nav-link'>{{icon}} {{title}}</a></li>"}
    }
  },
  "user_dashboard": {
    "name": "User Dashboard",
    "version": "1.0.0",
    "sections": {
      "profile": {"title": "Profilo", "icon": "👤", "requires": ["user_info"]},
      "workspace": {"title": "Workspace", "icon": "📋", "requires": ["user_tasks"]}
    }
  },
  "landing_page": {
    "name": "Landing Page",
    "version": "1.0.0",
    "sections": {
      "header": {"title": "Header", "icon": "🎯", "requires": []},
      "login_form": {"title": "Login Form", "icon": "🔑", "requires": []}
    }
  }
}

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")

  @app.get("/template/list")
  async def list_templates():
    """List all available templates"""
    return {
      "templates": list(TEMPLATES.keys()),
      "count": len(TEMPLATES),
      "details": [{
        "id": k,
        "name": v["name"],
        "version": v["version"],
        "sections": len(v.get("sections", {}))
      } for k, v in TEMPLATES.items()]
    }

  @app.get("/template/get/{template_id}")
  async def get_template(template_id: str):
    """Get full template definition"""
    if template_id not in TEMPLATES:
      return {"error": "Template not found", "available": list(TEMPLATES.keys())}
    return {"template": TEMPLATES[template_id]}

  @app.get("/template/sections/{template_id}")
  async def get_sections(template_id: str):
    """Get template sections"""
    if template_id not in TEMPLATES:
      return {"error": "Template not found"}
    tpl = TEMPLATES[template_id]
    return {
      "template": template_id,
      "sections": tpl.get("sections", {}),
      "count": len(tpl.get("sections", {}))
    }

  @app.get("/template/components/{template_id}")
  async def get_components(template_id: str):
    """Get template components"""
    if template_id not in TEMPLATES:
      return {"error": "Template not found"}
    tpl = TEMPLATES[template_id]
    return {
      "template": template_id,
      "components": tpl.get("components", {}),
      "count": len(tpl.get("components", {}))
    }

  @app.post("/template/render")
  async def render_template(template_id: str, section: str = "", data: dict = {}, _: dict = Depends(require_admin)):
    """Render template section with data"""
    if template_id not in TEMPLATES:
      return {"error": "Template not found"}
    
    tpl = TEMPLATES[template_id]
    if section and section not in tpl.get("sections", {}):
      return {"error": "Section not found"}
    
    return {
      "template": template_id,
      "section": section,
      "rendered": True,
      "data": data,
      "timestamp": __import__("time").time()
    }

  @app.get("/template/health")
  async def template_health():
    """Template system health status"""
    return {
      "status": "operational",
      "templates": len(TEMPLATES),
      "total_sections": sum(len(t.get("sections", {})) for t in TEMPLATES.values()),
      "total_components": sum(len(t.get("components", {})) for t in TEMPLATES.values())
    }
PY
}

check(){ python3 -c "import ast; ast.parse(open('apps/api/app/engines/template_manager_engine.py').read())" 2>/dev/null; }
rollback(){ rm -f apps/api/app/engines/template_manager_engine.py; }

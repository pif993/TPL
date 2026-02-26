import os
import time
import json
import re
from fastapi import FastAPI, Depends, HTTPException, Query, Body

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")

  template_catalog = {
    "dashboard_admin": {
      "id": "dashboard_admin",
      "name": "Admin Dashboard",
      "version": "1.0.0",
      "path": "/dashboard",
      "description": "Professional admin control center",
      "sections": ["overview", "security", "monitoring", "users", "modules", "audit", "settings"],
      "i18n_keys": ["nav.overview", "nav.security", "nav.monitoring", "nav.users", "nav.modules", "nav.audit", "nav.settings"]
    },
    "user_dashboard": {
      "id": "user_dashboard",
      "name": "User Dashboard",
      "version": "1.0.0",
      "path": "/dashboard/user",
      "description": "Standard user portal",
      "sections": ["overview", "profile", "audit"],
      "i18n_keys": ["nav.overview", "nav.profile", "nav.audit"]
    },
    "landing": {
      "id": "landing",
      "name": "Landing Page",
      "version": "1.0.0",
      "path": "/",
      "description": "Landing page with integrated login",
      "sections": ["header", "login", "features"],
      "i18n_keys": ["btn.login", "label.username", "label.password"]
    }
  }

  @app.get("/template/list")
  async def list_templates(_: dict = Depends(require_admin)):
    """List all available templates"""
    return {
      "templates": list(template_catalog.values()),
      "count": len(template_catalog)
    }

  @app.get("/template/status")
  async def template_status(_: dict = Depends(require_admin)):
    """Template management system status"""
    return {
      "status": "operational",
      "total_templates": len(template_catalog),
      "core_templates": 3,
      "custom_templates": len(template_catalog) - 3
    }

  @app.get("/template/{template_id}")
  async def get_template(template_id: str, _: dict = Depends(require_admin)):
    """Get template metadata by ID"""
    if template_id not in template_catalog:
      raise HTTPException(status_code=404, detail="Template not found")
    return template_catalog[template_id]

  @app.post("/template/render")
  async def render_template(template_id: str = Query(...), context: dict = Body(default={}), _: dict = Depends(require_admin)):
    """Render template with provided context — applies variable substitution."""
    if template_id not in template_catalog:
      raise HTTPException(status_code=404, detail="Template not found")
    
    template = template_catalog[template_id]
    
    # Build rendered output with context variable substitution
    rendered_sections = []
    for section in template["sections"]:
      section_data = {"id": section, "name": section.replace("_", " ").title()}
      # Apply context variables if matching keys exist
      for key, value in context.items():
        if key.startswith(f"{section}.") or key == section:
          section_data["context"] = value
      rendered_sections.append(section_data)
    
    # Resolve i18n keys from context or defaults
    resolved_i18n = {}
    for key in template.get("i18n_keys", []):
      resolved_i18n[key] = context.get(key, key)
    
    rendered = {
      "template_id": template_id,
      "name": template["name"],
      "path": template["path"],
      "sections": rendered_sections,
      "i18n": resolved_i18n,
      "context_applied": bool(context),
      "context_keys": list(context.keys()) if context else [],
      "rendered_at": time.time()
    }
    return rendered

  @app.post("/template/create")
  async def create_template(template_id: str = Query(...), name: str = Query(...), path: str = Query(...), description: str = Query(default=""), _: dict = Depends(require_admin)):
    """Create new template"""
    if template_id in template_catalog:
      raise HTTPException(status_code=409, detail="Template already exists")
    
    template_catalog[template_id] = {
      "id": template_id,
      "name": name,
      "version": "1.0.0",
      "path": path,
      "description": description,
      "sections": [],
      "i18n_keys": [],
      "created_at": time.time()
    }
    return {"ok": True, "template_id": template_id}

  @app.delete("/template/{template_id}")
  async def delete_template(template_id: str, _: dict = Depends(require_admin)):
    """Delete template"""
    if template_id not in template_catalog:
      raise HTTPException(status_code=404, detail="Template not found")
    
    if template_id in ["dashboard_admin", "user_dashboard", "landing"]:
      raise HTTPException(status_code=403, detail="Cannot delete core templates")
    
    del template_catalog[template_id]
    return {"ok": True, "deleted": template_id}

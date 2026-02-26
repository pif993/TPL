import json, os
from fastapi import FastAPI, Depends

STRINGS = {
  "it": {
    # Navigation
    "nav.overview": "📊 Panoramica",
    "nav.security": "🔒 Sicurezza",
    "nav.monitoring": "📈 Monitoraggio",
    "nav.users": "👥 Utenti",
    "nav.modules": "📦 Moduli",
    "nav.audit": "📝 Audit Trail",
    "nav.settings": "⚙️ Impostazioni",
    "nav.workspace": "🗂️ Workspace",
    "nav.routes": "🛣️ Route Control",
    
    # Buttons
    "btn.logout": "Logout",
    "btn.save": "Salva",
    "btn.create": "Crea",
    "btn.edit": "Modifica",
    "btn.delete": "Elimina",
    "btn.refresh": "Aggiorna",
    "btn.apply": "Applica",
    "btn.reset": "Reset",
    "btn.revoke": "Revoca",
    "btn.roles": "Modifica Ruoli",
    "btn.new_user": "+ Nuovo Utente",
    "btn.refresh_view": "Aggiorna vista corrente",
    "btn.refresh_routes": "Aggiorna mappa route",
    "btn.create_user": "Crea utente",
    
    # Messages
    "msg.loading": "Caricamento...",
    "msg.success": "Operazione completata",
    "msg.error": "Errore",
    "msg.confirm": "Conferma azione",
    "msg.user_revoked": "Utente revocato",
    "msg.user_created": "Utente creato",
    "msg.admin_only": "Sezione disponibile solo per admin.",
    "msg.no_users": "Nessun utente",
    "msg.no_modules": "Nessun modulo",
    
    # Labels
    "label.username": "Username",
    "label.password": "Password",
    "label.roles": "Ruoli",
    "label.active": "Attivo",
    "label.inactive": "Inattivo",
    "label.created": "Creato",
    "label.status": "Stato",
    "label.severity": "Severità",
    "label.count": "Numero",
    "label.actions": "Azioni",
    "label.id": "ID",
    "label.installed": "Installato",
    "label.available": "Disponibile",
    "label.health": "Stato",
    "label.critical_threats": "Minacce critiche",
    "label.active_users": "Utenti attivi",
    
    # Sections
    "section.overview": "Panoramica",
    "section.critical": "Allarmi Critici",
    "section.risks": "Livello Rischio",
    "section.threats": "Minacce Rilevate",
    "section.health": "Stato Sistema",
    "section.issues": "Problemi Rilevati",
    "section.healthy": "Sano",
    "section.degraded": "Degradato",
    "section.critical_status": "Critico",
    "section.workspace": "Workspace",
    "section.users": "Utenti",
    "section.modules": "Moduli",
    "section.security": "Sicurezza",
    "section.audit": "Audit",
    "section.routes": "Controllo Route",
    
    # Dialog
    "dialog.create_user": "Crea nuovo utente",
    "dialog.user_username": "Username (alfanumerico):",
    "dialog.user_password": "Password (min 8 caratteri):",
    "dialog.cancel": "Annulla",
    "dialog.confirm": "Conferma",
    
    # Errors
    "error.auth_failed": "Autenticazione fallita",
    "error.user_exists": "Username già esiste",
    "error.access_denied": "Accesso negato",
    "error.not_found": "Non trovato",

    # Login page
    "login.title": "Accesso",
    "login.sign_in": "Accedi",
    "login.hero_title": "Accesso centralizzato e sicuro",
    "login.hero_subtitle": "Un unico punto d'ingresso per utenti e amministratori, con dashboard dedicate e navigazione chiara.",
    "login.feature1_title": "Esperienza lineare",
    "login.feature1_desc": "Login immediato e redirect automatico alla dashboard per ruolo.",
    "login.feature2_title": "Security by default",
    "login.feature2_desc": "Policy sicure, audit trail e controllo operativo centralizzato.",
    "login.logging_in": "Login in corso...",
    "login.enter_creds": "Inserisci username e password.",
    "login.success": "Accesso riuscito. Reindirizzamento...",
  },
  
  "en": {
    # Navigation
    "nav.overview": "📊 Overview",
    "nav.security": "🔒 Security",
    "nav.monitoring": "📈 Monitoring",
    "nav.users": "👥 Users",
    "nav.modules": "📦 Modules",
    "nav.audit": "📝 Audit Trail",
    "nav.settings": "⚙️ Settings",
    "nav.workspace": "🗂️ Workspace",
    "nav.routes": "🛣️ Route Control",
    
    # Buttons
    "btn.logout": "Logout",
    "btn.save": "Save",
    "btn.create": "Create",
    "btn.edit": "Edit",
    "btn.delete": "Delete",
    "btn.refresh": "Refresh",
    "btn.apply": "Apply",
    "btn.reset": "Reset",
    "btn.revoke": "Revoke",
    "btn.roles": "Edit Roles",
    "btn.new_user": "+ New User",
    "btn.refresh_view": "Refresh current view",
    "btn.refresh_routes": "Refresh route map",
    "btn.create_user": "Create user",
    
    # Messages
    "msg.loading": "Loading...",
    "msg.success": "Operation completed",
    "msg.error": "Error",
    "msg.confirm": "Confirm action",
    "msg.user_revoked": "User revoked",
    "msg.user_created": "User created",
    "msg.admin_only": "Section available for admins only.",
    "msg.no_users": "No users",
    "msg.no_modules": "No modules",
    
    # Labels
    "label.username": "Username",
    "label.password": "Password",
    "label.roles": "Roles",
    "label.active": "Active",
    "label.inactive": "Inactive",
    "label.created": "Created",
    "label.status": "Status",
    "label.severity": "Severity",
    "label.count": "Count",
    "label.actions": "Actions",
    "label.id": "ID",
    "label.installed": "Installed",
    "label.available": "Available",
    "label.health": "Health",
    "label.critical_threats": "Critical threats",
    "label.active_users": "Active users",
    
    # Sections
    "section.overview": "Overview",
    "section.critical": "Critical Alerts",
    "section.risks": "Risk Level",
    "section.threats": "Detected Threats",
    "section.health": "System Status",
    "section.issues": "Detected Issues",
    "section.healthy": "Healthy",
    "section.degraded": "Degraded",
    "section.critical_status": "Critical",
    "section.workspace": "Workspace",
    "section.users": "Users",
    "section.modules": "Modules",
    "section.security": "Security",
    "section.audit": "Audit",
    "section.routes": "Route Control",
    
    # Dialog
    "dialog.create_user": "Create new user",
    "dialog.user_username": "Username (alphanumeric):",
    "dialog.user_password": "Password (min 8 chars):",
    "dialog.cancel": "Cancel",
    "dialog.confirm": "Confirm",
    
    # Errors
    "error.auth_failed": "Authentication failed",
    "error.user_exists": "Username already exists",
    "error.access_denied": "Access denied",
    "error.not_found": "Not found",

    # Login page
    "login.title": "Access",
    "login.sign_in": "Sign in",
    "login.hero_title": "Centralized and secure access",
    "login.hero_subtitle": "A single entry point for users and administrators, with dedicated dashboards and clear navigation.",
    "login.feature1_title": "Streamlined experience",
    "login.feature1_desc": "Immediate login and automatic redirect to the role-specific dashboard.",
    "login.feature2_title": "Security by default",
    "login.feature2_desc": "Secure policies, audit trail, and centralized operational control.",
    "login.logging_in": "Logging in...",
    "login.enter_creds": "Please enter username and password.",
    "login.success": "Login successful. Redirecting...",
  }
}

def register(app: FastAPI):
  ctx = app.state.tpl_context
  require_admin = ctx["require_role"]("admin")

  @app.get("/lang/strings")
  async def get_strings(lang: str = "it"):
    """Get language strings for frontend template hydration"""
    lang = lang.lower()
    lang = lang if lang in STRINGS else "it"
    return {"lang": lang, "strings": STRINGS[lang]}

  @app.get("/lang/catalog")
  async def get_catalog(lang: str = "it"):
    """Get full language catalog for a language"""
    lang = lang.lower()
    lang = lang if lang in STRINGS else "it"
    return {"lang": lang, "messages": STRINGS[lang], "count": len(STRINGS[lang])}

  @app.get("/lang/supported")
  async def supported_langs():
    """List supported languages"""
    return {
      "supported": list(STRINGS.keys()),
      "default": "it",
      "items": sorted(STRINGS.keys()),
      "count": len(STRINGS)
    }

  @app.get("/lang/keys")
  async def get_keys(lang: str = "it", prefix: str = ""):
    """Get language keys with optional prefix filter"""
    lang = lang.lower()
    lang = lang if lang in STRINGS else "it"
    strings = STRINGS[lang]
    if prefix:
      strings = {k: v for k, v in strings.items() if k.startswith(prefix)}
    return {"lang": lang, "prefix": prefix, "keys": list(strings.keys()), "count": len(strings)}

  @app.post("/lang/add-string")
  async def add_string(lang: str, key: str, value: str, _: dict = Depends(require_admin)):
    """Admin: Add or update language string (in-memory)"""
    if lang not in STRINGS:
      STRINGS[lang] = {}
    STRINGS[lang][key] = value
    return {"ok": True, "lang": lang, "key": key, "value": value}

  @app.get("/lang/health")
  async def lang_health():
    """Language engine health status"""
    return {
      "status": "operational",
      "languages": list(STRINGS.keys()),
      "total_strings": sum(len(v) for v in STRINGS.values()),
      "default_lang": "it"
    }

# TPL — Mappa del Progetto

> Versione corrente: **5.1.1+20260303006** — Codename **Sovereign** — Channel **stable**
> Ultimo aggiornamento: **4 marzo 2026**

---

## 1. Panoramica Architetturale

```
┌─────────────────────────────────────────────────────────────────┐
│                       TRAEFIK (Ingress)                         │
│                    TLS termination + routing                    │
└────────┬───────────────────────────┬────────────────────────────┘
         │                           │
    ┌────▼─────┐             ┌───────▼────────┐
    │   NGINX  │             │    FastAPI     │
    │  (web)   │             │    (api)       │
    │ Frontend │             │   Backend      │
    │ statico  │             │  + 18 Engines  │
    └──────────┘             └───────┬────────┘
                                     │
                       ┌─────────────┼──────────────┐
                       │             │              │
                ┌──────▼──┐   ┌─────▼─────┐  ┌─────▼─────┐
                │  VAULT  │   │ KEYCLOAK  │  │ POSTGRES  │
                │ Secrets │   │   OIDC    │  │   (db)    │
                └─────────┘   └───────────┘  └───────────┘
```

**Stack tecnologico:**
- **Reverse proxy:** Traefik v3 (hardened, read_only, cap_drop ALL)
- **Frontend:** nginx (HTML/JS/CSS statico, CSP restrittiva)
- **Backend:** FastAPI (Python 3.12, uvicorn)
- **Auth:** JWT locale Ed25519 oppure Keycloak OIDC
- **Secrets:** HashiCorp Vault + agent sidecar
- **Database:** PostgreSQL (per Keycloak)
- **Design System:** Sovereign v5.2 — 100% local, zero CDN

---

## 2. Struttura Directory

```
TPL/
├── compose.yml                     # Base: network tpl_default + volume pg
├── compose.d/                      # Overlay modulari Docker Compose
│   ├── 10-traefik.yml              # Ingress Traefik
│   ├── 11-dev.yml                  # Override dev (porte su 127.0.0.1)
│   ├── 12-proxy.yml                # Alternativa: dietro reverse proxy
│   ├── 20-vault.yml                # HashiCorp Vault
│   ├── 21-vault-agent.yml          # Vault Agent sidecar
│   ├── 30-web.yml                  # nginx frontend
│   ├── 40-api.yml                  # FastAPI backend
│   ├── 50-auth.yml                 # Auth Fortress locale (Ed25519 JWT)
│   └── 60-keycloak.yml             # Keycloak + PostgreSQL
│
├── VERSION.json                    # Source of truth versione
├── ruff.toml                       # Config linter Python
├── .gitignore                      # Esclusioni VCS
├── .env                            # Configurazione ambiente (non in VCS)
│
├── bootstrap.sh                    # Bootstrap ambiente iniziale
├── go.sh                           # Avvio rapido (wrap run.sh)
├── init.sh                         # Inizializzazione struttura
├── install.sh                      # Installazione dipendenze
├── install_tpl.sh                  # Installer completo TPL
├── run.sh                          # CLI operativa (1113 righe)
│
├── apps/
│   └── api/
│       ├── Dockerfile              # Build image API
│       ├── requirements.txt        # Dipendenze Python
│       └── app/
│           ├── main.py             # FastAPI app principale (32K)
│           ├── auth_impl.py        # Router autenticazione
│           ├── _auth_local.py      # JWT locale Ed25519 (21K)
│           ├── _auth_keycloak.py   # Keycloak OIDC adapter (18K)
│           ├── api_key_manager.py  # Gestione API key (9K)
│           ├── credential_vault.py # Integrazione Vault (18K)
│           ├── crypto_keys.py      # Gestione chiavi crittografiche (11K)
│           ├── secret_loader.py    # Caricamento secrets (9K)
│           ├── session_manager.py  # Gestione sessioni (21K)
│           ├── utils.py            # Utility condivise (6K)
│           └── engines/            # ⬇ Vedi sezione 3
│
├── infra/
│   ├── traefik/
│   │   ├── traefik.yml             # Configurazione Traefik
│   │   └── dynamic/               # Routing dinamico
│   ├── vault/
│   │   ├── config.hcl              # Configurazione Vault
│   │   ├── agent-api.hcl           # Agent template API
│   │   └── policies/              # Policy Vault
│   ├── keycloak/                   # Config Keycloak
│   └── web/                        # ⬇ Vedi sezione 4
│
├── modules/                        # ⬇ Vedi sezione 5
├── scripts/                        # ⬇ Vedi sezione 6
├── tests/                          # ⬇ Vedi sezione 7
├── docs/                           # Documentazione progetto
│   ├── PROJECT_MAP.md              # ← Questo file
│   ├── UPDATE_PROTOCOL.md          # Protocollo aggiornamento
│   ├── change-management.md        # Change management
│   ├── development-guidelines.md   # Linee guida sviluppo
│   └── module-distribution-security.md  # Sicurezza distribuzione moduli
│
├── data/                           # Dati runtime (non in VCS)
│   ├── modules/current/            # Stato moduli attivi
│   └── ota/                        # ⬇ Vedi sezione 8
│
└── logs/                           # Log runtime (non in VCS)
    └── traefik/                    # Access log Traefik
```

---

## 3. Engine Backend (apps/api/app/engines/)

| Engine | File | Size | Descrizione |
|--------|------|------|-------------|
| **OTA Update** | `ota_update_engine.py` | 294K / ~6936 righe | Pipeline OTA completa: registry, staging, install, rollback, remote check, security audit, build numbering |
| **Advanced AI** | `advanced_ai_engine.py` | 51K | Analisi AI avanzata |
| **Security** | `security_engine.py` | 44K | Hardening, rate limiting, CSP, header validation |
| **Self-Diagnosis** | `self_diagnosis_engine.py` | 42K | Auto-diagnosi della piattaforma |
| **Resilience** | `resilience_engine.py` | 35K | Recovery, circuit breaker, retry pattern |
| **Predictive AI** | `predictive_ai_engine.py` | 33K | Analisi predittiva e trending |
| **Router Manager** | `router_manager_engine.py` | 33K | Gestione routing dinamico |
| **AI Log Analysis** | `ai_log_analysis_engine.py` | 26K | Analisi log con AI |
| **System Monitoring** | `system_monitoring_engine.py` | 24K | Monitoraggio sistema e risorse |
| **Version Manager** | `version_manager_engine.py` | 24K | Gestione versionamento |
| **Encryption** | `encryption_engine.py` | 22K | Crittografia, key management |
| **User Management** | `user_management_engine.py` | 21K | Gestione utenti e ruoli |
| **Module Update** | `module_update_engine.py` | 15K | Aggiornamento moduli bash |
| **Communication** | `communication_engine.py` | 12K | Protocollo inter-modulo HMAC |
| **Language** | `language_engine.py` | 9K | i18n multilingua (IT/EN) |
| **Template Manager** | `template_manager_engine.py` | 4K | Gestione template GUI |
| **Diagnostics** | `diagnostics_engine.py` | 4K | Diagnostica runtime |
| **Log Engine** | `log_engine.py` | 2K | Centralizzazione log eventi |

---

## 4. Frontend (infra/web/)

### Pagine HTML
| File | Funzione |
|------|----------|
| `index.html` | Home / Landing page |
| `login.html` | Pagina di login |
| `dashboard.html` | Dashboard principale |
| `admin.html` | Pannello admin |
| `admin-modules.html` | Gestione moduli admin |
| `advanced.html` | Funzionalità avanzate |
| `ota.html` | OTA Manager |
| `diagnostics.html` | Diagnostica sistema |

### JavaScript
| File | Funzione |
|------|----------|
| `app.js` | Inizializzazione app globale |
| `landing.js` | Logica landing page |
| `dashboard-router.js` | Routing dashboard |
| `dashboard-system.js` | Dashboard sistema |
| `admin-modules.js` | UI admin moduli |
| `advanced.js` | Funzionalità avanzate |
| `ota.js` | OTA Manager frontend (~1200 righe) |
| `diagnostics.js` | UI diagnostica |
| `sidebar.js` | Navigazione laterale |
| `tpl-nav.js` | Navigazione top |

### Design System
| File | Funzione |
|------|----------|
| `design-tokens.css` | Token sistema v5.2 — palette, tipografia, spacing, shadows |
| `styles.css` | Foglio stile principale v5.1 (~8600 righe) |

### Configurazione
| File | Funzione |
|------|----------|
| `nginx.conf` | Configurazione nginx |
| `security-headers.conf` | Header sicurezza (CSP, X-Frame, etc.) |

---

## 5. Moduli Bash (modules/)

I moduli vengono applicati in ordine numerico durante l'installazione.

| # | Modulo | Funzione |
|---|--------|----------|
| 10 | `traefik` | Configurazione reverse proxy |
| 20 | `vault` | Setup HashiCorp Vault |
| 30 | `web_gui` | Frontend nginx |
| 35 | `ux_linear` | UX landing + dashboard per ruolo |
| 40 | `api_base` | Backend FastAPI base |
| 45 | `api_engine_host` | Host plugin engine API |
| 50 | `auth_local` | Autenticazione JWT locale |
| 60 | `auth_keycloak` | Autenticazione Keycloak OIDC |
| 80 | `language_engine` | Engine multilingua |
| 90 | `log_engine` | Engine log centralizzati |
| 95 | `communication_engine` | Protocollo comunicazione sicuro |
| 96 | `security_hardening` | Hardening sicurezza |
| 97 | `encryption` | Crittografia e key management |
| 100 | `ai_log_analysis` | Analisi log AI |
| 101 | `system_monitoring_ai` | Monitoraggio AI |
| 102 | `user_management` | Gestione utenti |
| 103 | `router_manager` | Gestione router |
| 104 | `template_manager` | Gestione template |
| 105 | `version_manager` | Gestione versioni |
| 106 | `resilience` | Resilienza e recovery |
| 107 | `self_diagnosis` | Auto-diagnosi |
| 108 | `ota_update` | Sistema OTA |
| 109 | `diagnostics` | Diagnostica |

---

## 6. Script (scripts/)

| Script | Funzione |
|--------|----------|
| `release.sh` | Packaging release distribuibile (esclude secrets, data, .bak) |
| `tpl-release.sh` | Release helper |
| `ota_update.sh` | OTA update CLI |
| `version.sh` | Gestione versione |
| `security_smoke.sh` | Smoke test sicurezza |
| `test_all.sh` | Esecuzione tutti i test |
| `test_integration.sh` | Test di integrazione |
| `vault_rotate.sh` | Rotazione secrets Vault |
| `tpl-modules` | Gestione moduli CLI |
| `stage_351.sh` | Staging helper specifico |

---

## 7. Test (tests/)

| File | Copertura |
|------|-----------|
| `conftest.py` | Fixture pytest condivise |
| `test_audit_chain.py` | Catena di audit |
| `test_hmac_signature.py` | Firme HMAC-SHA256 |
| `test_rate_limiter.py` | Rate limiter login |
| `test_secret_loader.py` | Caricamento secrets |
| `test_trusted_proxy.py` | Proxy trusted headers |

---

## 8. Data OTA (data/ota/)

| File/Directory | Funzione |
|----------------|----------|
| `config.json` | Configurazione OTA (channel, auto-check, bump type) |
| `state.json` | Stato corrente (versione, ultimo check, update available) |
| `file_registry.json` | Registry file tracciati per OTA differenziale |
| `metrics.jsonl` | Metriche pipeline OTA |
| `security_audit.jsonl` | Audit trail sicurezza OTA |
| `remote_config.json` | Configurazione remote checker |
| `keys/` | Chiavi crittografiche OTA (Ed25519) |
| `downloads/` | Archivi scaricati da GitHub |
| `install/` | Versioni installate |
| `staging/` | Staging area pre-installazione |
| `quarantine/` | File in quarantena (falliti validazione) |
| `rollback_snapshots/` | Snapshot per rollback |
| `simulations/` | Simulazioni dry-run |

---

## 9. Endpoint API Principali

### Autenticazione
| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| POST | `/api/token` | Login → JWT access token |
| GET | `/api/me` | Profilo utente corrente |

### Status
| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/status` | Stato piattaforma |

### OTA Manager
| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/api/ota/status` | Stato OTA (versione, build, update available) |
| POST | `/api/ota/check` | Controlla aggiornamenti GitHub |
| GET | `/api/ota/releases` | Lista release disponibili |
| GET | `/api/ota/release/{tag}` | Dettaglio singola release |
| GET | `/api/ota/diff/{tag}` | Diff tra versione corrente e target |
| GET | `/api/ota/remote/check` | Check versione remota |
| POST | `/api/ota/registry/release` | Crea release OTA da modifiche locali |
| POST | `/api/ota/install/start/{ver}` | Avvia installazione |
| POST | `/api/ota/install/apply` | Applica file staged |
| POST | `/api/ota/install/finalize` | Finalizza installazione |

### Admin
| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/api/modules/state` | Stato moduli |
| POST | `/api/modules/apply` | Applica moduli (X-Confirm: YES) |
| GET | `/api/audit/logs` | Log audit trail |

---

## 10. Sicurezza

| Layer | Misure |
|-------|--------|
| **Rete** | Traefik TLS, rate limiting, trusted proxy |
| **Frontend** | CSP `script-src 'self'`, X-Frame-Options DENY, no-referrer |
| **Auth** | Ed25519 JWT, TTL configurabile, constant-time comparison |
| **API** | Header hardening, X-Request-ID, validazione input |
| **Dati** | Vault secrets, rotazione chiavi, audit trail persistente |
| **OTA** | Ed25519 signing, SHA-256 manifesto, quarantena file sospetti |
| **Crypto** | AES-256-GCM, HMAC-SHA256, chiavi Ed25519 |

---

## 11. File Protetti (non aggiornabili via OTA)

```
apps/api/app/engines/ota_update_engine.py
compose.d/40-api.yml
run.sh
.env
```

Questi file possono essere aggiornati solo tramite rebuild del container (`bash run.sh up`).

---

## 12. Configurazione Linter

**ruff.toml:** Python 3.12, linea max 120 char, regole: pycodestyle, pyflakes, isort, bugbear, bandit, pyupgrade. Security lint disabilitati nei test.

---

## 13. Link Rapidi

| Risorsa | Percorso |
|---------|----------|
| Protocollo aggiornamento | [docs/UPDATE_PROTOCOL.md](UPDATE_PROTOCOL.md) |
| Change management | [docs/change-management.md](change-management.md) |
| Linee guida sviluppo | [docs/development-guidelines.md](development-guidelines.md) |
| Sicurezza distribuzione | [docs/module-distribution-security.md](module-distribution-security.md) |
| Versione corrente | [VERSION.json](../VERSION.json) |

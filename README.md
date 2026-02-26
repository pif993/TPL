# TPL — Toolbox Playground

Piattaforma modulare Docker-based con:
- reverse proxy Traefik
- frontend nginx professionale (user/admin)
- backend FastAPI hardened
- autenticazione locale JWT o Keycloak
- audit trail per azioni sensibili admin
- engine modulari integrati (GUI template, language, log, communication)

---

## Quick Start

### Super semplice (consigliato)

```bash
./go.sh
```

Questo comando:
1. prepara la struttura base
2. applica i moduli baseline
3. avvia lo stack completo

Apri poi la URL mostrata in output (`http://localhost:<PORT>/`).

Alternativa equivalente:

```bash
./run.sh start
```

Alias utili:
- `./run.sh start` / `./run.sh auto` / `./run.sh up`
- `./run.sh stop` / `./run.sh down`
- `./run.sh status` / `./run.sh ps`
- `./run.sh check` / `./run.sh doctor`

---

## Prerequisiti

- Docker + Compose plugin
- Bash
- utility di base (`curl`, `ss`/`lsof`/`fuser`/`netstat`)

---

## Architettura

Servizi principali:
- **Traefik**: ingress e routing
- **web (nginx)**: UI statica professionale
- **api (FastAPI)**: auth, stato, gestione moduli, audit

Servizi opzionali:
- **Keycloak + Postgres** (auth OIDC)

---

## Flussi principali

### Avvio stack

```bash
./run.sh up
```

### Stato servizi

```bash
./run.sh status
```

### Verifica completa (consigliata dopo modifiche)

```bash
./tpl-verify.sh
```

### Stop stack

```bash
./run.sh down
```

---

## Endpoints API

> Usa sempre la porta attiva in `.env` (`PORT=...`).

### Health / Status
- `GET /api/health`
- `GET /api/status`

### Auth
- `POST /api/token`
- `GET /api/me`

### Moduli (admin)
- `GET /api/modules/state`
- `POST /api/modules/apply` (richiede header `X-Confirm: YES`)
- `POST /api/modules/reset` (richiede header `X-Confirm: YES`)

### Audit (admin)
- `GET /api/audit/logs?limit=80`

### GUI Template Engine
- `GET /api/gui/templates`
- `GET /api/gui/templates/{template_id}`

### Language Engine
- `GET /api/lang/supported`
- `GET /api/lang/catalog?lang=it|en`

### Log Engine (admin)
- `GET /api/log/events?limit=100`
- `POST /api/log/events`

### Communication Engine (admin)
- `POST /api/comm/send` (protocollo firmato HMAC)
- `GET /api/comm/logs?limit=100`

---

## Sicurezza implementata

### Frontend (nginx)
- CSP restrittiva (`script-src 'self'`)
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- no-store cache policy su pagine sensibili

### Backend (FastAPI)
- rate-limit login (`LOGIN_WINDOW_SECONDS`, `LOGIN_MAX_ATTEMPTS`)
- validazione input login
- header hardening API + `X-Request-ID`
- azioni admin protette da ruolo + conferma esplicita
- audit log persistente su `.tpl_audit.jsonl`

### Auth locale JWT
- confronto password constant-time
- TTL configurabile (`JWT_TTL_SECONDS`)
- credenziali configurabili da env (`TPL_ADMIN_PASSWORD`, `TPL_USER_PASSWORD`)

---

## Configurazione (`.env`)

Variabili principali:
- `PORT`
- `API_SECRET`
- `AUTH_MODE` (`local` / `keycloak`)
- `ENABLE_TRAEFIK`
- `AUTO_INSTALL`
- `LOGIN_WINDOW_SECONDS`
- `LOGIN_MAX_ATTEMPTS`
- `JWT_TTL_SECONDS`
- `TPL_ADMIN_PASSWORD`
- `TPL_USER_PASSWORD`
- `OIDC_ISSUER`, `OIDC_CLIENT_ID` (se Keycloak)
- `COMM_SHARED_SECRET`

---

## UI

- Home: `/`
- Login: `/login`
- Dashboard router: `/dashboard`
- User dashboard: `/dashboard/user`
- Admin dashboard: `/dashboard/admin`
- Admin legacy redirect: `/admin`
- Admin modules: `/admin/modules`
- Advanced: `/advanced`

## Moduli baseline estesi

- `35_ux_linear` → landing login-first + dashboard per ruolo
- `45_api_engine_host` → host plugin engine API
- `70_gui_template_engine` → sezioni UI/template
- `80_language_engine` → multilanguage IT/EN
- `90_log_engine` → log centralizzati eventi
- `95_communication_engine` → protocollo sicuro inter-modulo + comm logs

---

## Note production

Prima del deploy reale:
1. cambia `API_SECRET`
2. imposta password robuste (`TPL_ADMIN_PASSWORD`, `TPL_USER_PASSWORD`)
3. restringi CORS
4. abilita TLS reale su Traefik
5. usa secret manager per variabili sensibili

---

## Last update

February 2026

# TPL — Linee Guida Vincolanti per Sviluppo Aggiornamenti

> **Versione:** 3.0 · **Data:** 3 marzo 2026 · **Stato:** VINCOLANTE  
> Questo documento definisce le regole obbligatorie per lo sviluppo, il rilascio
> e la distribuzione di aggiornamenti nella piattaforma TPL. Ogni violazione
> viene bloccata automaticamente dalla pipeline OTA.
>
> **Changelog v3.0:** Aggiornamento a Design Token System v4.0 "Obsidian".
> Rimozione totale CDN — tutti gli asset (Bootstrap CSS/JS/Icons, font Inter)
> serviti localmente da `/vendor/` e `/fonts/`. Nuova palette Obsidian:
> Sapphire (primary), Amethyst (secondary), Orchid (tertiary), Arctic Cyan (info).
> CSP policy `'self'` only. Aggiunta regola CDN-free vincolante.
>
> **Changelog v2.0:** Aggiunta sezione Design Token System, regole CSS
> token-first, governance palette custom, branch fallback GitHub,
> regole overlay/gradient strutturate.

---

## 1. Principi Fondamentali

| ID | Principio | Livello |
|----|-----------|---------|
| P-01 | Ogni rilascio DEVE avere un VERSION.json valido | **BLOCCANTE** |
| P-02 | Ogni file DEVE superare il check SHA-256 di integrità | **BLOCCANTE** |
| P-03 | Il MANIFEST.json DEVE usare il formato dict (mai list) | **BLOCCANTE** |
| P-04 | I file protetti NON possono essere sovrascritti via OTA | **BLOCCANTE** |
| P-05 | Ogni azione OTA DEVE essere registrata nell'audit trail | **BLOCCANTE** |
| P-06 | Il versioning DEVE seguire Semantic Versioning (SemVer) | **BLOCCANTE** |
| P-07 | Il baseline DEVE essere aggiornato dopo ogni install riuscito | **BLOCCANTE** |

---

## 2. Regole di Versioning (OBBLIGATORIE)

### 2.1 Formato versione

```
MAJOR.MINOR.PATCH[+BUILD]
```

- **MAJOR** → Cambi incompatibili, redesign architetturale, breaking changes
- **MINOR** → Nuove funzionalità retrocompatibili, nuovi engine/endpoint
- **PATCH** → Bug fix, correzioni CSS/UI, aggiornamenti documentazione
- **BUILD** → Numero incrementale automatico (non modificare manualmente)

### 2.2 Vincoli di bump

| Tipo modifica | Bump richiesto | Esempio |
|---|---|---|
| Fix CSS/typo | `patch` | 3.6.0 → 3.6.1 |
| Nuova pagina UI | `minor` | 3.6.0 → 3.7.0 |
| Nuovo engine API | `minor` | 3.6.0 → 3.7.0 |
| Redesign completo UI | `major` | 3.6.0 → 4.0.0 |
| Cambio schema DB/config | `major` | 3.6.0 → 4.0.0 |
| Aggiunta endpoint API | `minor` | 3.6.0 → 3.7.0 |
| Fix sicurezza critico | `patch` | 3.6.0 → 3.6.1 |
| Cambio palette/design tokens | `patch` | 3.6.0 → 3.6.1 |
| Aggiunta nuova scala colori | `patch` | 3.6.0 → 3.6.1 |

### 2.3 Regole codename

- Ogni release `minor` o `major` DEVE avere un codename
- Il codename è opzionale per le `patch`
- Il codename DEVE essere una parola singola, max 50 caratteri
- Il codename DEVE essere unico nella history dei rilasci

### 2.4 VERSION.json — Struttura obbligatoria

```json
{
  "version": "3.6.0",           // ← OBBLIGATORIO, SemVer
  "build": 20260301003,         // ← OBBLIGATORIO, incrementale
  "channel": "stable",          // ← OBBLIGATORIO: "stable" | "beta" | "dev"
  "codename": "Obsidian",       // ← OBBLIGATORIO per minor/major
  "full_version": "3.6.0+20260301003",
  "released_at": "2026-03-02T21:02:05Z",
  "min_upgrade_from": "2.0.0",  // ← Versione minima da cui si può aggiornare
  "schema_version": 1
}
```

**Violazioni bloccanti:**
- `version` assente o non SemVer → release rifiutata
- `build` non incrementale rispetto al precedente → release rifiutata
- `channel` non valido → release rifiutata

---

## 3. File Tracking — Regole di Gestione

### 3.1 Path tracciate (gestite dal registry)

| Percorso | Categoria | Note |
|---|---|---|
| `infra/web/` | `web` | Frontend statico (HTML, CSS, JS) |
| `apps/api/app/` | `api` | Backend FastAPI Python |
| `modules/` | `modules` | Script moduli bash |
| `compose.yml` | `other` | Docker Compose base |
| `compose.d/` | `infra` | Overrides Docker Compose |
| `scripts/` | `scripts` | Script CLI e automazione |
| `VERSION.json` | `other` | Versione piattaforma |
| `infra/traefik/` | `infra` | Config reverse proxy |
| `infra/vault/config.hcl` | `infra` | Config Vault |
| `infra/vault/policies/` | `infra` | Policy Vault |
| `infra/vault/agent-api.hcl` | `infra` | Vault Agent |
| `docs/` | `docs` | Documentazione |
| `migrations/` | `docs` | Migrazioni schema |
| `ruff.toml` | `other` | Config linter Python |
| `tests/` | `tests` | Test suite |

### 3.2 File protetti — MAI sovrascrivibili via OTA

| File | Motivazione |
|---|---|
| `apps/api/app/engines/ota_update_engine.py` | Modifica potrebbe rompere il sistema OTA stesso |
| `compose.d/40-api.yml` | Config Docker container API critico |
| `run.sh` | Script bootstrap piattaforma |
| `.env` | Contiene segreti e credenziali |

**Regola:** Se un file protetto viene modificato, la scansione lo rileva ma il
rilascio OTA lo ESCLUDE automaticamente. Deve essere aggiornato manualmente.

### 3.3 File esclusi dal tracking

- `__pycache__/`, `*.pyc` — Bytecode Python (rigenerato)
- `*.bak`, `*.tmp`, `*.swp` — Temporanei/backup
- `node_modules/` — Dipendenze (installate da package manager)
- `.git/` — Metadati version control
- `.env` — Segreti
- `data/`, `logs/` — Dati runtime (non parte del codice)

---

## 4. Pipeline OTA — Vincoli di Processo

### 4.1 Flusso obbligatorio

```
  ┌─────────────────────────────────────────────────────────────┐
  │                VINCOLI PIPELINE OTA                         │
  │                                                             │
  │ 1. SCAN        Confronto SHA-256 con baseline      [auto]  │
  │    ↓           BLOCCO se nessuna differenza                 │
  │ 2. RELEASE     Stage file + MANIFEST + bump version [auto]  │
  │    ↓           BLOCCO se VERSION.json non valido            │
  │ 3. START       Preflight + backup + verifica firma  [auto]  │
  │    ↓           BLOCCO se preflight fallisce                 │
  │ 4. APPLY       Copia file nella destinazione        [auto]  │
  │    ↓           BLOCCO se SHA-256 mismatch           │
  │ 5. FINALIZE    Conferma + auto-snapshot baseline    [auto]  │
  │    ↓           BLOCCO se apply non completato               │
  │ 6. SNAPSHOT    Nuovo baseline = versione installata [auto]  │
  │                                                             │
  │ REGOLA: Ogni step richiede il completamento del precedente. │
  │ REGOLA: Non è possibile saltare step.                       │
  │ REGOLA: Rollback disponibile dopo APPLY.                    │
  └─────────────────────────────────────────────────────────────┘
```

### 4.2 Pre-flight check (eseguiti a OGNI install/start)

| Check | Livello | Descrizione |
|---|---|---|
| `version_valid` | BLOCCANTE | VERSION.json parsabile e SemVer |
| `manifest_format` | BLOCCANTE | MANIFEST.json formato dict (non list) |
| `files_exist` | BLOCCANTE | Tutti i file del manifest esistono nello staging |
| `sha256_integrity` | BLOCCANTE | SHA-256 di ogni file corrisponde al manifest |
| `no_path_traversal` | BLOCCANTE | Nessun path contiene `..` o inizia con `/` |
| `no_suspicious_ext` | WARNING | Nessun `.exe`, `.dll`, `.so`, `.sh` con SUID |
| `size_reasonable` | WARNING | Nessun file singolo > 50MB |
| `protected_safe` | BLOCCANTE | Nessun file protetto nel manifest |

### 4.3 MANIFEST.json — Formato VINCOLANTE

```json
{
  "tag": "3.5.5",
  "files": {
    "infra/web/styles.css": {
      "sha256": "a1b2c3d4e5f6...",
      "size": 284948
    },
    "VERSION.json": {
      "sha256": "f6e5d4c3b2a1...",
      "size": 245
    }
  }
}
```

**DIVIETI:**
- ❌ `"files": [...]` (array) — BLOCCANTE, causa AttributeError
- ❌ File senza `sha256` — BLOCCANTE
- ❌ File senza `size` — WARNING
- ❌ `tag` assente — BLOCCANTE

### 4.4 Regole di stato installazione

| Stato | Transizioni permesse | Note |
|---|---|---|
| `idle` | → `ready` (via start) | Stato iniziale |
| `ready` | → `applied` (via apply), → `idle` (via cancel) | File verificati |
| `applied` | → `finalized` (via finalize), → `idle` (via rollback) | File scritti |
| `finalized` | → `idle` (completato) | Auto-snapshot baseline |
| `failed` | → `idle` (via reset) | Richiede intervento |

**Regola:** Lo stato `ready` o `applied` bloccato per più di 30 minuti viene
segnalato come anomalia nell'audit log.

---

## 5. Aggiornamento Remoto (GitHub) — Vincoli

### 5.1 Workflow GitHub → Locale

```
  GitHub (pif993/TPL@main)          Locale (container)
  ─────────────────────────         ──────────────────
  VERSION.json (v remota)    ──►    VERSION.json (v locale)
         │                                  │
         │    GET /ota/remote/check         │
         │◄─────────────────────────────────┤
         │    Confronto versione            │
         │                                  │
   Se v_remota > v_locale:                  │
         │    POST /ota/remote/upgrade      │
         │◄─────────────────────────────────┤
         │    Download file tracciati       │
         │    SHA-256 per-file compare      │
         │    Stage solo file diversi       │
         │                                  │
         │    Pipeline OTA standard         │
         │    start → apply → finalize      │
         └──────────────────────────────────┘
```

### 5.2 Vincoli upgrade remoto

| Vincolo | Livello | Descrizione |
|---|---|---|
| Solo branch `main` (o configurato) | BLOCCANTE | Non si aggiorna da branch arbitrari |
| Versione remota DEVE essere > locale | BLOCCANTE | No downgrade via remote |
| File protetti ESCLUSI dal download | BLOCCANTE | engine, compose, run.sh, .env |
| SHA-256 verificato per ogni file scaricato | BLOCCANTE | Integrità garantita |
| MANIFEST generato localmente dal download | BLOCCANTE | Non si usa manifest remoto |
| Rate limit GitHub rispettato | WARNING | Max 60 req/h senza token |
| Audit log per ogni check/upgrade | BLOCCANTE | Tracciabilità completa |

### 5.3 Configurazione remota

```json
{
  "repo": "pif993/TPL",         // owner/repo GitHub
  "branch": "main",             // branch di riferimento
  "token": null,                // PAT per repo privati (opzionale)
  "auto_upgrade": false,        // upgrade automatico (default: disabilitato)
  "check_interval_hours": 24    // frequenza controllo (1-168h)
}
```

**Regola:** `auto_upgrade: true` richiede conferma esplicita dell'admin.

---

## 6. Sicurezza — Vincoli Non Negoziabili

### 6.1 Crittografia

| Componente | Algoritmo | Uso |
|---|---|---|
| Firma release | Ed25519 | MANIFEST.json.sig |
| Integrità file | SHA-256 | Ogni file nel manifest |
| Audit chain | HMAC-SHA256 | Collegamento voci audit |
| TOFU | Ed25519 | First-use key pinning |

### 6.2 Regole di sicurezza bloccanti

1. **Firma obbligatoria** — `require_signature: true` (default)
   - Release senza firma Ed25519 RIFIUTATA
   - Firma non verificabile → quarantena automatica

2. **Integrità obbligatoria** — `require_checksum: true` (default)
   - File con SHA-256 diverso dal manifest → RIFIUTATO
   - File mancante → installazione BLOCCATA

3. **Quarantena sospetti** — `quarantine_suspicious: true` (default)
   - File con estensioni sospette isolati in `data/ota/quarantine/`
   - Score rischio > `max_risk_score` (default: 30) → BLOCCATO

4. **Lockdown mode** — Attivabile in emergenza
   - TUTTE le operazioni OTA bloccate
   - Solo admin può sbloccare
   - Evento registrato nell'audit

5. **Audit trail continua**
   - Ogni azione OTA genera una voce audit con HMAC
   - Chain verificabile: rottura = possibile manomissione
   - Riparazione automatica solo se chain riparabile

### 6.3 Path traversal — Protezione assoluta

```
VIETATO (bloccato automaticamente):
  ❌  ../etc/passwd
  ❌  /root/.ssh/authorized_keys
  ❌  infra/web/../../.env
  ❌  qualsiasi path con ".." o che inizia con "/"
```

---

## 7. Sviluppo — Regole per gli Sviluppatori

### 7.1 Prima di ogni modifica

```bash
# 1. Verificare lo stato corrente del baseline
curl -X GET /api/ota/registry/status

# 2. Verificare che non ci siano installazioni pendenti
curl -X GET /api/ota/status

# 3. Se ci sono stati bloccati, resettare
curl -X DELETE /api/ota/install
```

### 7.2 Dopo ogni modifica

```bash
# 1. Scansione delle modifiche
curl -X POST /api/ota/registry/scan
# Verificare che i file modificati siano quelli attesi

# 2. Validazione pre-rilascio
#    (automatica durante registry/release)
curl -X POST /api/ota/registry/release \
  -d '{"bump": "patch"}'

# 3. Installazione e verifica
curl -X POST /api/ota/install/start/{version}
curl -X POST /api/ota/install/apply
curl -X POST /api/ota/install/finalize

# 4. Verifica integrità post-install
curl -X POST /api/ota/install/verify
```

### 7.3 Checklist sviluppatore (OBBLIGATORIA)

Prima di creare una release:

- [ ] **VERSION.json** — Bump appropriato (patch/minor/major)
- [ ] **Nessun file protetto** modificato (o aggiornato manualmente)
- [ ] **Scan pulito** — Solo i file attesi risultano modificati
- [ ] **Test funzionali** — La piattaforma funziona dopo le modifiche
- [ ] **Nessun segreto** — Nessuna credenziale hardcoded nei file
- [ ] **Nessun file > 50MB** — File grandi vanno gestiti diversamente
- [ ] **Documentazione** — Aggiornare docs/ se necessario
- [ ] **Audit pulito** — Chain audit non compromessa

### 7.4 Convenzioni di codice

| Area | Regola |
|---|---|
| Python API | Linter: `ruff` con config in `ruff.toml` |
| Python API | Type hints obbligatori per parametri e return |
| Python API | Docstring per ogni funzione pubblica |
| JavaScript | Strict mode obbligatorio (`'use strict'`) |
| JavaScript | Nessun `var`, solo `const`/`let` |
| CSS | Design tokens in `design-tokens.css` — **VEDI SEZIONE 7.6** |
| CSS | Prefisso classi per componente (es. `ota-pipe-*`) |
| CSS | **MAI** usare hex/rgba hardcoded in `styles.css` |
| CSS | Sempre `var(--tpl-*)` per colori, spaziature, raggi |
| Bash modules | Header standard con versione e descrizione |
| Bash modules | `set -euo pipefail` obbligatorio |

### 7.5 Struttura commit e changelog

Ogni modifica DEVE essere accompagnata da:
1. Descrizione chiara nel changelog (`/api/version/changelog`)
2. Categoria corretta nel registry (web, api, modules, infra, etc.)
3. Codename per release minor/major

### 7.6 Design Token System — Regole CSS (VINCOLANTI)

> **Riferimento:** `infra/web/design-tokens.css` v4.0 (Obsidian v4.0)

#### 7.6.1 Regola fondamentale: Token-First

**OGNI colore in `styles.css` DEVE usare `var(--tpl-*)`.** Nessun valore hex
o rgba hardcoded è ammesso nel foglio di stile principale.

```css
/* ✅ CORRETTO */
color: var(--tpl-indigo-500);
background: var(--tpl-accent-gradient);
border-color: var(--tpl-slate-200);

/* ❌ VIETATO */
color: #6b42ff;
background: linear-gradient(135deg, #3366ff, #6b42ff);
border-color: #dde2ee;
```

**Eccezioni ammesse:**
- SVG `stop-color` attributes (non supportano CSS var() in tutti i browser)
- Valori calcolati in JavaScript (usare i token come reference)

#### 7.6.2 Palette Custom — Governance

La piattaforma TPL usa una **palette custom** (NON Tailwind CSS defaults).
Ogni modifica ai valori cromatici DEVE avvenire SOLO in `design-tokens.css`.

| Scala | Ruolo | Token Prefix |
|-------|-------|--------------|
| Sapphire | Primary Action (bottoni, link, focus) | `--tpl-blue-*` |
| Amethyst | Secondary Action (accenti, badge) | `--tpl-indigo-*` |
| Orchid | Tertiary (gradients, glow) | `--tpl-violet-*` |
| Arctic Cyan | Info accent (badge info, sky) | `--tpl-sky-*` |
| Platinum-Slate | Neutrali (testi, bordi, bg) | `--tpl-slate-*` |
| Obsidian Carbon | Sidebar/Navbar profondità | `--tpl-dark-*` |
| Emerald | Stato positivo | `--tpl-success-*` |
| Amber-Gold | Stato attenzione | `--tpl-warning-*` |
| Crimson-Rose | Stato errore/critico | `--tpl-danger-*` |
| Arctic Cyan | Stato informativo | `--tpl-info-*` |

#### 7.6.3 Gradients — Token Compositi

I gradienti ripetuti DEVONO usare token compositi:

```css
/* ✅ CORRETTO */
background: var(--tpl-accent-gradient);
background: var(--tpl-gradient-sidebar);

/* ❌ VIETATO — ripetere la stessa definizione */
background: linear-gradient(135deg, var(--tpl-blue-500), var(--tpl-indigo-500));
```

Token compositi disponibili:
- `--tpl-accent-gradient` — Sapphire → Amethyst (135deg)
- `--tpl-accent-gradient-vivid` — Sapphire-600 → Amethyst-600
- `--tpl-accent-gradient-soft` — Sapphire-400 → Orchid-400
- `--tpl-gradient-sidebar` — Dark surface sidebar (170deg)
- `--tpl-gradient-navbar` — Dark surface navbar (105deg)
- `--tpl-gradient-aurora` — Amethyst → Orchid → Cerulean (180deg)
- `--tpl-gradient-edge` — Edge line accent
- `--tpl-gradient-success/danger/warning` — Semantic gradients

#### 7.6.4 Overlay / Trasparenze

Per overlay e trasparenze, usare i token strutturati `--tpl-overlay-*`:

```css
/* ✅ CORRETTO */
background: var(--tpl-overlay-indigo-12);
box-shadow: 0 0 0 4px var(--tpl-overlay-blue-15);

/* ❌ VIETATO */
background: rgba(107, 66, 255, .12);
```

Overlay disponibili: `indigo-{4,6,12,15,20,25}`, `violet-{10,12,14}`,
`white-{4,6,8,10,12,20}`, `black-{4,6}`, `blue-{10,15,20,25}`.

#### 7.6.5 Validazione colori

| Controllo | Livello | Errore |
|-----------|---------|--------|
| Hex hardcoded in styles.css | **WARNING** | `GUIDELINE_WARN: hex hardcoded` |
| rgba hardcoded senza token | **WARNING** | `GUIDELINE_WARN: rgba senza overlay token` |
| Colore Tailwind default usato | **WARNING** | `GUIDELINE_WARN: usare palette custom` |
| Modifica design-tokens.css senza review | **BLOCCANTE** | Non rilasciabile |

### 7.7 Policy CDN-Free (VINCOLANTE)

> **Da Obsidian v4.0 in poi, ZERO dipendenze CDN.**

Tutti gli asset di terze parti DEVONO essere serviti localmente:

| Asset | Path locale | Dimensione |
|-------|-------------|------------|
| Bootstrap CSS | `/vendor/bootstrap/css/bootstrap.min.css` | 228 KB |
| Bootstrap JS | `/vendor/bootstrap/js/bootstrap.bundle.min.js` | 79 KB |
| Bootstrap Icons CSS | `/vendor/bootstrap-icons/font/bootstrap-icons.min.css` | 84 KB |
| Bootstrap Icons WOFF2 | `/vendor/bootstrap-icons/font/fonts/bootstrap-icons.woff2` | 128 KB |
| Inter Font (latin) | `/fonts/inter/inter-latin.woff2` | 48 KB |
| Inter Font (latin-ext) | `/fonts/inter/inter-latin-ext.woff2` | 85 KB |

**Regole:**
- **VIETATO** inserire URL `cdn.jsdelivr.net`, `fonts.googleapis.com`, o qualsiasi CDN esterno
- **VIETATO** caricare script/css da domini esterni
- CSP (Content-Security-Policy) configurato a `'self'` only — nessun dominio esterno ammesso
- Ogni aggiornamento di librerie (`/vendor/`) deve essere scaricato, verificato e committato localmente
- Cache headers per `/vendor/` e `/fonts/`: `immutable, max-age=31536000` (1 anno)
- `@font-face` definiti in `design-tokens.css` con path relativi a `/fonts/`

```nginx
# ✅ CORRETTO — nginx.conf
location /vendor/ { expires max; add_header Cache-Control "public, immutable, max-age=31536000"; }
location /fonts/  { expires max; add_header Cache-Control "public, immutable, max-age=31536000"; }
```

```html
<!-- ✅ CORRETTO -->
<link href="/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">

<!-- ❌ VIETATO -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css" rel="stylesheet">
```

### 7.8 Aggiornamento Remoto — Branch Fallback

Quando un tag OTA non esiste sul repository GitHub (es. release locale),
il sistema di download automaticamente:

1. Tenta il download da `refs/tags/{tag}.tar.gz`
2. Se **404** → fallback a `refs/heads/{branch}.tar.gz` (default: `main`)
3. Il campo `branch_fallback: true` nella risposta segnala il fallback
4. Evento registrato nell'audit trail: `ota.download.tag_fallback`

**Regola:** Il branch di fallback è configurabile in `/ota/remote/config`.
Il default è `main`. Solo branch protetti sono ammessi come fallback.

```
  Tag check (GitHub)         Branch fallback
  ─────────────────         ────────────────
  refs/tags/3.6.1    ──►   ✓ Download da tag
       │
       └─ 404?  ──►  refs/heads/main  ──►  ✓ Download da branch
                          │
                          └─ 404?  ──►  ✗ Errore definitivo
```

---

## 8. Validazione Automatica — Enforcement

Il sistema OTA applica automaticamente queste regole tramite validazione
pre-rilascio. La funzione `_validate_release_guidelines()` controlla:

### 8.1 Controlli bloccanti (MUST PASS)

| ID | Controllo | Errore se fallisce |
|----|-----------|-------------------|
| G-01 | VERSION.json presente e parsabile | `GUIDELINE_FAIL: VERSION.json mancante o corrotto` |
| G-02 | Versione SemVer valida (X.Y.Z) | `GUIDELINE_FAIL: versione non SemVer` |
| G-03 | Build incrementale | `GUIDELINE_FAIL: build non incrementale` |
| G-04 | Channel valido (stable/beta/dev) | `GUIDELINE_FAIL: channel non valido` |
| G-05 | MANIFEST formato dict | `GUIDELINE_FAIL: MANIFEST must be dict` |
| G-06 | Nessun file protetto nel rilascio | `GUIDELINE_FAIL: file protetto incluso` |
| G-07 | Nessun path traversal | `GUIDELINE_FAIL: path traversal rilevato` |
| G-08 | SHA-256 valido per ogni file | `GUIDELINE_FAIL: integrity check failed` |
| G-09 | Tag versione non duplicato | `GUIDELINE_FAIL: versione già rilasciata` |
| G-10 | Nessun segreto nei file staged | `GUIDELINE_FAIL: possibile segreto rilevato` |
| G-11 | Colori in styles.css usano var(--tpl-*) | `GUIDELINE_WARN: hex hardcoded rilevato` |

### 8.2 Controlli warning (SHOULD FIX)

| ID | Controllo | Warning |
|----|-----------|---------|
| W-01 | File singolo > 10MB | `GUIDELINE_WARN: file molto grande` |
| W-02 | > 50 file in un singolo rilascio | `GUIDELINE_WARN: molti file modificati` |
| W-03 | Codename mancante per minor/major | `GUIDELINE_WARN: codename consigliato` |
| W-04 | docs/ non aggiornato in release con API changes | `GUIDELINE_WARN: documentazione non aggiornata` |
| W-05 | tests/ non aggiornato in release con API changes | `GUIDELINE_WARN: test non aggiornati` |
| W-06 | design-tokens.css modificato senza docs | `GUIDELINE_WARN: documentare cambio palette` |
| W-07 | rgba hardcoded senza overlay token | `GUIDELINE_WARN: usare --tpl-overlay-*` |

---

## 9. Casi speciali

### 9.1 Hotfix di emergenza

Per fix critici di sicurezza, la procedura accelerata permette:
1. Modifica diretta del file
2. `POST /ota/registry/release` con `bump: "patch"`
3. Pipeline OTA standard

Non è consentito saltare la pipeline nemmeno in emergenza.

### 9.2 Downgrade

Il downgrade via OTA **NON è supportato**. Per eseguire un rollback:
1. Usare `POST /ota/install/rollback` (ripristina snapshot pre-update)
2. Oppure ripristino manuale dai rollback snapshots

### 9.3 Migrazione schema

Se l'aggiornamento richiede una migrazione schema (database, config):
1. Creare script in `migrations/` con naming `{from_version}_to_{to_version}.py`
2. La pipeline OTA esegue automaticamente le migrazioni pre/post-apply
3. Fallimento migrazione → blocco (ma file già applicati restano, review manuale)

### 9.4 Aggiornamento engine OTA

L'engine `ota_update_engine.py` è un file protetto. Per aggiornarlo:
1. Modificare il file manualmente
2. Ricostruire il container API: `./run.sh down && ./run.sh up`
3. Verificare con smoke test: tutti i 6 check devono passare
4. Aggiornare il baseline: `POST /ota/registry/snapshot`

---

## 10. Riepilogo vincoli — Quick Reference

```
╔══════════════════════════════════════════════════════════════════╗
║                   TPL UPDATE GUIDELINES                         ║
║                                                                  ║
║  OBBLIGATORIO:                                                   ║
║  ✓ SemVer (MAJOR.MINOR.PATCH)                                   ║
║  ✓ VERSION.json valido con tutti i campi                         ║
║  ✓ MANIFEST.json formato dict (MAI list)                         ║
║  ✓ SHA-256 per ogni file del rilascio                            ║
║  ✓ Pipeline completa: start → apply → finalize                   ║
║  ✓ Audit log per ogni azione OTA                                 ║
║  ✓ No file protetti via OTA                                      ║
║  ✓ No path traversal                                             ║
║  ✓ No segreti nei file distribuiti                                ║
║                                                                  ║
║  VIETATO:                                                        ║
║  ✗ Saltare step della pipeline                                   ║
║  ✗ Downgrade via OTA                                             ║
║  ✗ MANIFEST come array                                           ║
║  ✗ Release senza scan preventivo                                 ║
║  ✗ File > 50MB singolo                                           ║
║  ✗ Modifica diretta di file protetti                             ║
║  ✗ Deploy senza verifica integrità                               ║
║  ✗ Ignorare warning di sicurezza                                 ║
║                                                                  ║
║  CONSIGLIATO:                                                    ║
║  ○ Codename per ogni release minor/major                         ║
║  ○ Aggiornare docs/ e tests/ insieme al codice                   ║
║  ○ Usare tpl-release.sh full per rilasci completi                ║
║  ○ Verificare post-install con /ota/install/verify               ║
║  ○ Controllare GitHub prima di rilasciare localmente             ║
║                                                                  ║
║  CSS / DESIGN TOKENS:                                            ║
║  ✓ SEMPRE var(--tpl-*) per colori in styles.css                  ║
║  ✓ Palette custom — MAI Tailwind defaults                        ║
║  ✓ Gradienti ripetuti → token compositi                          ║
║  ✓ Trasparenze → overlay tokens strutturati                      ║
║  ✗ MAI hex/rgba hardcoded in styles.css                          ║
║  ✗ MAI modificare valori colore fuori da design-tokens.css       ║
╚══════════════════════════════════════════════════════════════════╝
```

---

> **Documento vincolante** — v3.0, aggiornato il 3 marzo 2026  
> Enforcement automatico tramite `_validate_release_guidelines()` nell'OTA engine.  
> Design Token System v4.0, palette Obsidian v4.0, CDN-free policy, branch fallback GitHub.

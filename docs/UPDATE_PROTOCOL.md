# TPL — Protocollo di Modifica e Aggiornamento

> Versione protocollo: **1.0** — Ultimo aggiornamento: **4 marzo 2026**

Questo documento definisce il protocollo standard da seguire per ogni modifica al progetto TPL. È pensato per essere utilizzato sia da sviluppatori umani che da agenti AI.

---

## 1. Classificazione delle Modifiche

| Tipo | Bump | Quando usare | Esempio |
|------|------|--------------|---------|
| **Build** | `build` | Fix minori, aggiustamenti CSS/HTML, cleanup | Correzione colore, font-size, refactoring |
| **Patch** | `patch` | Bugfix, fix sicurezza, fix regressioni | Correzione endpoint, validazione mancante |
| **Minor** | `minor` | Nuove feature retrocompatibili | Nuovo engine, nuovo endpoint API |
| **Major** | `major` | Breaking change, redesign architetturale | Cambio schema API, migrazione dati |

---

## 2. Workflow Standard

### Fase 1 — Preparazione

```
1. Verificare lo stato corrente:
   $ cat VERSION.json
   → Annotare versione e build corrente

2. Leggere la mappa del progetto:
   → docs/PROJECT_MAP.md

3. Identificare i file coinvolti nella modifica

4. Verificare se i file sono PROTETTI (non aggiornabili via OTA):
   - apps/api/app/engines/ota_update_engine.py
   - compose.d/40-api.yml
   - run.sh
   - .env
   → Se sì: la modifica richiede REBUILD del container
```

### Fase 2 — Implementazione

```
1. Creare backup SOLO se la modifica è rischiosa e reversibile:
   → NON creare file .bak (sono in .gitignore)
   → Usare git per il versionamento

2. Applicare le modifiche

3. Verificare sintassi:
   - Python: $ python3 -c "import ast; ast.parse(open('FILE').read()); print('OK')"
   - JavaScript: $ node -e "new Function(require('fs').readFileSync('FILE','utf8'))"
   - CSS: verificare manualmente o con il browser

4. Per modifiche CSS/design:
   - Calcolare contrasto WCAG AA per OGNI combinazione testo/sfondo
   - Minimo 4.5:1 per testo normale, 3.0:1 per testo grande (≥18.66px bold, ≥24px)
   - Testare su TUTTI gli sfondi: white, surface (#FDFCFA), slate-100 (#F0EEEA), slate-200
   - Font size minimo: 0.7rem (11.2px) = --tpl-fs-xs
```

### Fase 3 — Deploy

#### 3a. File Frontend/Config (aggiornabili via OTA)

```bash
# 1. Ricostruire i container (necessario per caricare i file aggiornati)
$ bash run.sh up

# 2. Ottenere token di autenticazione
$ TOKEN=$(curl -sk https://localhost:8443/api/token \
    -X POST -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"<PASSWORD>"}' \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3. Creare release OTA (auto-scan + staging + bump VERSION.json)
$ curl -sk -X POST "https://localhost:8443/api/ota/registry/release" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"bump":"build","changelog":"Descrizione sintetica delle modifiche"}'
# → Restituisce: versione, build, full_version, file staged

# 4. Installare la release
$ curl -sk -X POST "https://localhost:8443/api/ota/install/start/<VERSION>" \
    -H "Authorization: Bearer $TOKEN"

# 5. Applicare i file
$ curl -sk -X POST "https://localhost:8443/api/ota/install/apply" \
    -H "Authorization: Bearer $TOKEN"

# 6. Finalizzare
$ curl -sk -X POST "https://localhost:8443/api/ota/install/finalize" \
    -H "Authorization: Bearer $TOKEN"
```

#### 3b. File Engine/Protetti (solo rebuild)

```bash
# Le modifiche ai file protetti diventano live al rebuild:
$ bash run.sh up
# Nessun passaggio OTA necessario
```

### Fase 4 — Verifica

```bash
# 1. Verificare versione
$ cat VERSION.json | python3 -m json.tool

# 2. Verificare endpoint OTA
$ curl -sk "https://localhost:8443/api/ota/status" -H "Authorization: Bearer $TOKEN"

# 3. Smoke test
$ bash scripts/security_smoke.sh

# 4. Test suite (se applicabile)
$ bash scripts/test_all.sh
```

---

## 3. Regole Obbligatorie

### 3.1 Nessun file .bak in produzione

```
❌ cp styles.css styles.css.bak      # MAI — usa git
✅ git add . && git commit -m "pre-X" # Versionamento corretto
```

### 3.2 Pulizia obbligatoria post-lavoro

Dopo ogni sessione di sviluppo verificare:
- Nessun file `*.bak`, `*.tmp`, `*.old` nella working directory
- Nessuna directory `__pycache__/` residua
- Il `.gitignore` copre tutte le esclusioni necessarie

### 3.3 Changelog nella release

Ogni release OTA DEVE includere un changelog descrittivo:
```json
{
  "bump": "build",
  "changelog": "Fix contrasto WCAG AA slate-500, normalizzazione font-size .7rem floor"
}
```

### 3.4 Aggiornamento documentazione

Al termine di modifiche strutturali aggiornare:
- `docs/PROJECT_MAP.md` — se cambiano file, engine, moduli, endpoint
- `README.md` — se cambia la panoramica del progetto
- `VERSION.json` — aggiornato automaticamente via OTA release

---

## 4. Protocollo per Modifiche al Design System

### 4.1 Palette colori

I colori sono definiti ESCLUSIVAMENTE in `infra/web/design-tokens.css`. Non usare valori hex/rgb diretti in `styles.css` — usare le variabili CSS.

| Token | Uso | Contrasto minimo su white |
|-------|-----|---------------------------|
| `--tpl-text` (slate-800) | Testo principale | 17.0:1 |
| `--tpl-text-sec` (slate-600) | Testo secondario | 7.2:1 |
| `--tpl-text-muted` (slate-500) | Testo muted | 7.0:1 |
| `--tpl-accent-text` (indigo-700) | Accento gold | 7.1:1 |
| `--tpl-accent-text-light` (indigo-600) | Accento gold leggero | 5.4:1 |

### 4.2 Scala tipografica

```
--tpl-fs-xs:      0.7rem   (11.2px) — Badge, tag, label secondarie
--tpl-fs-sm:      0.78rem  (12.5px) — Testo UI secondario
--tpl-fs-base:    0.88rem  (14.1px) — Testo contenuto primario
--tpl-fs-md:      0.95rem  (15.2px) — Testo enfatizzato
--tpl-fs-lg:      1.1rem   (17.6px) — Heading sezione
--tpl-fs-xl:      1.35rem  (21.6px) — Heading maggiore
--tpl-fs-2xl:     1.65rem  (26.4px) — Titolo pagina
--tpl-fs-3xl:     2rem     (32px)   — Display piccolo
--tpl-fs-display: 2.5rem   (40px)   — Display principale
```

**Regola:** Nessun `font-size` sotto `0.7rem` in produzione.

### 4.3 Verifica contrasto (script)

```python
def contrast(fg_rgb, bg_rgb):
    def srgb_to_linear(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    def luminance(r, g, b):
        return 0.2126 * srgb_to_linear(r) + 0.7152 * srgb_to_linear(g) + 0.0722 * srgb_to_linear(b)
    l1, l2 = luminance(*fg_rgb), luminance(*bg_rgb)
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)

# Esempio: slate-500 #5D5850 su white
print(contrast((93, 88, 80), (255, 255, 255)))  # → 7.05 ✅
```

---

## 5. Protocollo per Modifiche agli Engine

### 5.1 Struttura standard

Ogni engine segue lo schema:
```python
# Docstring con nome engine e versione
# Import
# Costanti
# Classi/funzioni private (_prefix)
# Endpoint API registrati tramite @app.get/post/put/delete
```

### 5.2 Versionamento dinamico

Usare `_get_platform_version()` (non `PLATFORM_VERSION`) per ottenere la versione corrente. La funzione legge `VERSION.json` ad ogni chiamata, così resta accurata dopo aggiornamenti OTA.

```python
# ✅ Corretto — versione dinamica
cur_ver = _get_platform_version()

# ❌ Sbagliato — versione cached all'avvio del processo
cur_ver = PLATFORM_VERSION  # solo per logging/informativo
```

### 5.3 Confronto versioni

```python
# Confronto semplice (solo semver)
_version_compare("5.1.1", "5.2.0")  # → -1

# Confronto build-aware (include build number come tiebreaker)
_version_compare("5.1.1+006", "5.1.1+007", build_aware=True)  # → -1
```

---

## 6. Protocollo per Release Distribuzione

Per creare un archivio distribuibile (da inviare al repository):

```bash
$ bash scripts/release.sh
```

Il release script:
- Esclude: `.bak`, `__pycache__`, `.secrets`, `.env`, `data/`, `logs/`, `.git/`
- Include: tutto il codice sorgente, compose, infra, modules, scripts, tests, docs
- Output: archivio tar.gz con hash SHA-256

---

## 7. Checklist Pre-Commit

```
□ Nessun file .bak o temp presente
□ Nessun __pycache__ residuo
□ python3 -c "import ast; ast.parse(...)" — OK per tutti i .py modificati
□ Font-size minimo ≥ 0.7rem in tutti i CSS
□ Contrasto WCAG AA ≥ 4.5:1 per tutte le combinazioni testo/sfondo
□ Changelog descrittivo nella release OTA
□ docs/PROJECT_MAP.md aggiornato se necessario
□ Smoke test: bash scripts/security_smoke.sh — OK
□ VERSION.json aggiornato (automatico via OTA release)
```

---

## 8. Checklist Analisi AI Pre-Implementazione

Quando un agente AI inizia una sessione di sviluppo su TPL:

```
1. Leggere docs/PROJECT_MAP.md per la mappa completa del progetto
2. Leggere docs/UPDATE_PROTOCOL.md (questo file) per il protocollo
3. Leggere VERSION.json per la versione corrente
4. Identificare i file da modificare e verificare se sono protetti
5. Seguire il workflow standard (Fase 1 → 4)
6. Aggiornare la documentazione se la struttura cambia
```

---

## 9. Contatti & Repository

| | |
|---|---|
| **Repository** | github.com/pif993/TPL |
| **Owner** | pif993 |
| **Stack** | Python 3.12 + FastAPI + Docker Compose + Traefik + Vault |
| **Design** | Sovereign v5.2 — luxury gold/sapphire/carbon |

# TPL Change Management & OTA System

> Versione: 1.0 — Data: 2 marzo 2026 — Codename: Fusion

## Panoramica

Il sistema di Change Management di TPL traccia automaticamente tutte le modifiche
ai file del progetto e permette di creare rilasci OTA con un singolo comando API.

### Problema risolto

Prima di questo sistema, creare un aggiornamento OTA richiedeva 7 passaggi manuali:

1. Modificare i file del progetto
2. Aggiornare `VERSION.json`
3. `docker cp` dei file nello staging
4. Generare `MANIFEST.json` con SHA-256
5. Aggiornare `state.json`
6. Eseguire la pipeline install (3 step)

**Ora basta un solo endpoint**: `POST /ota/registry/release` — oppure
`./scripts/tpl-release.sh full` da terminale.

---

## Architettura

```
┌──────────────────────────────────────────────────────────────────┐
│                   TPL File Registry                              │
│                                                                  │
│  data/ota/file_registry.json                                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ schema_version: 1                                           │ │
│  │ baseline_version: "3.5.4"                                   │ │
│  │ files: {                                                    │ │
│  │   "infra/web/styles.css": {sha256, size, mtime, category}  │ │
│  │   "apps/api/app/main.py": {sha256, size, mtime, category}  │ │
│  │   ... (117 file tracciati)                                  │ │
│  │ }                                                           │ │
│  │ history: [{version, from, files, codename, categories}]     │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
         │                    │                     │
         ▼                    ▼                     ▼
    ┌─────────┐       ┌──────────────┐      ┌─────────────┐
    │  scan() │       │  release()   │      │ snapshot()  │
    │  Diff   │       │  Auto-stage  │      │ New base-   │
    │  detect │       │  + manifest  │      │ line state  │
    └─────────┘       │  + version   │      └─────────────┘
                      │  bump        │             ▲
                      └──────┬───────┘             │
                             │                     │
                             ▼                     │
                    ┌────────────────┐             │
                    │ OTA Pipeline   │             │
                    │ start → apply  │─── finalize ┘
                    │   → finalize   │  (auto-snapshot)
                    └────────────────┘
```

---

## Workflow standard

### 1. Modifica file del progetto

```bash
# Modifica qualsiasi file tracciato nel progetto
vim infra/web/styles.css
vim infra/web/sidebar.js
# ... qualsiasi file sotto le path tracciate
```

### 2. Scansione automatica delle modifiche

```bash
# Via API
curl -X POST /api/ota/registry/scan

# Via script
./scripts/tpl-release.sh scan
```

Risposta:
```json
{
  "changed": [
    {"path": "infra/web/styles.css", "category": "web", "size_delta": +52}
  ],
  "new": [],
  "deleted": [],
  "summary": {"changed": 1, "new": 0, "deleted": 0}
}
```

### 3. Creazione release automatica

```bash
# Via API — un solo endpoint fa tutto
curl -X POST /api/ota/registry/release \
  -d '{"bump": "patch", "codename": "Fusion"}'

# Via script
./scripts/tpl-release.sh release --bump patch --codename "Fusion"
```

Cosa fa automaticamente:
- ✅ Rileva i file modificati/nuovi
- ✅ Incrementa la versione (3.5.4 → 3.5.5)
- ✅ Aggiorna `VERSION.json` nel progetto
- ✅ Copia i file modificati in `staging/3.5.5/`
- ✅ Genera `MANIFEST.json` (formato dict con SHA-256)
- ✅ Aggiorna `state.json` (latest_available = 3.5.5)
- ✅ Registra nella history del registry

### 4. Installazione via OTA Pipeline

```bash
# Via API (3 step standard)
curl -X POST /api/ota/install/start/3.5.5
curl -X POST /api/ota/install/apply
curl -X POST /api/ota/install/finalize

# Oppure tutto in un comando
./scripts/tpl-release.sh full --codename "Fusion" --yes
```

### 5. Baseline auto-aggiornato

Dopo il `finalize`, il registry aggiorna automaticamente il baseline alla nuova
versione. La prossima scansione partirà da questo stato.

---

## API Endpoints

### Registry

| Endpoint | Metodo | Descrizione |
|----------|--------|-------------|
| `/ota/registry` | GET | Registry completo (files, history, config) |
| `/ota/registry/status` | GET | Sommario rapido (conteggi, ultima release) |
| `/ota/registry/scan` | POST | Scansiona e mostra diff vs baseline |
| `/ota/registry/release` | POST | Crea release automatica da modifiche |
| `/ota/registry/snapshot` | POST | Aggiorna baseline allo stato corrente |
| `/ota/registry/history` | GET | Storico completo dei rilasci |
| `/ota/registry/diff` | GET | Alias per scan |
| `/ota/registry/config` | POST | Configura path tracciate ed escluse |

### Parametri di `/ota/registry/release`

```json
{
  "bump": "patch",      // "patch" | "minor" | "major"
  "codename": "Fusion"  // opzionale
}
```

---

## Script Host: tpl-release.sh

```bash
./scripts/tpl-release.sh scan             # Solo scansione
./scripts/tpl-release.sh release          # Crea release (interattivo)
./scripts/tpl-release.sh install 3.5.5    # Esegui pipeline OTA
./scripts/tpl-release.sh snapshot         # Nuovo baseline
./scripts/tpl-release.sh status           # Stato registry
./scripts/tpl-release.sh history          # Storico rilasci
./scripts/tpl-release.sh full             # Tutto: scan + release + install

# Opzioni
--codename NAME    # Codename del rilascio
--bump TYPE        # patch (default), minor, major
--dry              # Dry run: solo scansione
--yes              # Salta conferme interattive
```

### Variabili d'ambiente

| Variabile | Default | Descrizione |
|-----------|---------|-------------|
| `TPL_API_URL` | `https://localhost:8443` | URL dell'API |
| `TPL_USER` | `admin` | Username API |
| `TPL_PASS` | (prompt) | Password API |

---

## Path tracciate

Il registry traccia i seguenti percorsi:

| Percorso | Categoria | Descrizione |
|----------|-----------|-------------|
| `infra/web/` | web | Frontend (HTML, CSS, JS) |
| `apps/api/app/` | api | Backend Python API |
| `modules/` | modules | Script moduli TPL |
| `compose.yml` | other | Docker Compose base |
| `compose.d/` | infra | Compose overrides |
| `scripts/` | scripts | Script di utilità |
| `VERSION.json` | other | Versione piattaforma |
| `infra/traefik/` | infra | Configurazione Traefik |
| `infra/vault/*.hcl` | infra | Configurazione Vault |
| `docs/` | docs | Documentazione |
| `migrations/` | docs | Registry migrazioni |
| `tests/` | tests | Test suite |

### Esclusi automaticamente

- `__pycache__/`, `*.pyc` — bytecode Python
- `*.bak`, `*.tmp`, `*.swp` — file temporanei
- `node_modules/` — dipendenze Node
- `.git/` — metadata Git
- `.env` — segreti
- `data/`, `logs/` — dati runtime

### File protetti (mai sovrascritti da OTA)

- `apps/api/app/engines/ota_update_engine.py`
- `compose.d/40-api.yml`
- `run.sh`
- `.env`

---

## File Registry Persistente

Il file `data/ota/file_registry.json` mantiene:

```json
{
  "schema_version": 1,
  "baseline_version": "3.5.4",
  "files": {
    "infra/web/styles.css": {
      "sha256": "d930643886708cd3...",
      "size": 284896,
      "mtime": "2026-03-01T14:00:00",
      "category": "web",
      "installed_by": "3.5.4",
      "tracked_since": "2026-03-01T14:00:00",
      "snapshot_at": "2026-03-02T19:08:00"
    }
  },
  "history": [
    {
      "version": "3.5.5",
      "from_version": "3.5.4",
      "codename": "Fusion",
      "files": ["infra/web/styles.css", "VERSION.json"],
      "files_count": 2,
      "categories": {"web": 1, "other": 1},
      "released_at": "2026-03-02T19:10:00"
    }
  ]
}
```

### Lifecycle dei dati

1. **`snapshot()`** — Scrive SHA-256 di tutti i file tracciati → diventa il baseline
2. **`scan()`** — Confronta lo stato attuale con il baseline → genera diff
3. **`release()`** — Crea release OTA automatica → registra in `history`
4. **`finalize` hook** — Dopo OTA install, auto-chiama `snapshot()` per aggiornare il baseline

---

## Integrazione con OTA Pipeline

Il registry si integra nel ciclo OTA esistente:

```
                          ┌─────────────────────┐
  Le modifiche al         │   File Registry     │
  progetto vengono  ─────►│   scan() → diff     │
  tracciate auto-         │   release() → stage │
  maticamente             └─────────┬───────────┘
                                    │
                                    ▼
                          ┌─────────────────────┐
                          │  OTA Pipeline       │
                          │  install/start      │  Ed25519 verify
                          │  install/apply      │  SHA-256 integrity
                          │  install/finalize ──┼──► auto snapshot()
                          └─────────────────────┘
                                    │
                                    ▼
                          ┌─────────────────────┐
                          │  Post-Install       │
                          │  baseline = nuova   │
                          │  versione           │
                          │  scan() → 0 changes │
                          └─────────────────────┘
```

---

## FAQ

**D: Cosa succede se modifico un file protetto?**
R: Il file viene rilevato dalla scansione ma ESCLUSO dal rilascio OTA. I file protetti
non vengono mai sovrascritti durante l'installazione OTA.

**D: Posso aggiungere nuove path da tracciare?**
R: Sì, via `POST /ota/registry/config` con la lista aggiornata di `tracked_paths`.

**D: Cosa succede se cancello un file tracciato?**
R: La scansione lo rileva come "deleted". Verrà segnalato nel diff ma non generato
nel release (non si possono distribuire cancellazioni via OTA al momento).

**D: Il baseline si aggiorna automaticamente?**
R: Sì, dopo ogni `finalize` riuscito. Oppure manualmente via `POST /ota/registry/snapshot`.

**D: Posso vedere la storia di tutti i rilasci?**
R: `GET /ota/registry/history` — mostra versione, codename, file modificati, categorie,
timestamp per ogni rilascio.

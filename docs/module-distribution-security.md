# TPL Module Distribution — Security Checklist

Questo documento descrive le verifiche di sicurezza per il sistema di distribuzione
moduli bundle-based di TPL.

## Architettura

```
┌──────────────────────────────────────────────────────┐
│  tpl-modules CLI (scripts/tpl-modules)               │
│  ────────────────────────────────────────────────     │
│  pack  → crea bundle firmato (.tar.gz)               │
│  verify → verifica firma + checksum                  │
│  install → download → verify → stage → switch        │
│  rollback → ripristino atomico release precedente    │
└──────────────────────────────────────────────────────┘
         │ atomic symlink swap
         ▼
┌──────────────────────────────────────────────────────┐
│  /var/lib/tpl/modules/                               │
│  ├── releases/                                       │
│  │   ├── 1700000000_tpl-modules-2.1.0/              │
│  │   │   ├── .manifest.json                          │
│  │   │   ├── .signature.sig                          │
│  │   │   └── *.sh                                    │
│  │   └── 1700100000_tpl-modules-2.2.0/ ← CURRENT   │
│  └── current → releases/1700100000_.../  (symlink)   │
└──────────────────────────────────────────────────────┘
         │ read-only mount (:ro)
         ▼
┌──────────────────────────────────────────────────────┐
│  API container (read_only: true)                     │
│  /work/modules (ro) — solo lettura metadati          │
│  ENABLE_CONTROL_PLANE=0 — no esecuzione script      │
│  /modules/bundle, /modules/releases — API read-only  │
└──────────────────────────────────────────────────────┘
```

## Checklist

### 1. Firma obbligatoria (`CRITICAL`)
- **Variabile:** `TPL_REQUIRE_SIGNATURE=1`
- **Verifica:** Tutti i bundle devono essere firmati con HMAC-SHA256
- **CLI:** `tpl-modules security-check <bundle.tar.gz>`
- **Impatto:** Bundle non firmati vengono rifiutati durante l'installazione

### 2. Control plane disabilitato (`CRITICAL`)
- **Variabile:** `ENABLE_CONTROL_PLANE=0`
- **Verifica:** L'endpoint `/modules/apply` restituisce 403 in produzione
- **Impatto:** Nessuna esecuzione di script bash via HTTP
- **Nota:** `ENABLE_CONTROL_PLANE=1` è consentito SOLO in sviluppo/bootstrap

### 3. Integrità file moduli (`CRITICAL`)
- **Verifica:** Ogni file nel bundle è verificato contro SHA-256 nel manifest.json
- **CLI:** `tpl-modules verify <bundle.tar.gz>`
- **API:** `GET /modules/integrity`
- **Impatto:** File corrotti o modificati vengono rilevati immediatamente

### 4. Release corrente firmata (`HIGH`)
- **Verifica:** La release attiva in `/var/lib/tpl/modules/current` ha firma valida
- **API:** `GET /modules/bundle` → campo `signature.signed`
- **Impatto:** Audit trail sulla provenienza del codice in esecuzione

### 5. Moduli montati in sola lettura (`HIGH`)
- **Compose:** `./modules:/work/modules:ro`
- **Verifica:** Il container non può scrivere nella directory moduli
- **Impatto:** Previene modifiche runtime anche in caso di compromissione

### 6. HTTPS forzato (`MEDIUM`)
- **Variabile:** `FORCE_HTTPS=true`
- **Verifica:** Header HSTS e redirect HTTPS attivi
- **Impatto:** Previene intercettazione di token e dati sensibili

### 7. Canale aggiornamenti (`LOW`)
- **Variabile:** `TPL_UPDATE_CHANNEL=stable`
- **Valori:** `stable` (raccomandato), `beta`, `dev`
- **Impatto:** Canale `stable` riceve solo release verificate

## Bundle Format

Un bundle TPL è un file `.tar.gz` contenente:

```
tpl-modules-<version>.tar.gz
├── manifest.json      # Metadati + checksum SHA-256 per ogni file
├── signature.sig      # Firma HMAC-SHA256 del manifest
└── modules/
    ├── 10_traefik.sh
    ├── 30_web_gui.sh
    ├── ...
    └── 107_self_diagnosis.sh
```

### manifest.json
```json
{
  "version": "2.1.0",
  "channel": "stable",
  "created": "20260221T120000Z",
  "modules_count": 21,
  "files": {
    "10_traefik.sh": {"sha256": "abc123...", "size": 4096, "version": "1.0.0"},
    ...
  },
  "min_platform_version": "2.0.0",
  "signature_algorithm": "hmac-sha256"
}
```

### signature.sig
```json
{
  "signed": true,
  "algorithm": "hmac-sha256",
  "manifest_hash": "<sha256 del manifest.json>",
  "signature": "<hmac della hash>",
  "key_fingerprint": "<primi 16 char del fingerprint>"
}
```

## Procedura di aggiornamento sicuro

1. **Genera keypair** (una tantum):
   ```bash
   scripts/tpl-modules keygen
   ```

2. **Crea bundle firmato**:
   ```bash
   scripts/tpl-modules pack ./modules 2.1.0 ./dist
   ```

3. **Verifica (pre-flight)**:
   ```bash
   scripts/tpl-modules security-check ./dist/tpl-modules-2.1.0.tar.gz
   scripts/tpl-modules verify ./dist/tpl-modules-2.1.0.tar.gz
   ```

4. **Installa atomicamente**:
   ```bash
   scripts/tpl-modules install ./dist/tpl-modules-2.1.0.tar.gz
   ```

5. **Riavvia container**:
   ```bash
   docker compose restart tpl-api
   ```

6. **Verifica post-install**:
   ```bash
   scripts/tpl-modules info
   scripts/tpl-modules list
   curl -s https://localhost:8443/api/modules/integrity | jq
   ```

## Rollback

```bash
# Rollback interattivo
scripts/tpl-modules rollback

# Rollback a release specifica
scripts/tpl-modules rollback <release_id>

# Verifica
scripts/tpl-modules info
docker compose restart tpl-api
```

## Variabili d'ambiente

| Variabile | Default | Descrizione |
|---|---|---|
| `TPL_MODULES_BASE` | `/var/lib/tpl/modules` | Directory base per releases |
| `TPL_REQUIRE_SIGNATURE` | `1` | Firma obbligatoria |
| `TPL_UPDATE_CHANNEL` | `stable` | Canale aggiornamenti |
| `TPL_UPDATE_URL` | (vuoto) | URL repository remoto |
| `TPL_MAX_RELEASES` | `5` | Max release mantenute |
| `ENABLE_CONTROL_PLANE` | `0` | 0 = prod, 1 = solo dev |

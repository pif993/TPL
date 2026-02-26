#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  TPL — Installazione pulita (primo avvio)
# ═══════════════════════════════════════════════════════════════════════════════
#  Uso:
#    ./install_tpl.sh            Installazione pulita (primo avvio)
#    ./install_tpl.sh --reset    Riporta il progetto allo stato vergine
#
#  Installazione:
#   1. Verifica che NON sia già installato (protezione da doppia esecuzione)
#   2. Applica tutti i moduli baseline (init.sh auto-install)
#   3. Genera secrets random (.secrets/)
#   4. Genera certificato TLS self-signed
#   5. Builda e avvia i container Docker
#   6. Mostra la PASSWORD ADMIN TEMPORANEA nel terminale
#
#  Dopo l'installazione, usare:   ./go.sh   per avviare la piattaforma
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Reset: riporta il progetto allo stato vergine ─────────────────────────────
_do_reset() {
  echo ""
  echo "═══════════════════════════════════════════════════════════════"
  echo "  TPL — Reset allo stato vergine"
  echo "═══════════════════════════════════════════════════════════════"
  echo ""

  # 1. Stop containers — force-remove ALL tpl project containers regardless of source dir
  echo "Fase 1/4: Arresto container..."
  # Try compose down with all available fragments first
  local _compose_files=(-f compose.yml)
  for _f in "$SCRIPT_DIR"/compose.d/*.yml; do
    [ -f "$_f" ] && _compose_files+=(-f "$_f")
  done
  docker compose "${_compose_files[@]}" down --remove-orphans --volumes 2>/dev/null || true
  # Force-remove any remaining tpl containers (e.g. from a different working directory)
  docker ps -a --filter "label=com.docker.compose.project=tpl" -q 2>/dev/null | \
    xargs -r docker rm -f 2>/dev/null || true

  # 2. Rimuovi secrets e config generati
  echo "Fase 2/4: Rimozione secrets, config e stato..."
  # .secrets/ potrebbe essere root:999 (creato con sudo) — usa Docker se non rimovibile
  rm -rf "$SCRIPT_DIR/.secrets" 2>/dev/null || {
    echo "  Pulizia .secrets/ via Docker (proprietà root)..."
    docker run --rm -v "$SCRIPT_DIR:/mnt" alpine sh -c 'rm -rf /mnt/.secrets' 2>/dev/null || true
  }
  rm -f  "$SCRIPT_DIR/.env" 2>/dev/null || true
  rm -f  "$SCRIPT_DIR/.tpl_state.json" 2>/dev/null || true
  rm -f  "$SCRIPT_DIR/.bootstrapped" 2>/dev/null || true

  # 3. Pulisci data/ (UID 999 → usa Docker per rimuovere)
  if [[ -d "$SCRIPT_DIR/data" ]]; then
    local owner
    owner=$(stat -c '%u' "$SCRIPT_DIR/data" 2>/dev/null) || owner="$(id -u)"
    if [[ "$owner" != "$(id -u)" ]]; then
      echo "  Pulizia data/ via Docker (file di proprietà del container)..."
      docker run --rm -v "$SCRIPT_DIR/data:/mnt" alpine sh -c \
        'rm -rf /mnt/.tpl_* /mnt/.bootstrapped /mnt/modules/current/* 2>/dev/null; true' \
        2>/dev/null || true
    else
      rm -rf "$SCRIPT_DIR/data/.tpl_"* 2>/dev/null || true
      rm -f "$SCRIPT_DIR/data/.bootstrapped" 2>/dev/null || true
      rm -rf "$SCRIPT_DIR/data/modules/current/"* 2>/dev/null || true
    fi
  fi

  # 3b. Rimuovi artefatti Vault
    rm -f "$SCRIPT_DIR/.vault_unseal_keys.json" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/.vault_approle" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/compose.d/20-vault.yml" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/compose.d/60-keycloak.yml" "$SCRIPT_DIR/compose.d/60-auth.yml" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/.secrets/keycloak" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/infra/keycloak/realm.json" 2>/dev/null || true

  # 4. Rimuovi volumi e immagini Docker TPL
  echo "Fase 3/4: Pulizia Docker (volumi e immagini)..."
  docker volume rm tpl_pg tpl_tpl_data tpl_vault_data tpl_vault_audit 2>/dev/null || true
  docker rmi tpl-api:latest 2>/dev/null || true

  # 5. Verifica stato vergine
  echo "Fase 4/4: Verifica..."
  local clean=true
  [[ -d "$SCRIPT_DIR/.secrets" ]] && { echo "  ⚠ .secrets/ ancora presente"; clean=false; }
  [[ -f "$SCRIPT_DIR/.env" ]]     && { echo "  ⚠ .env ancora presente"; clean=false; }

  echo ""
  if [[ "$clean" = true ]]; then
    echo "  ✅ Progetto TPL riportato allo stato vergine."
    echo ""
    echo "  Per reinstallare:  ./install_tpl.sh"
  else
    echo "  ⚠  Pulizia parziale. Alcuni file non sono stati rimossi."
    echo "     Prova con: sudo rm -rf .secrets/ .env data/.tpl_*"
  fi
  echo ""
}

if [[ "${1:-}" = "--reset" || "${1:-}" = "reset" || "${1:-}" = "clean" ]]; then
  _do_reset
  exit 0
fi

# ── Protezione: blocca se già installato ──────────────────────────────────────
_already_installed() {
  if [[ -d "$SCRIPT_DIR/.secrets" && -f "$SCRIPT_DIR/compose.d/40-api.yml" ]]; then
    return 0
  fi
  if [[ -d "/opt/tpl/secrets" && -f "/etc/tpl/config.env" ]]; then
    return 0
  fi
  return 1
}

if _already_installed; then
  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  TPL è già installato.                                      ║"
  echo "╠═══════════════════════════════════════════════════════════════╣"
  echo "║                                                             ║"
  echo "║  Per avviare la piattaforma:    ./go.sh                     ║"
    # Applica moduli (forza sempre 60_auth_keycloak)
    ./init.sh apply 60_auth_keycloak
    ./init.sh apply_all
  echo "║                                                             ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo ""
  exit 1
fi

# ── Prerequisiti ──────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  TPL — Installazione pulita"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── Avviso sudo: non necessario per install_tpl.sh (dev/local) ────────────
if [[ "$(id -u)" -eq 0 ]]; then
  echo "  ⚠  Stai eseguendo come root (sudo)."
  echo "     Per installazione locale non è necessario."
  echo "     I file saranno creati con le permission corrette."
  echo ""
fi

_need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: '$1' non trovato. Installalo prima." >&2; exit 1; }; }
_need bash
_need docker
_need python3

if ! docker compose version >/dev/null 2>&1; then
  echo "FATAL: Docker Compose v2 non trovato." >&2
  exit 1
fi

echo "  ✓ Docker $(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)"
echo "  ✓ Docker Compose $(docker compose version --short 2>/dev/null || echo '?')"
echo "  ✓ Python3 $(python3 --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)"
echo ""

# ── Fase 1: Installazione moduli + generazione secrets ───────────────────────
echo "Fase 1/3: Installazione moduli e generazione secrets..."
[ -x ./init.sh ] || chmod +x ./init.sh
[ -x ./run.sh ]  || chmod +x ./run.sh
[ -x ./go.sh ]   || chmod +x ./go.sh

./init.sh auto-install

# ── Fase 2: Avvio servizi ────────────────────────────────────────────────────
echo ""
echo "Fase 2/3: Avvio servizi Docker..."
ENABLE_TRAEFIK="${ENABLE_TRAEFIK:-1}" AUTO_INSTALL=0 ./run.sh up

# ── Fase 3: Riepilogo finale ─────────────────────────────────────────────────
# La password viene già mostrata da run.sh _show_initial_creds.
# Aggiungiamo solo le istruzioni operative.

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  ✅  INSTALLAZIONE COMPLETATA"
echo ""
echo "  Prossimi passi:"
echo "    1. Apri l'URL mostrato sopra nel browser"
echo "    2. Accedi con admin e la password temporanea"
echo "    3. Cambia la password (obbligatorio al primo login)"
echo ""
echo "  Comandi successivi:"
echo "    ./go.sh              Avvia la piattaforma"
echo "    ./run.sh down        Ferma la piattaforma"
echo "    ./run.sh status      Stato dei servizi"
echo "    ./run.sh doctor      Check completo"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# ── go.sh — Avvio rapido della piattaforma TPL ──────────────────────────────
# Prerequisito: installazione già eseguita con ./install_tpl.sh
#
# Uso:  ./go.sh          Avvia tutti i servizi
#       ./go.sh down     Ferma i servizi
#       ./go.sh status   Stato servizi

# Verifica che l'installazione sia stata fatta
if [[ ! -d .secrets && ! -d /opt/tpl/secrets ]]; then
  echo ""
  echo "  ⚠  TPL non è ancora installato."
  echo ""
  echo "  Esegui prima:  ./install_tpl.sh"
  echo ""
  exit 1
fi

[ -x ./run.sh ] || chmod +x ./run.sh

# Passa il comando (default: up), disabilita auto-install
AUTO_INSTALL=0 ENABLE_TRAEFIK="${ENABLE_TRAEFIK:-1}" ./run.sh "${1:-up}"

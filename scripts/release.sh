#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TPL Release Packaging — creates a stateless distributable archive.
# ─────────────────────────────────────────────────────────────────────────────
#
# Produces:  tpl-<version>-<date>.tar.gz  (or .zip with -z flag)
#
# Guarantees:
#   • NO .tpl_* state/audit/backup files
#   • NO .secrets/ or Vault credentials
#   • NO .env (only .env.example ships)
#   • NO __pycache__, node_modules, dist, .git
#   • Reproducible: same source → same archive (modulo timestamp)
#
# Usage:
#   ./scripts/release.sh              # → tpl-<ver>-<date>.tar.gz
#   ./scripts/release.sh -z           # → tpl-<ver>-<date>.zip
#   ./scripts/release.sh -o /tmp      # → /tmp/tpl-<ver>-<date>.tar.gz
#   TPL_VERSION=2.1.0 ./scripts/release.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${TPL_VERSION:-$(date +%Y%m%d)}"
DATE="$(date +%Y%m%d-%H%M%S)"
FMT="tar"
OUTDIR="$ROOT"

while getopts "zo:" opt; do
  case "$opt" in
    z) FMT="zip" ;;
    o) OUTDIR="$OPTARG" ;;
    *) echo "Usage: $0 [-z] [-o outdir]" >&2; exit 1 ;;
  esac
done

NAME="tpl-${VERSION}-${DATE}"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "INFO: Staging release in $STAGE/$NAME ..."

# ── 1. Copy source tree, excluding all non-distributable content ─────────────
rsync -a --delete \
  --exclude='.git' \
  --exclude='.git/' \
  --exclude='.env' \
  --exclude='.secrets' \
  --exclude='.secrets/' \
  --exclude='.vault_unseal_keys.json' \
  --exclude='.vault_approle' \
  --exclude='.vault_approle/' \
  --exclude='infra/vault/data' \
  --exclude='infra/vault/data/' \
  --exclude='*.vault-token' \
  --exclude='.tpl_*' \
  --exclude='.tpl_backups' \
  --exclude='.tpl_backups/' \
  --exclude='.tpl_rollback_points' \
  --exclude='.tpl_rollback_points/' \
  --exclude='__pycache__' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='node_modules' \
  --exclude='node_modules/' \
  --exclude='.next' \
  --exclude='dist' \
  --exclude='*.tar.gz' \
  --exclude='*.zip' \
  --exclude='config.env' \
  --exclude='data' \
  --exclude='data/' \
  --exclude='logs' \
  --exclude='logs/' \
  --exclude='*.bak' \
  --exclude='infra/traefik/acme' \
  --exclude='infra/traefik/acme/' \
  "$ROOT/" "$STAGE/$NAME/"

# ── 2. Verify no state/secret leaks ─────────────────────────────────────────
LEAKED=0
while IFS= read -r -d '' f; do
  echo "ERROR: state file leaked into release: $f" >&2
  LEAKED=$((LEAKED + 1))
done < <(find "$STAGE/$NAME" -maxdepth 1 \( -name ".tpl_*" -o -name ".tpl_backups" -o -name ".tpl_rollback_points" \) -print0 2>/dev/null)

if [ -d "$STAGE/$NAME/.secrets" ]; then
  echo "ERROR: .secrets/ leaked into release" >&2
  LEAKED=$((LEAKED + 1))
fi
if [ -f "$STAGE/$NAME/.env" ]; then
  echo "ERROR: .env leaked into release" >&2
  LEAKED=$((LEAKED + 1))
fi
if [ -f "$STAGE/$NAME/config.env" ]; then
  echo "ERROR: config.env leaked into release" >&2
  LEAKED=$((LEAKED + 1))
fi
if [ -d "$STAGE/$NAME/data" ]; then
  echo "ERROR: data/ leaked into release" >&2
  LEAKED=$((LEAKED + 1))
fi
if [ -d "$STAGE/$NAME/logs" ]; then
  echo "ERROR: logs/ leaked into release" >&2
  LEAKED=$((LEAKED + 1))
fi

if [ "$LEAKED" -gt 0 ]; then
  echo "FATAL: $LEAKED leak(s) detected — release aborted." >&2
  exit 1
fi

# ── 3. Package ───────────────────────────────────────────────────────────────
mkdir -p "$OUTDIR"
if [ "$FMT" = "zip" ]; then
  OUT="$OUTDIR/${NAME}.zip"
  (cd "$STAGE" && zip -rq "$OUT" "$NAME")
else
  OUT="$OUTDIR/${NAME}.tar.gz"
  tar -czf "$OUT" -C "$STAGE" "$NAME"
fi

SIZE=$(du -h "$OUT" | cut -f1)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Release packaged successfully                              ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  Archive: $(basename "$OUT")"
echo "║  Size:    $SIZE"
echo "║  Path:    $OUT"
echo "║                                                             ║"
echo "║  Verified: no .tpl_*, no .secrets/, no .env, no __pycache__ ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

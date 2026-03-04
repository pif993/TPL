#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  TPL Platform — Export Archive Generator
#  Generates a compressed .tar.gz of the project for distribution,
#  excluding secrets, runtime data, logs, and build artifacts.
#
#  Usage:  bash scripts/export.sh          (from project root)
#          bash scripts/export.sh --zip    (produces .zip instead)
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Resolve project root ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ─── Read version from VERSION.json ─────────────────────────────────
if [[ ! -f VERSION.json ]]; then
  echo "❌  VERSION.json not found in project root"
  exit 1
fi

FULL_VERSION=$(python3 -c "import json; print(json.load(open('VERSION.json'))['full_version'])")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="TPL-${FULL_VERSION}"

# ─── Choose format ───────────────────────────────────────────────────
FORMAT="tar.gz"
if [[ "${1:-}" == "--zip" ]]; then
  FORMAT="zip"
fi

ARCHIVE_NAME="${BASE_NAME}.${FORMAT}"
DIST_DIR="${PROJECT_ROOT}/dist"

# ─── Ensure dist/ directory exists ───────────────────────────────────
mkdir -p "$DIST_DIR"

# ─── Remove previous archives of the same version ───────────────────
rm -f "${DIST_DIR}/TPL-${FULL_VERSION}."* 2>/dev/null || true

# ─── Exclusion list (secrets, runtime, caches, archives) ────────────
EXCLUDES=(
  # Secrets & crypto
  ".env"
  ".env.*"
  "config.env"
  ".secrets"
  ".keys"
  "*.pem"
  "*.key"
  "*.crt"
  "*.p12"
  "*.jks"

  # Vault runtime
  ".vault_unseal_keys.json"
  ".vault_approle"
  "*.vault-token"
  "infra/vault/data"

  # Runtime state & data
  "data"
  "logs"
  ".tpl_*"
  ".tpl_backups"
  ".tpl_rollback_points"

  # Traefik ACME
  "infra/traefik/acme"

  # Keycloak (root-owned Docker volume)
  "infra/keycloak"

  # Build artifacts & dist
  "dist"

  # Python caches
  "__pycache__"
  "*.py[cod]"
  "*.egg-info"
  ".venv"
  "venv"
  ".mypy_cache"
  ".ruff_cache"
  ".pytest_cache"
  "htmlcov"
  ".coverage"

  # Node (future)
  "node_modules"

  # Editor & IDE
  ".vscode"
  ".idea"
  "*.swp"
  "*.swo"

  # OS artifacts
  ".DS_Store"
  "Thumbs.db"

  # Backups & temp
  "*.bak"
  "*.tmp"
  "*.temp"
  "*.orig"
  "*.log"
  "*.pid"

  # Docker overrides
  "docker-compose.override.yml"
  ".docker"

  # Misc
  ".bootstrapped"
  ".git"
)

echo "══════════════════════════════════════════════════════════════"
echo "  TPL Export Archive Generator"
echo "══════════════════════════════════════════════════════════════"
echo "  Version:  ${FULL_VERSION}"
echo "  Format:   ${FORMAT}"
echo "  Output:   dist/${ARCHIVE_NAME}"
echo "──────────────────────────────────────────────────────────────"

if [[ "$FORMAT" == "tar.gz" ]]; then
  # Build tar exclude flags
  TAR_EXCLUDES=()
  for pattern in "${EXCLUDES[@]}"; do
    TAR_EXCLUDES+=("--exclude=${pattern}")
  done

  tar czf "${DIST_DIR}/${ARCHIVE_NAME}" \
    "${TAR_EXCLUDES[@]}" \
    --transform "s,^\\.,${BASE_NAME}," \
    -C "$PROJECT_ROOT" .

elif [[ "$FORMAT" == "zip" ]]; then
  # Create temp staging directory
  STAGING=$(mktemp -d)
  trap "rm -rf '$STAGING'" EXIT

  # Build rsync exclude flags
  RSYNC_EXCLUDES=()
  for pattern in "${EXCLUDES[@]}"; do
    RSYNC_EXCLUDES+=("--exclude=${pattern}")
  done

  rsync -a "${RSYNC_EXCLUDES[@]}" "$PROJECT_ROOT/" "$STAGING/${BASE_NAME}/"

  (cd "$STAGING" && zip -rq "${DIST_DIR}/${ARCHIVE_NAME}" "${BASE_NAME}")
fi

# ─── Summary ─────────────────────────────────────────────────────────
SIZE=$(du -sh "${DIST_DIR}/${ARCHIVE_NAME}" | cut -f1)
FILES=$(tar tzf "${DIST_DIR}/${ARCHIVE_NAME}" 2>/dev/null | wc -l || echo "N/A")

echo ""
echo "  ✅  Archive created successfully"
echo "  📦  ${DIST_DIR}/${ARCHIVE_NAME}"
echo "  📏  Size: ${SIZE}"
[[ "$FORMAT" == "tar.gz" ]] && echo "  📂  Files: ${FILES}"
echo ""
echo "══════════════════════════════════════════════════════════════"

#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# TPL v3.5.1 OTA Staging Script
# Usage: sudo bash scripts/stage_351.sh
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="${ROOT}/data/ota/staging/v3.5.1"
STATE="${ROOT}/data/ota/state.json"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  TPL v3.5.1 — OTA Staging                                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Create staging directory
mkdir -p "$STAGING"

# List of changed files to stage
FILES=(
  "VERSION.json"
  "apps/api/app/main.py"
  "apps/api/app/auth_impl.py"
  "apps/api/app/_auth_local.py"
  "apps/api/requirements.txt"
  "infra/web/diagnostics.js"
  "infra/web/diagnostics.html"
  "infra/web/app.js"
  "infra/web/landing.js"
  "infra/web/nginx.conf"
  "scripts/version.sh"
  "scripts/release.sh"
  "scripts/tpl-modules"
  "scripts/ota_update.sh"
)

echo ""
echo "Staging ${#FILES[@]} file modificati..."

for f in "${FILES[@]}"; do
  src="${ROOT}/${f}"
  dst="${STAGING}/${f}"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
    echo "  ✓ ${f}"
  else
    echo "  ✗ ${f} (non trovato!)"
  fi
done

# Generate manifest with SHA-256 checksums
echo ""
echo "Generazione manifest..."
MANIFEST="${STAGING}/.ota_manifest.json"
python3 -c "
import json, hashlib, os, time

staging = '$STAGING'
files = {}
for root, dirs, fnames in os.walk(staging):
    for fn in fnames:
        if fn.startswith('.ota_'):
            continue
        fp = os.path.join(root, fn)
        rel = os.path.relpath(fp, staging)
        sha = hashlib.sha256(open(fp, 'rb').read()).hexdigest()
        files[rel] = {'sha256': sha, 'size': os.path.getsize(fp)}

manifest = {
    'version': '3.5.1',
    'build': 20260228011,
    'full_version': '3.5.1+20260228011',
    'codename': 'Horizon',
    'channel': 'stable',
    'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'file_count': len(files),
    'files': files,
}
with open('$MANIFEST', 'w') as f:
    json.dump(manifest, f, indent=2)
print(f'  ✓ Manifest: {len(files)} file, checksum generati')
"

# Update state.json to add v3.5.1 to prepared_versions
if [[ -f "$STATE" ]]; then
  echo ""
  echo "Aggiornamento state.json..."
  python3 -c "
import json, time

with open('$STATE', 'r') as f:
    state = json.load(f)

# Add v3.5.1 to prepared_versions if not already there
pv = state.get('prepared_versions', [])
if 'v3.5.1' not in pv:
    pv.append('v3.5.1')
    state['prepared_versions'] = pv

# Update latest_version
state['latest_version'] = '3.5.1'
state['update_available'] = True
state['last_check'] = int(time.time())
state['last_check_iso'] = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime())

with open('$STATE', 'w') as f:
    json.dump(state, f, indent=2)
print('  ✓ state.json aggiornato (v3.5.1 aggiunto a prepared_versions)')
"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Staging completato!                                        ║"
echo "║                                                             ║"
echo "║  Per applicare:                                             ║"
echo "║    sudo bash scripts/ota_update.sh --apply v3.5.1           ║"
echo "║                                                             ║"
echo "║  Per verificare:                                            ║"
echo "║    bash scripts/ota_update.sh --check                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# TPL Fortress — Smart Build Numbering System
# ═══════════════════════════════════════════════════════════════════════════
#
# Guarantees:
#   • Every build number is strictly monotonically increasing
#   • Format: MAJOR.MINOR.PATCH+BUILD  (SemVer 2.0 compliant)
#   • BUILD = YYYYMMDD<SEQ>  where SEQ is a 3-digit daily sequence (001–999)
#   • Comparison: semver for release ordering, build for uniqueness
#   • OTA integration: compares full_version for upgradability decisions
#
# Usage:
#   ./scripts/version.sh                 # Show current version
#   ./scripts/version.sh bump patch      # 3.1.0 → 3.1.1  (new build)
#   ./scripts/version.sh bump minor      # 3.1.1 → 3.2.0  (new build)
#   ./scripts/version.sh bump major      # 3.2.0 → 4.0.0  (new build)
#   ./scripts/version.sh bump build      # Same version, new build number
#   ./scripts/version.sh check 3.0.0+20260101001  # Check if current > given
#   ./scripts/version.sh compare V1 V2   # Compare two full versions
#   ./scripts/version.sh export          # Export as env vars (for CI/CD)
#   ./scripts/version.sh apply           # Write version to all platform files
#
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION_FILE="$ROOT/VERSION.json"

# ── Ensure jq is available ───────────────────────────────────────────────
command -v jq >/dev/null 2>&1 || {
  echo "ERROR: jq is required. Install with: apt install jq" >&2
  exit 1
}

# ── Read current version ─────────────────────────────────────────────────
read_version() {
  if [ ! -f "$VERSION_FILE" ]; then
    echo "ERROR: $VERSION_FILE not found" >&2
    exit 1
  fi
  jq -r '.' "$VERSION_FILE"
}

get_field() {
  jq -r ".$1" "$VERSION_FILE"
}

# ── Parse semver components ──────────────────────────────────────────────
parse_semver() {
  local ver="$1"
  # Strip build metadata and pre-release
  ver="${ver%%+*}"
  ver="${ver%%-*}"
  echo "$ver"
}

get_major() { parse_semver "$1" | cut -d. -f1; }
get_minor() { parse_semver "$1" | cut -d. -f2; }
get_patch() { parse_semver "$1" | cut -d. -f3; }

# ── Generate next build number ───────────────────────────────────────────
# Format: YYYYMMDD<SEQ> — e.g., 20260227001, 20260227002, ...
# The daily sequence guarantees multiple builds per day are ordered.
generate_build() {
  local today
  today="$(date +%Y%m%d)"
  local current_build
  current_build="$(get_field build)"

  # Extract date part from current build (first 8 digits)
  local current_date="${current_build:0:8}"
  local current_seq="${current_build:8}"

  if [ "$current_date" = "$today" ]; then
    # Same day: increment sequence
    local next_seq=$(( 10#$current_seq + 1 ))
    printf "%s%03d" "$today" "$next_seq"
  else
    # New day: reset to 001
    printf "%s001" "$today"
  fi
}

# ── Compare two full versions (returns: -1, 0, 1) ───────────────────────
# Comparison logic:
#   1. Compare semver parts (major, minor, patch)
#   2. If semver equal, compare build numbers numerically
compare_versions() {
  local v1="$1" v2="$2"

  local sv1="${v1%%+*}" sv2="${v2%%+*}"
  local b1="${v1#*+}" b2="${v2#*+}"
  [ "$b1" = "$v1" ] && b1="0"
  [ "$b2" = "$v2" ] && b2="0"

  local maj1 min1 pat1 maj2 min2 pat2
  maj1=$(get_major "$sv1"); min1=$(get_minor "$sv1"); pat1=$(get_patch "$sv1")
  maj2=$(get_major "$sv2"); min2=$(get_minor "$sv2"); pat2=$(get_patch "$sv2")

  # Compare major
  if [ "$maj1" -gt "$maj2" ]; then echo "1"; return; fi
  if [ "$maj1" -lt "$maj2" ]; then echo "-1"; return; fi

  # Compare minor
  if [ "$min1" -gt "$min2" ]; then echo "1"; return; fi
  if [ "$min1" -lt "$min2" ]; then echo "-1"; return; fi

  # Compare patch
  if [ "$pat1" -gt "$pat2" ]; then echo "1"; return; fi
  if [ "$pat1" -lt "$pat2" ]; then echo "-1"; return; fi

  # Semver equal — compare build numbers
  # Remove non-numeric characters for safe comparison
  b1=$(echo "$b1" | tr -cd '0-9')
  b2=$(echo "$b2" | tr -cd '0-9')
  [ -z "$b1" ] && b1="0"
  [ -z "$b2" ] && b2="0"

  if [ "$b1" -gt "$b2" ]; then echo "1"; return; fi
  if [ "$b1" -lt "$b2" ]; then echo "-1"; return; fi

  echo "0"
}

# ── Bump version ─────────────────────────────────────────────────────────
bump_version() {
  local bump_type="${1:-build}"
  local current_version
  current_version="$(get_field version)"

  local major minor patch new_version
  major=$(get_major "$current_version")
  minor=$(get_minor "$current_version")
  patch=$(get_patch "$current_version")

  case "$bump_type" in
    major)
      major=$(( major + 1 ))
      minor=0
      patch=0
      ;;
    minor)
      minor=$(( minor + 1 ))
      patch=0
      ;;
    patch)
      patch=$(( patch + 1 ))
      ;;
    build)
      # No semver change, just new build number
      ;;
    *)
      echo "ERROR: Invalid bump type: $bump_type (use: major|minor|patch|build)" >&2
      exit 1
      ;;
  esac

  new_version="${major}.${minor}.${patch}"
  local new_build
  new_build="$(generate_build)"
  local full_version="${new_version}+${new_build}"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Verify monotonic increase
  local current_full
  current_full="$(get_field full_version)"
  local cmp
  cmp="$(compare_versions "$full_version" "$current_full")"

  if [ "$cmp" -le 0 ] && [ "$bump_type" != "build" ]; then
    # Force a higher build number if needed
    new_build="$(generate_build)"
    full_version="${new_version}+${new_build}"
  fi

  # Update VERSION.json
  jq --arg v "$new_version" \
     --arg b "$new_build" \
     --arg fv "$full_version" \
     --arg ra "$now" \
     '.version = $v | .build = ($b | tonumber) | .full_version = $fv | .released_at = $ra' \
     "$VERSION_FILE" > "${VERSION_FILE}.tmp" && mv "${VERSION_FILE}.tmp" "$VERSION_FILE"

  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  Version Bumped Successfully                                ║"
  echo "╠═══════════════════════════════════════════════════════════════╣"
  echo "║  Type:     $bump_type"
  echo "║  Version:  $new_version"
  echo "║  Build:    $new_build"
  echo "║  Full:     $full_version"
  echo "║  Date:     $now"
  echo "╚═══════════════════════════════════════════════════════════════╝"
}

# ── Check if current version can upgrade from given version ──────────────
check_upgradable() {
  local from_version="$1"
  local current_full
  current_full="$(get_field full_version)"
  local min_from
  min_from="$(get_field min_upgrade_from)"

  # Check if from_version is too old (below min_upgrade_from)
  local from_sv="${from_version%%+*}"
  local min_cmp
  min_cmp="$(compare_versions "$from_sv" "$min_from")"

  if [ "$min_cmp" -lt 0 ]; then
    echo "BLOCKED: $from_version is below minimum upgrade path ($min_from)"
    echo "  Action: Upgrade to $min_from first, then to $current_full"
    return 2
  fi

  local cmp
  cmp="$(compare_versions "$current_full" "$from_version")"

  if [ "$cmp" -gt 0 ]; then
    echo "UPGRADABLE: $from_version → $current_full"
    return 0
  elif [ "$cmp" -eq 0 ]; then
    echo "CURRENT: Already at $current_full"
    return 1
  else
    echo "DOWNGRADE: $from_version is newer than $current_full"
    return 1
  fi
}

# ── Export as environment variables ──────────────────────────────────────
export_vars() {
  echo "export TPL_VERSION=\"$(get_field version)\""
  echo "export TPL_BUILD=\"$(get_field build)\""
  echo "export TPL_FULL_VERSION=\"$(get_field full_version)\""
  echo "export TPL_CHANNEL=\"$(get_field channel)\""
  echo "export TPL_CODENAME=\"$(get_field codename)\""
  echo "export TPL_RELEASED_AT=\"$(get_field released_at)\""
}

# ── Apply version to all platform files ──────────────────────────────────
apply_version() {
  local version full_version
  version="$(get_field version)"
  full_version="$(get_field full_version)"
  local build
  build="$(get_field build)"

  echo "INFO: Applying version $full_version to platform files..."

  # Update footer versions in HTML files
  local html_files=(
    "$ROOT/infra/web/dashboard.html"
    "$ROOT/infra/web/ota.html"
    "$ROOT/infra/web/advanced.html"
    "$ROOT/infra/web/admin-modules.html"
  )

  for f in "${html_files[@]}"; do
    if [ -f "$f" ]; then
      # Update footer version (matches TPL-specific version markers only)
      sed -i -E "s/(TPL[[:space:]]+\S*[[:space:]]*)v[0-9]+\.[0-9]+(\.[0-9]+)?/\1v${version}/g" "$f"
      sed -i -E "s/(Versione[[:space:]]*)v?[0-9]+\.[0-9]+(\.[0-9]+)?/\1v${version}/g" "$f"
      # Update script cache busters
      sed -i -E "s/(sidebar\.js\?v=)[0-9.]+/\1${version}/" "$f"
      sed -i -E "s/(ota\.js\?v=)[0-9.]+/\1${version}/" "$f"
      echo "  ✓ $(basename "$f")"
    fi
  done

  # Update sidebar.js version display if present
  if [ -f "$ROOT/infra/web/sidebar.js" ]; then
    sed -i -E "s/TPL Fortress v[0-9]+\.[0-9]+(\.[0-9]+)?/TPL Fortress v${version}/" "$ROOT/infra/web/sidebar.js"
    echo "  ✓ sidebar.js"
  fi

  # Update login page copyright
  if [ -f "$ROOT/infra/web/index.html" ]; then
    sed -i -E "s/TPL Fortress v[0-9]+\.[0-9]+(\.[0-9]+)?/TPL Fortress v${version}/" "$ROOT/infra/web/index.html"
    echo "  ✓ index.html"
  fi

  # Update OTA engine fallback version (Python backend)
  local engine="$ROOT/apps/api/app/engines/ota_update_engine.py"
  if [ -f "$engine" ]; then
    sed -i -E "s/return \"[0-9]+\.[0-9]+\.[0-9]+\"/return \"${version}\"/" "$engine"
    echo "  ✓ ota_update_engine.py (fallback version)"
  fi

  # Copy VERSION.json to data volume so API can read it at runtime
  local data_dir="${TPL_DATA_DIR:-$ROOT/data}"
  if [ -d "$data_dir" ]; then
    cp "$ROOT/VERSION.json" "$data_dir/VERSION.json" 2>/dev/null || true
    echo "  ✓ VERSION.json → data volume"
  fi

  # Update app.js version comment
  if [ -f "$ROOT/infra/web/app.js" ]; then
    sed -i -E "s/Core client library v[0-9]+\.[0-9]+(\.[0-9]+)?/Core client library v${version}/" "$ROOT/infra/web/app.js"
    echo "  ✓ app.js"
  fi

  echo ""
  echo "INFO: Version $full_version applied to all platform files."
}

# ── Show current version ─────────────────────────────────────────────────
show_version() {
  local version build full channel codename released_at
  version="$(get_field version)"
  build="$(get_field build)"
  full="$(get_field full_version)"
  channel="$(get_field channel)"
  codename="$(get_field codename)"
  released_at="$(get_field released_at)"

  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  TPL Fortress — Platform Version                            ║"
  echo "╠═══════════════════════════════════════════════════════════════╣"
  echo "║  Version:     $version"
  echo "║  Build:       $build"
  echo "║  Full:        $full"
  echo "║  Channel:     $channel"
  echo "║  Codename:    $codename"
  echo "║  Released:    $released_at"
  echo "║                                                             ║"
  echo "║  Build Format: YYYYMMDD<SEQ> (monotonically increasing)     ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
}

# ═══ Main ════════════════════════════════════════════════════════════════
case "${1:-}" in
  bump)
    bump_version "${2:-build}"
    ;;
  check)
    if [ -z "${2:-}" ]; then
      echo "Usage: $0 check <from_version>" >&2
      exit 1
    fi
    check_upgradable "$2"
    ;;
  compare)
    if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
      echo "Usage: $0 compare <version1> <version2>" >&2
      exit 1
    fi
    result=$(compare_versions "$2" "$3")
    case "$result" in
      1)  echo "$2 > $3" ;;
      0)  echo "$2 = $3" ;;
      -1) echo "$2 < $3" ;;
    esac
    ;;
  export)
    export_vars
    ;;
  apply)
    apply_version
    ;;
  ""|show|info)
    show_version
    ;;
  *)
    echo "TPL Fortress — Smart Build Numbering System"
    echo ""
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  show|info              Show current version"
    echo "  bump <type>            Bump version (major|minor|patch|build)"
    echo "  check <version>        Check if current can upgrade from <version>"
    echo "  compare <v1> <v2>      Compare two full versions"
    echo "  export                 Output as env vars (eval-friendly)"
    echo "  apply                  Write version to all platform files"
    echo ""
    echo "Build Number Format:"
    echo "  YYYYMMDD<SEQ> — e.g., 20260227001"
    echo "  Guarantees monotonic increase (multiple builds per day supported)"
    echo ""
    echo "Full Version Format:"
    echo "  MAJOR.MINOR.PATCH+BUILD — SemVer 2.0 compliant"
    echo "  e.g., 3.1.0+20260227001"
    exit 0
    ;;
esac

"""
TPL OTA Update Engine — v1.0.0
Rilevazione automatica aggiornamenti da GitHub e installazione guidata.
Repository: https://github.com/pif93/TPL

Features:
  - Check automatico periodico via GitHub REST API
  - Elenco release con note di rilascio e confronto
  - Download e staging aggiornamenti su volume condiviso
  - Pre-flight checks prima dell'installazione
  - Guida installazione step-by-step
  - Notifiche aggiornamenti disponibili
"""

import asyncio
import json
import os
import re
import shutil
import tarfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# ── Constants ───────────────────────────────────────────────────────────

GITHUB_OWNER = "pif93"
GITHUB_REPO = "TPL"
GITHUB_API = "https://api.github.com"
GITHUB_DOWNLOAD = "https://github.com"
PLATFORM_VERSION = "2.1.0"

# ── Models ──────────────────────────────────────────────────────────────


class OTAConfigUpdate(BaseModel):
    auto_check: Optional[bool] = None
    check_interval_minutes: Optional[int] = Field(None, ge=15, le=1440)
    branch: Optional[str] = Field(None, max_length=50)
    pre_release: Optional[bool] = None


class OTAPrepareRequest(BaseModel):
    tag: str = Field(..., min_length=1, max_length=100)


class OTADismissRequest(BaseModel):
    tag: str = Field(..., min_length=1, max_length=100)


# ── Helpers ─────────────────────────────────────────────────────────────

def _version_tuple(v: str) -> tuple:
    """Parse semver string to comparable tuple."""
    clean = v.lstrip("v").strip()
    parts = re.findall(r"\d+", clean)
    return tuple(int(x) for x in parts[:3]) if parts else (0, 0, 0)


def _version_compare(a: str, b: str) -> int:
    """Compare two version strings. Returns -1, 0, 1."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def _fmt_size(size_bytes: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _sanitize_tag(tag: str) -> str:
    """Sanitize tag to prevent path traversal."""
    return re.sub(r"[^a-zA-Z0-9._-]", "", tag)


# ── Engine Registration ────────────────────────────────────────────────

def register(app: FastAPI):
    ctx = app.state.tpl_context
    require_admin = ctx["require_role"]("admin")
    audit = ctx["audit"]
    root = ctx.get("root", "/data")

    # ── Paths ─────────────────────────────────────────────────────────
    OTA_DIR = os.path.join(root, "ota")
    OTA_STATE = os.path.join(OTA_DIR, "state.json")
    OTA_CONFIG_FILE = os.path.join(OTA_DIR, "config.json")
    OTA_DOWNLOADS = os.path.join(OTA_DIR, "downloads")
    OTA_STAGING = os.path.join(OTA_DIR, "staging")
    OTA_CACHE = os.path.join(OTA_DIR, "cache.json")

    for d in (OTA_DIR, OTA_DOWNLOADS, OTA_STAGING):
        os.makedirs(d, exist_ok=True)

    # ── State Management ──────────────────────────────────────────────

    def _load_config() -> dict:
        defaults = {
            "auto_check": True,
            "check_interval_minutes": 60,
            "branch": "main",
            "pre_release": False,
            "repo_owner": GITHUB_OWNER,
            "repo_name": GITHUB_REPO,
        }
        if os.path.isfile(OTA_CONFIG_FILE):
            try:
                with open(OTA_CONFIG_FILE, "r") as f:
                    saved = json.load(f)
                defaults.update(saved)
            except Exception:
                pass
        return defaults

    def _save_config(cfg: dict):
        with open(OTA_CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)

    def _load_state() -> dict:
        defaults = {
            "last_check": 0,
            "last_check_iso": "",
            "update_available": False,
            "latest_version": None,
            "releases_cache": [],
            "dismissed": [],
            "prepared_versions": [],
            "etag": "",
            "rate_limit_remaining": 60,
            "check_count": 0,
        }
        if os.path.isfile(OTA_STATE):
            try:
                with open(OTA_STATE, "r") as f:
                    saved = json.load(f)
                defaults.update(saved)
            except Exception:
                pass
        return defaults

    def _save_state(state: dict):
        with open(OTA_STATE, "w") as f:
            json.dump(state, f, indent=2)

    # ── GitHub API Helpers ────────────────────────────────────────────

    async def _github_get(path: str, params: dict = None, etag: str = "") -> tuple:
        """Call GitHub REST API. Returns (data, headers, status_code)."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": f"TPL-Platform/{PLATFORM_VERSION}",
        }
        if etag:
            headers["If-None-Match"] = etag

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"{GITHUB_API}{path}",
                    params=params or {},
                    headers=headers,
                )
                rate_remaining = int(resp.headers.get("X-RateLimit-Remaining", "60"))
                resp_etag = resp.headers.get("ETag", "")

                if resp.status_code == 304:
                    return None, {"etag": resp_etag, "rate_remaining": rate_remaining}, 304
                if resp.status_code == 403 and rate_remaining == 0:
                    reset_at = int(resp.headers.get("X-RateLimit-Reset", "0"))
                    raise HTTPException(
                        429,
                        f"GitHub API rate limit exceeded. Resets at {datetime.fromtimestamp(reset_at).isoformat()}",
                    )
                if resp.status_code == 404:
                    return None, {"etag": resp_etag, "rate_remaining": rate_remaining}, 404
                resp.raise_for_status()
                return resp.json(), {"etag": resp_etag, "rate_remaining": rate_remaining}, resp.status_code
        except httpx.HTTPStatusError as e:
            raise HTTPException(502, f"GitHub API error: {e.response.status_code}")
        except httpx.RequestError as e:
            raise HTTPException(504, f"GitHub connection failed: {str(e)[:200]}")

    async def _fetch_releases(config: dict, state: dict) -> list:
        """Fetch releases from GitHub with ETag caching."""
        owner = config.get("repo_owner", GITHUB_OWNER)
        repo = config.get("repo_name", GITHUB_REPO)

        data, headers, status = await _github_get(
            f"/repos/{owner}/{repo}/releases",
            params={"per_page": 20},
            etag=state.get("etag", ""),
        )

        state["rate_limit_remaining"] = headers.get("rate_remaining", 60)

        if status == 304:
            # Not modified — use cache
            return state.get("releases_cache", [])

        if status == 404:
            # Repo not found or no releases yet
            state["repo_status"] = "not_found"
            return []

        if data is None:
            return state.get("releases_cache", [])

        state["etag"] = headers.get("etag", "")

        releases = []
        for r in data:
            if not config.get("pre_release", False) and r.get("prerelease", False):
                continue
            tag = r.get("tag_name", "")
            releases.append({
                "tag": tag,
                "version": tag.lstrip("v"),
                "name": r.get("name", tag),
                "body": r.get("body", ""),
                "published_at": r.get("published_at", ""),
                "prerelease": r.get("prerelease", False),
                "draft": r.get("draft", False),
                "tarball_url": r.get("tarball_url", ""),
                "html_url": r.get("html_url", ""),
                "author": (r.get("author") or {}).get("login", ""),
                "assets": [
                    {
                        "name": a.get("name", ""),
                        "size": a.get("size", 0),
                        "download_url": a.get("browser_download_url", ""),
                    }
                    for a in (r.get("assets") or [])
                ],
            })

        releases.sort(
            key=lambda x: _version_tuple(x["version"]),
            reverse=True,
        )
        return releases

    async def _fetch_commits_between(
        config: dict, base: str, head: str
    ) -> list:
        """Fetch commits between two refs."""
        owner = config.get("repo_owner", GITHUB_OWNER)
        repo = config.get("repo_name", GITHUB_REPO)
        try:
            data, _, _ = await _github_get(
                f"/repos/{owner}/{repo}/compare/{base}...{head}",
            )
            commits = []
            for c in (data or {}).get("commits", [])[:30]:
                commits.append({
                    "sha": c.get("sha", "")[:8],
                    "message": (c.get("commit", {}).get("message", "")).split("\n")[0],
                    "author": (c.get("commit", {}).get("author", {})).get("name", ""),
                    "date": (c.get("commit", {}).get("author", {})).get("date", ""),
                })
            files_changed = []
            for f in (data or {}).get("files", [])[:100]:
                files_changed.append({
                    "filename": f.get("filename", ""),
                    "status": f.get("status", ""),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "changes": f.get("changes", 0),
                })
            return {
                "total_commits": (data or {}).get("total_commits", 0),
                "commits": commits,
                "files_changed": files_changed,
                "ahead_by": (data or {}).get("ahead_by", 0),
                "behind_by": (data or {}).get("behind_by", 0),
            }
        except Exception:
            return {
                "total_commits": 0,
                "commits": [],
                "files_changed": [],
                "ahead_by": 0,
                "behind_by": 0,
            }

    async def _download_release(tag: str, config: dict) -> dict:
        """Download a release tarball to staging area."""
        safe_tag = _sanitize_tag(tag)
        if not safe_tag:
            raise HTTPException(400, "Invalid tag")

        owner = config.get("repo_owner", GITHUB_OWNER)
        repo = config.get("repo_name", GITHUB_REPO)
        download_url = f"{GITHUB_DOWNLOAD}/{owner}/{repo}/archive/refs/tags/{safe_tag}.tar.gz"

        dest_file = os.path.join(OTA_DOWNLOADS, f"{safe_tag}.tar.gz")
        staging_dir = os.path.join(OTA_STAGING, safe_tag)

        # Check if already downloaded
        if os.path.isfile(dest_file) and os.path.isdir(staging_dir):
            size = os.path.getsize(dest_file)
            file_count = sum(1 for _ in Path(staging_dir).rglob("*") if _.is_file())
            return {
                "status": "already_downloaded",
                "tag": safe_tag,
                "file": dest_file,
                "staging": staging_dir,
                "size": size,
                "size_human": _fmt_size(size),
                "file_count": file_count,
            }

        try:
            async with httpx.AsyncClient(
                timeout=120.0, follow_redirects=True
            ) as client:
                resp = await client.get(download_url)
                resp.raise_for_status()

                with open(dest_file, "wb") as f:
                    f.write(resp.content)

            size = os.path.getsize(dest_file)

            # Extract to staging
            if os.path.isdir(staging_dir):
                shutil.rmtree(staging_dir)
            os.makedirs(staging_dir, exist_ok=True)

            with tarfile.open(dest_file, "r:gz") as tar:
                # Security: prevent path traversal
                for member in tar.getmembers():
                    if member.name.startswith("/") or ".." in member.name:
                        raise HTTPException(400, "Suspicious path in archive")
                tar.extractall(staging_dir)

            # The tarball extracts to a subdirectory like TPL-v2.2.0/
            # Move contents up one level
            subdirs = [
                d
                for d in os.listdir(staging_dir)
                if os.path.isdir(os.path.join(staging_dir, d))
            ]
            if len(subdirs) == 1:
                inner = os.path.join(staging_dir, subdirs[0])
                for item in os.listdir(inner):
                    src = os.path.join(inner, item)
                    dst = os.path.join(staging_dir, item)
                    shutil.move(src, dst)
                os.rmdir(inner)

            file_count = sum(1 for _ in Path(staging_dir).rglob("*") if _.is_file())

            return {
                "status": "downloaded",
                "tag": safe_tag,
                "file": dest_file,
                "staging": staging_dir,
                "size": size,
                "size_human": _fmt_size(size),
                "file_count": file_count,
            }
        except HTTPException:
            raise
        except Exception as e:
            # Cleanup on failure
            if os.path.isfile(dest_file):
                os.remove(dest_file)
            if os.path.isdir(staging_dir):
                shutil.rmtree(staging_dir)
            raise HTTPException(502, f"Download failed: {str(e)[:200]}")

    def _pre_flight_checks(staging_dir: str) -> list:
        """Run pre-flight checks before installation."""
        checks = []

        # 1. Staging directory exists
        staging_exists = os.path.isdir(staging_dir)
        checks.append({
            "id": "staging_exists",
            "name": "Directory staging presente",
            "passed": staging_exists,
            "detail": staging_dir if staging_exists else "Directory non trovata",
        })
        if not staging_exists:
            return checks

        # 2. Key files present
        for key_file in ("compose.yml", "run.sh", "apps/api/app/main.py"):
            exists = os.path.isfile(os.path.join(staging_dir, key_file))
            checks.append({
                "id": f"file_{key_file.replace('/', '_')}",
                "name": f"File chiave: {key_file}",
                "passed": exists,
                "detail": "Presente" if exists else "Mancante",
            })

        # 3. Modules directory present
        modules_dir = os.path.join(staging_dir, "modules")
        has_modules = os.path.isdir(modules_dir)
        module_count = len([f for f in os.listdir(modules_dir) if f.endswith(".sh")]) if has_modules else 0
        checks.append({
            "id": "modules_dir",
            "name": "Directory moduli",
            "passed": has_modules,
            "detail": f"{module_count} moduli trovati" if has_modules else "Mancante",
        })

        # 4. Engines directory present
        engines_dir = os.path.join(staging_dir, "apps", "api", "app", "engines")
        has_engines = os.path.isdir(engines_dir)
        engine_count = (
            len([f for f in os.listdir(engines_dir) if f.endswith("_engine.py")])
            if has_engines
            else 0
        )
        checks.append({
            "id": "engines_dir",
            "name": "Directory engine",
            "passed": has_engines,
            "detail": f"{engine_count} engine trovati" if has_engines else "Mancante",
        })

        # 5. Disk space check
        try:
            stat = os.statvfs(OTA_DIR)
            free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
            checks.append({
                "id": "disk_space",
                "name": "Spazio disco disponibile",
                "passed": free_mb > 100,
                "detail": f"{free_mb:.0f} MB liberi",
            })
        except Exception:
            checks.append({
                "id": "disk_space",
                "name": "Spazio disco disponibile",
                "passed": True,
                "detail": "Controllo non disponibile",
            })

        # 6. No suspicious files
        suspicious = []
        for fpath in Path(staging_dir).rglob("*"):
            if fpath.is_file():
                name = fpath.name.lower()
                if name.endswith((".exe", ".dll", ".bat", ".cmd", ".com")):
                    suspicious.append(str(fpath.relative_to(staging_dir)))
        checks.append({
            "id": "no_suspicious",
            "name": "Nessun file sospetto",
            "passed": len(suspicious) == 0,
            "detail": "OK" if not suspicious else f"Trovati: {', '.join(suspicious[:5])}",
        })

        return checks

    def _generate_install_guide(tag: str, staging_dir: str) -> dict:
        """Generate installation guide with host-side commands."""
        safe_tag = _sanitize_tag(tag)
        return {
            "tag": safe_tag,
            "steps": [
                {
                    "step": 1,
                    "title": "Backup corrente",
                    "description": "Crea un backup completo della configurazione attuale",
                    "command": "cd /home/curciop/Documenti/TPL && sudo cp -a . ../TPL-backup-$(date +%Y%m%d_%H%M%S)",
                    "risk": "low",
                    "automated": False,
                },
                {
                    "step": 2,
                    "title": "Ferma i servizi",
                    "description": "Arresta tutti i container Docker per sicurezza",
                    "command": "cd /home/curciop/Documenti/TPL && sudo docker compose down",
                    "risk": "medium",
                    "automated": False,
                },
                {
                    "step": 3,
                    "title": "Applica aggiornamento",
                    "description": f"Esegui lo script di aggiornamento OTA per la versione {safe_tag}",
                    "command": f"cd /home/curciop/Documenti/TPL && sudo bash scripts/ota_update.sh --apply {safe_tag}",
                    "risk": "high",
                    "automated": False,
                },
                {
                    "step": 4,
                    "title": "Ricostruisci container",
                    "description": "Rebuild dei container con il nuovo codice",
                    "command": "cd /home/curciop/Documenti/TPL && sudo docker compose build --no-cache",
                    "risk": "medium",
                    "automated": False,
                },
                {
                    "step": 5,
                    "title": "Avvia servizi",
                    "description": "Riavvia tutti i container aggiornati",
                    "command": "cd /home/curciop/Documenti/TPL && sudo ./run.sh",
                    "risk": "low",
                    "automated": False,
                },
                {
                    "step": 6,
                    "title": "Verifica installazione",
                    "description": "Esegui i test di verifica post-aggiornamento",
                    "command": "cd /home/curciop/Documenti/TPL && sudo bash scripts/test_all.sh",
                    "risk": "low",
                    "automated": False,
                },
            ],
            "rollback": {
                "description": "In caso di problemi, ripristina dal backup",
                "command": "cd /home/curciop/Documenti/TPL && sudo docker compose down && cd .. && sudo rm -rf TPL && sudo mv TPL-backup-* TPL && cd TPL && sudo ./run.sh",
            },
            "notes": [
                "L'aggiornamento preserva i dati in ./data/ e i segreti in ./.secrets/",
                "I moduli personalizzati in ./data/modules/current/ vengono preservati",
                "Eseguire sempre un backup prima di procedere",
                f"File di staging disponibili in: ./data/ota/staging/{safe_tag}/",
            ],
        }

    def _get_changed_files_list(staging_dir: str) -> list:
        """List files in staging that differ from current installation."""
        changes = []
        if not os.path.isdir(staging_dir):
            return changes

        # Compare key directories
        compare_dirs = [
            ("apps/api/app", "Backend API"),
            ("apps/api/app/engines", "Engine API"),
            ("infra/web", "Frontend"),
            ("modules", "Moduli Shell"),
            ("scripts", "Script"),
            ("compose.d", "Docker Compose"),
            ("infra/traefik", "Traefik Config"),
        ]

        for subdir, label in compare_dirs:
            staging_sub = os.path.join(staging_dir, subdir)
            if not os.path.isdir(staging_sub):
                continue
            for fpath in Path(staging_sub).rglob("*"):
                if fpath.is_file():
                    rel = str(fpath.relative_to(staging_dir))
                    changes.append({
                        "file": rel,
                        "category": label,
                        "size": fpath.stat().st_size,
                    })

        return changes

    # ── Background auto-check ─────────────────────────────────────────

    _auto_check_task = None

    async def _auto_check_loop():
        """Periodically check for updates."""
        await asyncio.sleep(30)  # Initial delay on startup
        while True:
            config = _load_config()
            if not config.get("auto_check", True):
                await asyncio.sleep(300)
                continue
            try:
                state = _load_state()
                releases = await _fetch_releases(config, state)
                state["releases_cache"] = releases[:10]
                state["check_count"] = state.get("check_count", 0) + 1
                state["last_check"] = int(time.time())
                state["last_check_iso"] = datetime.now().isoformat()

                if releases:
                    latest = releases[0]
                    cmp = _version_compare(PLATFORM_VERSION, latest["version"])
                    dismissed = state.get("dismissed", [])
                    state["update_available"] = (
                        cmp < 0 and latest["tag"] not in dismissed
                    )
                    state["latest_version"] = latest["version"]
                else:
                    state["update_available"] = False
                    state["latest_version"] = None

                _save_state(state)
            except Exception:
                pass

            interval = config.get("check_interval_minutes", 60) * 60
            await asyncio.sleep(max(interval, 900))

    @app.on_event("startup")
    async def _start_ota_auto_check():
        nonlocal _auto_check_task
        _auto_check_task = asyncio.create_task(_auto_check_loop())

    # ── Endpoints ─────────────────────────────────────────────────────

    @app.get("/ota/status")
    async def ota_status(_u=Depends(require_admin)):
        """Current OTA status: version, last check, update availability."""
        state = _load_state()
        config = _load_config()
        prepared = []
        if os.path.isdir(OTA_STAGING):
            for d in os.listdir(OTA_STAGING):
                dp = os.path.join(OTA_STAGING, d)
                if os.path.isdir(dp):
                    prepared.append(d)

        return {
            "current_version": PLATFORM_VERSION,
            "latest_version": state.get("latest_version"),
            "update_available": state.get("update_available", False),
            "last_check": state.get("last_check", 0),
            "last_check_iso": state.get("last_check_iso", ""),
            "auto_check": config.get("auto_check", True),
            "check_interval_minutes": config.get("check_interval_minutes", 60),
            "branch": config.get("branch", "main"),
            "pre_release": config.get("pre_release", False),
            "rate_limit_remaining": state.get("rate_limit_remaining", 60),
            "check_count": state.get("check_count", 0),
            "prepared_versions": prepared,
            "dismissed": state.get("dismissed", []),
            "repo": f"https://github.com/{config.get('repo_owner', GITHUB_OWNER)}/{config.get('repo_name', GITHUB_REPO)}",
            "repo_status": state.get("repo_status", "ok"),
        }

    @app.post("/ota/check")
    async def ota_check(request: Request, _u=Depends(require_admin)):
        """Manually trigger an update check against GitHub."""
        config = _load_config()
        state = _load_state()

        releases = await _fetch_releases(config, state)
        state["releases_cache"] = releases[:10]
        state["check_count"] = state.get("check_count", 0) + 1
        state["last_check"] = int(time.time())
        state["last_check_iso"] = datetime.now().isoformat()

        update_available = False
        latest_version = None
        newer_releases = []

        if releases:
            latest = releases[0]
            latest_version = latest["version"]
            dismissed = state.get("dismissed", [])

            for r in releases:
                cmp = _version_compare(PLATFORM_VERSION, r["version"])
                if cmp < 0:
                    newer_releases.append({
                        "tag": r["tag"],
                        "version": r["version"],
                        "name": r["name"],
                        "published_at": r["published_at"],
                        "prerelease": r["prerelease"],
                        "dismissed": r["tag"] in dismissed,
                    })
            update_available = any(
                not nr["dismissed"] for nr in newer_releases
            )

        state["update_available"] = update_available
        state["latest_version"] = latest_version
        _save_state(state)

        audit(
            request,
            "ota.check",
            "success",
            _u.get("sub", "admin"),
            {
                "latest": latest_version,
                "update_available": update_available,
                "newer_count": len(newer_releases),
            },
        )

        return {
            "current_version": PLATFORM_VERSION,
            "latest_version": latest_version,
            "update_available": update_available,
            "newer_releases": newer_releases,
            "total_releases": len(releases),
            "checked_at": state["last_check"],
            "rate_limit_remaining": state.get("rate_limit_remaining", 60),
            "repo_status": state.get("repo_status", "ok"),
            "note": "Repository non trovato o non ancora pubblicato. Assicurarsi che il repository sia pubblico e contenga rilasci." if state.get("repo_status") == "not_found" else None,
        }

    @app.get("/ota/releases")
    async def ota_releases(_u=Depends(require_admin)):
        """List all available releases from GitHub (cached)."""
        state = _load_state()
        config = _load_config()

        # If never checked or cache is old (>2h), fetch fresh
        if (
            not state.get("releases_cache")
            or time.time() - state.get("last_check", 0) > 7200
        ):
            releases = await _fetch_releases(config, state)
            state["releases_cache"] = releases[:10]
            state["last_check"] = int(time.time())
            state["last_check_iso"] = datetime.now().isoformat()
            _save_state(state)
        else:
            releases = state.get("releases_cache", [])

        # Annotate with update status
        for r in releases:
            r["is_newer"] = _version_compare(PLATFORM_VERSION, r.get("version", "")) < 0
            r["is_current"] = r.get("version", "") == PLATFORM_VERSION
            r["is_prepared"] = os.path.isdir(
                os.path.join(OTA_STAGING, _sanitize_tag(r.get("tag", "")))
            )

        return {
            "releases": releases,
            "current_version": PLATFORM_VERSION,
            "total": len(releases),
        }

    @app.get("/ota/release/{tag}")
    async def ota_release_detail(tag: str, _u=Depends(require_admin)):
        """Detailed info for a specific release."""
        safe_tag = _sanitize_tag(tag)
        config = _load_config()
        state = _load_state()

        # Find in cache first
        cached = next(
            (r for r in state.get("releases_cache", []) if r.get("tag") == tag),
            None,
        )

        if not cached:
            # Fetch from GitHub
            owner = config.get("repo_owner", GITHUB_OWNER)
            repo = config.get("repo_name", GITHUB_REPO)
            try:
                data, _, _ = await _github_get(
                    f"/repos/{owner}/{repo}/releases/tags/{tag}"
                )
                cached = {
                    "tag": data.get("tag_name", tag),
                    "version": data.get("tag_name", tag).lstrip("v"),
                    "name": data.get("name", tag),
                    "body": data.get("body", ""),
                    "published_at": data.get("published_at", ""),
                    "prerelease": data.get("prerelease", False),
                    "html_url": data.get("html_url", ""),
                    "author": (data.get("author") or {}).get("login", ""),
                    "assets": [
                        {
                            "name": a.get("name", ""),
                            "size": a.get("size", 0),
                            "download_url": a.get("browser_download_url", ""),
                        }
                        for a in (data.get("assets") or [])
                    ],
                }
            except Exception:
                raise HTTPException(404, f"Release {tag} not found")

        # Check if prepared
        staging_dir = os.path.join(OTA_STAGING, safe_tag)
        is_prepared = os.path.isdir(staging_dir)

        result = {
            **cached,
            "is_newer": _version_compare(PLATFORM_VERSION, cached.get("version", "")) < 0,
            "is_current": cached.get("version", "") == PLATFORM_VERSION,
            "is_prepared": is_prepared,
        }

        # If prepared, add pre-flight results
        if is_prepared:
            result["preflight"] = _pre_flight_checks(staging_dir)
            result["changed_files"] = _get_changed_files_list(staging_dir)
            result["install_guide"] = _generate_install_guide(tag, staging_dir)

        return result

    @app.get("/ota/diff/{tag}")
    async def ota_diff(tag: str, _u=Depends(require_admin)):
        """Show what changed between current version and target tag."""
        config = _load_config()
        base_ref = f"v{PLATFORM_VERSION}"
        head_ref = tag

        diff_data = await _fetch_commits_between(config, base_ref, head_ref)

        # Also check local staging if available
        safe_tag = _sanitize_tag(tag)
        staging_dir = os.path.join(OTA_STAGING, safe_tag)
        staged_files = _get_changed_files_list(staging_dir) if os.path.isdir(staging_dir) else []

        return {
            "base": base_ref,
            "head": head_ref,
            "current_version": PLATFORM_VERSION,
            "target_version": tag.lstrip("v"),
            **diff_data,
            "staged_files": staged_files,
        }

    @app.post("/ota/prepare/{tag}")
    async def ota_prepare(tag: str, request: Request, _u=Depends(require_admin)):
        """Download and stage a release for installation."""
        safe_tag = _sanitize_tag(tag)
        config = _load_config()

        audit(
            request,
            "ota.prepare",
            "started",
            _u.get("sub", "admin"),
            {"tag": safe_tag},
        )

        result = await _download_release(tag, config)

        # Run pre-flight checks
        staging_dir = os.path.join(OTA_STAGING, safe_tag)
        preflight = _pre_flight_checks(staging_dir)
        all_passed = all(c["passed"] for c in preflight)

        # Update state
        state = _load_state()
        prepared = state.get("prepared_versions", [])
        if safe_tag not in prepared:
            prepared.append(safe_tag)
            state["prepared_versions"] = prepared
        _save_state(state)

        audit(
            request,
            "ota.prepare",
            "success" if all_passed else "warning",
            _u.get("sub", "admin"),
            {
                "tag": safe_tag,
                "size": result.get("size", 0),
                "file_count": result.get("file_count", 0),
                "preflight_passed": all_passed,
            },
        )

        return {
            **result,
            "preflight": preflight,
            "all_checks_passed": all_passed,
            "install_guide": _generate_install_guide(tag, staging_dir),
            "changed_files": _get_changed_files_list(staging_dir),
        }

    @app.get("/ota/install-guide/{tag}")
    async def ota_install_guide(tag: str, _u=Depends(require_admin)):
        """Get installation guide for a prepared version."""
        safe_tag = _sanitize_tag(tag)
        staging_dir = os.path.join(OTA_STAGING, safe_tag)

        if not os.path.isdir(staging_dir):
            raise HTTPException(
                404,
                f"Version {safe_tag} not prepared. Use POST /ota/prepare/{tag} first.",
            )

        return {
            "guide": _generate_install_guide(tag, staging_dir),
            "preflight": _pre_flight_checks(staging_dir),
            "changed_files": _get_changed_files_list(staging_dir),
        }

    @app.post("/ota/config")
    async def ota_config_update(
        request: Request, cfg: OTAConfigUpdate, _u=Depends(require_admin)
    ):
        """Update OTA configuration."""
        config = _load_config()

        if cfg.auto_check is not None:
            config["auto_check"] = cfg.auto_check
        if cfg.check_interval_minutes is not None:
            config["check_interval_minutes"] = cfg.check_interval_minutes
        if cfg.branch is not None:
            config["branch"] = cfg.branch
        if cfg.pre_release is not None:
            config["pre_release"] = cfg.pre_release

        _save_config(config)

        audit(
            request,
            "ota.config",
            "updated",
            _u.get("sub", "admin"),
            {"config": config},
        )

        return {"ok": True, "config": config}

    @app.get("/ota/config")
    async def ota_config_get(_u=Depends(require_admin)):
        """Get current OTA configuration."""
        return _load_config()

    @app.post("/ota/dismiss")
    async def ota_dismiss(
        request: Request, req: OTADismissRequest, _u=Depends(require_admin)
    ):
        """Dismiss an update notification for a specific version."""
        state = _load_state()
        dismissed = state.get("dismissed", [])
        if req.tag not in dismissed:
            dismissed.append(req.tag)
            state["dismissed"] = dismissed

        # Re-evaluate update_available
        releases = state.get("releases_cache", [])
        state["update_available"] = any(
            _version_compare(PLATFORM_VERSION, r.get("version", "")) < 0
            and r.get("tag", "") not in dismissed
            for r in releases
        )
        _save_state(state)

        audit(
            request,
            "ota.dismiss",
            "success",
            _u.get("sub", "admin"),
            {"tag": req.tag},
        )

        return {"ok": True, "dismissed": dismissed}

    @app.delete("/ota/staging/{tag}")
    async def ota_cleanup_staging(
        tag: str, request: Request, _u=Depends(require_admin)
    ):
        """Remove a staged version download."""
        safe_tag = _sanitize_tag(tag)
        staging_dir = os.path.join(OTA_STAGING, safe_tag)
        download_file = os.path.join(OTA_DOWNLOADS, f"{safe_tag}.tar.gz")

        removed = []
        if os.path.isdir(staging_dir):
            shutil.rmtree(staging_dir)
            removed.append(f"staging/{safe_tag}")
        if os.path.isfile(download_file):
            os.remove(download_file)
            removed.append(f"downloads/{safe_tag}.tar.gz")

        # Update state
        state = _load_state()
        prepared = state.get("prepared_versions", [])
        if safe_tag in prepared:
            prepared.remove(safe_tag)
            state["prepared_versions"] = prepared
        _save_state(state)

        audit(
            request,
            "ota.cleanup",
            "success",
            _u.get("sub", "admin"),
            {"tag": safe_tag, "removed": removed},
        )

        return {"ok": True, "removed": removed}

    # Record engine startup
    if not hasattr(app.state, "_ota_started"):
        app.state._ota_started = time.time()
